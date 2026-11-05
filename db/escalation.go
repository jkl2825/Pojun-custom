package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// 意图阶梯的存储层原语（2026-11-05）。
//
// 背景：任务 333 一晚跑 10 小时，71 个 finding，但没有任何机制回答「这条意图
// 已经跑了多久、还有没有产出」。sapper-v2 的做法是给每条工作单元一个时间阶梯：
// 无产出 15 分钟→纠偏，45 分钟→停放（阈值由它那场比赛的均值推算，我们按
// 自己 4.2 分钟/意图的实测重新定为 15/45）。
//
// 这里只放最小原语：谁在跑、从什么时候开始跑、最后一次产出是什么时候。
// 判定逻辑在 server/escalation.go，保持 DB 层不含策略。

// IntentClock 是阶梯判定需要的最小视图。
type IntentClock struct {
	ID              int64
	FirstRunAt      time.Time
	EscalationLevel int
}

// RunningIntentsWithClock 列出本探索下所有 running 意图的阶梯时钟。
//
// 只返回 first_run_at 非空的：理论上一进入 running 就会落章（ClaimIntent），
// 空值说明是本次升级前就在跑的老意图——此时不参与判定，避免拿「null」算出
// 一个巨大的 elapsed 把它立刻停放。
func (s *ExplorationStore) RunningIntentsWithClock() ([]IntentClock, error) {
	rows, err := s.db.Query(`SELECT id, first_run_at, escalation_level
FROM exploration_nodes
WHERE exploration_id=$1 AND kind='intent' AND state='running' AND first_run_at IS NOT NULL
ORDER BY id`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IntentClock
	for rows.Next() {
		var c IntentClock
		if err := rows.Scan(&c.ID, &c.FirstRunAt, &c.EscalationLevel); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LastYieldAt 返回该意图最后一次「产出」的时刻（intent --yields--> fact/finding
// 里最新那条的 created_at）。没有产出时返回零值。
//
// 为什么用产出而不是活动：333 的日志里「连续 3 轮无写回（本轮写回 6 条）」
// 说明活动量（工具调用）与产出是两件事。一个在跑长脚本的 worker 活动很多、
// 产出为零；一个刚写完结论的 worker 活动为零、产出为正。判空转要看产出。
func (s *ExplorationStore) LastYieldAt(intentID int64) (time.Time, error) {
	var ts *time.Time
	err := s.db.QueryRow(`SELECT max(n.created_at)
FROM exploration_edges e
JOIN exploration_nodes n ON n.id=e.dst_id AND n.exploration_id=e.exploration_id
WHERE e.exploration_id=$1 AND e.src_id=$2 AND e.rel=$3`, s.expID, intentID, RelYields).Scan(&ts)
	if err != nil {
		return time.Time{}, err
	}
	if ts == nil {
		return time.Time{}, nil
	}
	return *ts, nil
}

// SetEscalationLevel 记录该意图已升到哪一档（幂等：只会往上写）。
func (s *ExplorationStore) SetEscalationLevel(id int64, level int) error {
	_, err := s.db.Exec(`UPDATE exploration_nodes SET escalation_level=GREATEST(escalation_level,$1), updated_at=now()
WHERE id=$2 AND exploration_id=$3 AND kind='intent'`, level, id, s.expID)
	return err
}

// ParkIntent 把意图停放到 blocked，并写明原因（缺什么、试过什么）。
// 用 blocked 而不是 stopped/exhausted：
//   - stopped 是「planner 主动叫停」，语义是方向错误；
//   - exhausted 是「预算耗尽被掐断」，语义是还没做完、值得接续；
//   - blocked 是「撞墙了」，planner 看到它会先看 blocked_reason 再决定重开或换向。
func (s *ExplorationStore) ParkIntent(id int64, reason string) (bool, error) {
	res, err := s.db.Exec(`UPDATE exploration_nodes
SET state='blocked', blocked_reason=$1, completed_at=now(), updated_at=now(), escalation_level=GREATEST(escalation_level,3)
WHERE id=$2 AND exploration_id=$3 AND kind='intent' AND state='running'`, reason, id, s.expID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// BlockedIntentCount 返回本探索下处于 blocked 的意图数。
//
// 用途：任务收尾时区分「目标真的都达成了」和「方向全被停放、没活可干」。
// 2026-11-05 发现：engine 的 goalless 分支在「无 open 目标 + 无 active 意图」时
// 直接落 done 并播报「目标已全部达成」——但 L4 阶梯会把 running 意图改成
// blocked，那时是「全部撞墙」而不是「全部达成」，播报是错的。
func (s *ExplorationStore) BlockedIntentCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM exploration_nodes
WHERE exploration_id=$1 AND kind='intent' AND state='blocked'`, s.expID).Scan(&n)
	return n, err
}

type intentAdmissionPayload struct {
	Summary              string          `json:"summary"`
	CollaboratesWith     json.RawMessage `json:"collaborates_with"`
	CollaborationAngle   string          `json:"collaboration_angle"`
	Hypothesis           string          `json:"hypothesis"`
	SuccessCriteria      string          `json:"success_criteria"`
	BriefingIDs          []int64         `json:"briefing_ids"`
	AssetIDs             []int64         `json:"asset_ids"`
	Targets              json.RawMessage `json:"targets"`
	Continues            []int64         `json:"continues"`
	CollaborationSpawned bool            `json:"collaboration_spawned"`
}

// 本谓词只认实际证据；finding 的 {by,poc} 对象不能靠非空 by 绕过。
const collaborationEvidenceSQL = `n.kind IN ('fact','finding') AND n.state='confirmed' AND (
 (jsonb_typeof(n.payload->'evidence')='string' AND BTRIM(n.payload->>'evidence', E' \t\r\n')<>'')
 OR (jsonb_typeof(n.payload->'evidence')='object'
     AND jsonb_typeof(n.payload->'evidence'->'poc')='string'
     AND BTRIM(n.payload->'evidence'->>'poc', E' \t\r\n')<>'')
 OR (n.kind='finding' AND EXISTS (
     SELECT 1 FROM findings f WHERE f.node_id=n.id AND BTRIM(f.evidence, E' \t\r\n')<>''))
)`

func (s *ExplorationStore) admitCollaborationTx(tx *sql.Tx, payload map[string]any, fields intentAdmissionPayload, anchors []int64, admission IntentAdmission) error {
	var declaredSource int64
	if len(fields.CollaboratesWith) == 0 || json.Unmarshal(fields.CollaboratesWith, &declaredSource) != nil || declaredSource != admission.CollaboratesWith {
		return fmt.Errorf("collaboration_rejected: payload.collaborates_with 必须与准入源意图一致")
	}
	if strings.TrimSpace(fields.CollaborationAngle) == "" || strings.TrimSpace(fields.Hypothesis) == "" || strings.TrimSpace(fields.SuccessCriteria) == "" {
		return fmt.Errorf("collaboration_rejected: 必须明确协作角度、假设和成功判据")
	}
	if len(anchors) == 0 {
		return fmt.Errorf("collaboration_rejected: 协作必须限定在源意图的非空资产锚点内")
	}
	targets := "null"
	if len(fields.Targets) > 0 {
		targets = string(fields.Targets)
	}
	var sourceJSON []byte
	var sourceState string
	var sourcePriority, sourceLevel int
	var sameTargets bool
	if err := tx.QueryRow(`SELECT payload, state, priority, escalation_level,
 COALESCE(payload->'targets','null'::jsonb)=$3::jsonb
FROM exploration_nodes WHERE exploration_id=$1 AND id=$2 AND kind='intent' FOR UPDATE`, s.expID, admission.CollaboratesWith, targets).
		Scan(&sourceJSON, &sourceState, &sourcePriority, &sourceLevel, &sameTargets); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("collaboration_rejected: 源意图必须存在于本探索")
		}
		return fmt.Errorf("collaboration_rejected: 读取源意图: %w", err)
	}
	var source intentAdmissionPayload
	if err := json.Unmarshal(sourceJSON, &source); err != nil {
		return fmt.Errorf("collaboration_rejected: 无法解析源意图: %w", err)
	}
	if sourceState != "running" || sourcePriority < 8 || sourceLevel < 2 || len(source.CollaboratesWith) > 0 || len(source.Continues) > 0 || source.CollaborationSpawned {
		return fmt.Errorf("collaboration_rejected: 只允许已进入L2评估的高价值运行中原始意图发起一次协作，不可递归或刷新历史配额")
	}
	if len(fields.Continues) > 0 {
		return fmt.Errorf("collaboration_rejected: 协作与接续不能混用")
	}
	if !sameTargets {
		return fmt.Errorf("collaboration_rejected: 协作 targets 必须与源意图一致")
	}
	sourceSummary := normalizeIntentText(source.Summary)
	if sourceSummary == "" {
		return fmt.Errorf("collaboration_rejected: 源意图缺少可比较的摘要")
	}
	for _, text := range []string{fields.Summary, fields.CollaborationAngle, fields.Hypothesis, fields.SuccessCriteria} {
		normalized := normalizeIntentText(text)
		if normalized == "" || strings.Contains(sourceSummary, normalized) || strings.Contains(normalized, sourceSummary) {
			return fmt.Errorf("collaboration_rejected: 协作方向、角度、假设和判据不能只是源摘要的重复或扩写")
		}
	}
	var active, historical int
	if err := tx.QueryRow(`SELECT
 COUNT(*) FILTER (WHERE state IN ('open','running','paused') AND payload ? 'collaborates_with'),
 COUNT(*) FILTER (WHERE payload->>'collaborates_with'=$2)
FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent'`, s.expID, fmt.Sprint(admission.CollaboratesWith)).Scan(&active, &historical); err != nil {
		return fmt.Errorf("collaboration_rejected: 读取协作配额: %w", err)
	}
	if historical > 0 {
		return fmt.Errorf("collaboration_rejected: 该源意图已有历史协作，不再重复派发")
	}
	if active > 0 {
		return fmt.Errorf("collaboration_rejected: 本探索已有待领或运行中的协作")
	}
	briefing := append([]int64(nil), admission.ParentIDs...)
	briefing = append(briefing, fields.BriefingIDs...)
	if len(briefing) == 0 {
		return fmt.Errorf("collaboration_rejected: 必须引用本图事实或发现作为交接材料")
	}
	args := []any{s.expID}
	marks := make([]string, 0, len(briefing))
	for _, id := range briefing {
		args = append(args, id)
		marks = append(marks, fmt.Sprintf("$%d", len(args)))
	}
	var hasBriefing bool
	if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM exploration_nodes n
WHERE n.exploration_id=$1 AND n.id IN (`+strings.Join(marks, ",")+`) AND `+collaborationEvidenceSQL+`)`, args...).Scan(&hasBriefing); err != nil {
		return fmt.Errorf("collaboration_rejected: 读取交接证据: %w", err)
	}
	if !hasBriefing {
		return fmt.Errorf("collaboration_rejected: 交接材料缺少有效本图事实或发现证据")
	}
	rows, err := tx.Query(`SELECT a.asset_id FROM exploration_anchors a
JOIN assets asset ON asset.id=a.asset_id
WHERE a.node_id=$1 FOR KEY SHARE OF a,asset`, admission.CollaboratesWith)
	if err != nil {
		return fmt.Errorf("collaboration_rejected: 读取源意图资产锚点: %w", err)
	}
	sourceAnchors := make(map[int64]bool)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		sourceAnchors[id] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(sourceAnchors) == 0 {
		return fmt.Errorf("collaboration_rejected: 源意图没有有效资产锚点，不能确定协作边界")
	}
	allowed := make(map[int64]bool, len(anchors))
	for _, id := range anchors {
		if !sourceAnchors[id] {
			return fmt.Errorf("collaboration_rejected: 资产锚点 #%d 扩大了源意图范围", id)
		}
		allowed[id] = true
	}
	for _, id := range fields.AssetIDs {
		if !allowed[id] {
			return fmt.Errorf("collaboration_rejected: payload.asset_ids 不能超出协作锚点")
		}
	}
	payload["collaborates_with"] = admission.CollaboratesWith
	payload["asset_ids"] = append([]int64(nil), anchors...)
	payload["run_budget_seconds"] = 600
	payload["collaboration_wall_ms"] = 0
	// Persist the one-shot allowance on the source as well as its child. Deleting
	// a child or reopening the source must not mint another collaboration.
	_, err = tx.Exec(`UPDATE exploration_nodes SET payload=payload || '{"collaboration_spawned":true}'::jsonb
	WHERE id=$1 AND exploration_id=$2`, admission.CollaboratesWith, s.expID)
	return err
}
