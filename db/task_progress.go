package db

import (
	"database/sql"
	"errors"
	"time"
)

// TaskProgress 是一个任务的自动收尾进度快照（v0.5.0）。每个常规规划轮由引擎
// 记录一次；idle_rounds 连续零增长达到阈值且 frontier 抽干时自动收尾。
type TaskProgress struct {
	TaskID       string    `json:"task_id"`
	RoundNo      int64     `json:"round_no"`
	IdleRounds   int       `json:"idle_rounds"`
	FactCount    int64     `json:"fact_count"`
	FindingCount int64     `json:"finding_count"`
	TestedCount  int64     `json:"tested_count"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RecordTaskProgress 记录一轮进度。round 必须单调递增：迟到的旧轮次（round <=
// 已记录值）直接返回当前 idle，不重复计数。计数任一增长 → idle 归零；否则 +1。
func (d *DB) RecordTaskProgress(taskID string, round, facts, findings, tested int64) (int, error) {
	var idle int
	err := d.QueryRow(`
INSERT INTO task_progress(task_id,round_no,idle_rounds,fact_count,finding_count,tested_count,updated_at)
VALUES($1,$2,0,$3,$4,$5,now())
ON CONFLICT (task_id) DO UPDATE SET
    idle_rounds = CASE
        WHEN EXCLUDED.round_no <= task_progress.round_no THEN task_progress.idle_rounds
        WHEN EXCLUDED.fact_count    > task_progress.fact_count
          OR EXCLUDED.finding_count > task_progress.finding_count
          OR EXCLUDED.tested_count  > task_progress.tested_count THEN 0
        ELSE task_progress.idle_rounds + 1
    END,
    fact_count = CASE
        WHEN EXCLUDED.round_no > task_progress.round_no
        THEN GREATEST(task_progress.fact_count, EXCLUDED.fact_count)
        ELSE task_progress.fact_count END,
    finding_count = CASE
        WHEN EXCLUDED.round_no > task_progress.round_no
        THEN GREATEST(task_progress.finding_count, EXCLUDED.finding_count)
        ELSE task_progress.finding_count END,
    tested_count = CASE
        WHEN EXCLUDED.round_no > task_progress.round_no
        THEN GREATEST(task_progress.tested_count, EXCLUDED.tested_count)
        ELSE task_progress.tested_count END,
    round_no = GREATEST(task_progress.round_no, EXCLUDED.round_no),
    updated_at = now()
RETURNING idle_rounds`, taskID, round, facts, findings, tested).Scan(&idle)
	return idle, err
}

// GetTaskProgress 读取进度快照（不存在返回 nil, nil）。
func (d *DB) GetTaskProgress(taskID string) (*TaskProgress, error) {
	var p TaskProgress
	err := d.QueryRow(`
SELECT task_id,round_no,idle_rounds,fact_count,finding_count,tested_count,updated_at
FROM task_progress WHERE task_id=$1`, taskID).
		Scan(&p.TaskID, &p.RoundNo, &p.IdleRounds, &p.FactCount, &p.FindingCount, &p.TestedCount, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &p, nil
}

// ResetTaskProgress 归零 idle（新增目标/提示、任务复活时调用）。保留计数基线，
// 下一轮即使无增长也只从 0 重新累计。
func (d *DB) ResetTaskProgress(taskID string) error {
	_, err := d.Exec(`UPDATE task_progress SET idle_rounds=0, updated_at=now() WHERE task_id=$1`, taskID)
	return err
}

// DeleteTaskProgress 任务删除时清理。
func (d *DB) DeleteTaskProgress(taskID string) error {
	_, err := d.Exec(`DELETE FROM task_progress WHERE task_id=$1`, taskID)
	return err
}

// CountExplorationProgress 精确统计某探索图的 fact/finding 数（不用列表上限）。
func (d *DB) CountExplorationProgress(expID int64) (facts, findings int64, err error) {
	err = d.QueryRow(`
SELECT COUNT(*) FILTER (WHERE kind='fact'), COUNT(*) FILTER (WHERE kind='finding')
FROM exploration_nodes WHERE exploration_id=$1`, expID).Scan(&facts, &findings)
	return
}

// CountOrdinaryOpenIntents uses the same ordinary-queue predicate as admission;
// a reserved collaboration slot must not masquerade as a full ordinary queue.
func (s *ExplorationStore) CountOrdinaryOpenIntents() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM exploration_nodes
	WHERE exploration_id=$1 AND kind='intent' AND state='open'
	AND NOT (payload ? 'collaborates_with')`, s.expID).Scan(&count)
	return count, err
}

// RecordCollaborationRuntime charges a bounded collaboration for every finished
// execution attempt, including paused/cancelled runs. It never resets the total
// and does not touch ordinary work. Malformed accounting fails closed at the cap.
func (s *ExplorationStore) RecordCollaborationRuntime(id, elapsedMS int64) error {
	if elapsedMS < 0 {
		elapsedMS = 600000
	}
	_, err := s.db.Exec(`UPDATE exploration_nodes SET payload=jsonb_set(payload, '{collaboration_wall_ms}',
	to_jsonb(LEAST(600000::numeric,
	CASE WHEN jsonb_typeof(payload->'collaboration_wall_ms')='number'
	THEN CASE WHEN (payload->>'collaboration_wall_ms')::numeric >= 0
	THEN (payload->>'collaboration_wall_ms')::numeric ELSE 600000::numeric END
	ELSE 600000::numeric END + $1::numeric)::bigint))
	WHERE id=$2 AND exploration_id=$3 AND kind='intent' AND payload ? 'collaborates_with'`, elapsedMS, id, s.expID)
	return err
}
