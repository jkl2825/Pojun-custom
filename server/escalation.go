package server

import (
	"fmt"
	"log"
	"time"

	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
)

// 意图阶梯（2026-11-05，借鉴 sapper-v2 的升级阶梯方法论）。
//
// sapper 的做法是把「卡住」从一个模糊状态拆成带时间阈值的四档，每档绑定一个
// 动作：纠偏 → 换角度 → 升档模型 → 停放。它的价值不在具体分钟数（那是按
// 「24 槽位小时 ÷ 63 题」拟合的），而在**把裁量变成规则**。
//
// 三段动作保留相同 worker 总数：
//
//	L1 15 分钟无产出 → 一次具体战术纠偏（steer_work）
//	L2 25 分钟仍无进展 → 通知 planner 比较价值并评估不同角度，不自动编造任务
//	L4 45 分钟无产出 → 停放（blocked + 原因），释放 worker
//
// 不同角度经 AddIntentAdmitted 的证据、资产子集与配额校验；全图最多一个协作
// 在途、每源最多一次、最多10分钟。普通队列背压与协作保留位分开，避免遗留积压
// 禁掉所有有价值的协作。不会自动选择或更换昂贵模型。
//
// 阈值依据：333 的 349 条意图平均执行 4.2 分钟。15 分钟 ≈ 3.5 倍均值，
// 45 分钟 ≈ 10 倍均值。低于这个量级的多半只是慢（远程利用脚本单次 timeout
// 就 260s），不该动它——这正是我们刚刚修过的 idle-stop 误杀。
const (
	escalationSteerAfter  = 15 * time.Minute
	escalationReviewAfter = 25 * time.Minute
	escalationParkAfter   = 45 * time.Minute
)

// escalationAction 是阶梯判定的输出。
type escalationAction int

const (
	escalationNone escalationAction = iota
	escalationSteer
	escalationReview
	escalationPark
)

// decideEscalation 是纯判定函数（便于单测，不碰 DB、不看时钟）。
//
//	elapsed    该意图从首次领取到现在的时长
//	lastYield  最后一次产出的时间；hasYield=false 表示从未产出
//	level      已经升到第几档
//
// 判据的核心是「无产出」而不是「无活动」：日志里「连续 3 轮无写回（本轮写回
// 6 条）」说明活动与产出是两件事。
func decideEscalation(elapsed, sinceYield time.Duration, hasYield bool, level int) (escalationAction, string) {
	if elapsed < escalationSteerAfter {
		return escalationNone, ""
	}
	// 有产出且够新 → 这条意图还活着，不动。
	if hasYield && sinceYield < escalationSteerAfter {
		return escalationNone, ""
	}
	if elapsed >= escalationParkAfter && (!hasYield || sinceYield >= escalationParkAfter) {
		return escalationPark, fmt.Sprintf("已运行 %d 分钟无任何产出", int(elapsed.Minutes()))
	}
	if level < 1 {
		return escalationSteer, ""
	}
	if level < 2 && elapsed >= escalationReviewAfter {
		return escalationReview, "纠偏后仍无新产出，评估有依据的不同角度"
	}
	return escalationNone, ""
}

// escalationSteerMessage 是 L1 注入的纠偏内容。
//
// 必须是**具体动作**，不能是「加油」「再试试」。sapper 的 doctrine 里写得很直白：
// 给鼓励等于没给；要指出下一步做什么，或者明确要求收口。
const escalationSteerMessage = "这条意图已经运行 15 分钟仍没有任何 fact/finding 写回。" +
	"请停下来做三件事：① 如果已经拿到部分结论，立刻用 record_fact / report_finding 落库；" +
	"② 如果卡在某个具体障碍（认证、WAF、路径不通），在总结里写清是什么障碍、试过哪些手段；" +
	"③ 如果当前路径明显走不通，直接结束本条意图，不要在同一个假设上重复尝试。"

// checkEscalation 由 plannerLoop 的独立 ticker 驱动，对运行中的意图执行阶梯判定。
// ticker 与规划共用同一循环生命周期，worker 完成事件重臂规划心跳不会推迟监督。
func (e *Engine) checkEscalation(t *Task) {
	store := t.Store
	if store == nil {
		return
	}
	clocks, err := store.RunningIntentsWithClock()
	if err != nil {
		return
	}
	now := time.Now()
	for _, c := range clocks {
		lastYield, err := store.LastYieldAt(c.ID)
		if err != nil {
			continue
		}
		hasYield := !lastYield.IsZero()
		var sinceYield time.Duration
		if hasYield {
			sinceYield = now.Sub(lastYield)
		}
		act, reason := decideEscalation(now.Sub(c.FirstRunAt), sinceYield, hasYield, c.EscalationLevel)
		switch act {
		case escalationSteer:
			if err := e.SteerWork(c.ID, escalationSteerMessage); err != nil {
				continue // work 可能刚好结束，下一轮再说
			}
			_ = store.SetEscalationLevel(c.ID, 1)
			log.Printf("[escalation] task %s intent #%d L1 纠偏（已运行 %d 分钟无产出）",
				t.ID, c.ID, int(now.Sub(c.FirstRunAt).Minutes()))
			e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
				Summary: fmt.Sprintf("阶梯干预：意图 #%d 运行 %d 分钟无产出，已注入一次战术纠偏", c.ID, int(now.Sub(c.FirstRunAt).Minutes()))})
		case escalationReview:
			// Advance only once; the event requests a decision, not a blind spawn.
			if err := store.SetEscalationLevel(c.ID, 2); err != nil {
				continue
			}
			t.trigMu.Lock()
			t.pendingTriggers = append(t.pendingTriggers, agent.TriggerEvent{
				Kind: "collaboration", IntentID: c.ID, Detail: reason,
			})
			t.trigMu.Unlock()
			t.Notify()
			e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
				Summary: fmt.Sprintf("阶梯评估：意图 #%d 纠偏后仍未推进，交规划者比较不同角度与现有队列的价值（不增加worker）", c.ID)})
		case escalationPark:
			// 先落 blocked 再 kill：worker 收到取消后会尝试把状态写成 stopped，
			// 但那时 CAS 已因状态变更失败，blocked 与原因得以保留。
			ok, err := store.ParkIntent(c.ID, reason+"；已按阶梯停放，需要时可在图上重开")
			if err != nil || !ok {
				continue
			}
			_ = e.KillWork(c.ID)
			log.Printf("[escalation] task %s intent #%d L4 停放（%s）", t.ID, c.ID, reason)
			e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
				Summary: fmt.Sprintf("阶梯干预：意图 #%d %s，已停放并释放 worker", c.ID, reason)})
		}
	}
}
