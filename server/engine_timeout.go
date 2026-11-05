package server

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
)

// 任务级超时协调器(见 docs/任务级超时与收尾设计.md §4/§8.5)。
// 绝对墙钟:每个带 timeout 的任务一个定时 goroutine,到点驱动有序收尾时序:
//   ① settling → ② worker 停领新意图 / ③ planner 丢弃普通 notify
//   ④ 等在跑 worker drain(受 grace) → ⑤ 终局一轮 planner 判定 → ⑥ 定终态(带守卫)

const (
	// settleDrainGrace 是等在跑 worker 优雅收尾的上限;超过则硬 cancel。
	//
	// 为什么从 90s 提到 300s(2026-10-21 实测修正)：任务到点时可能同时有
	// **12 个 worker** 在跑(worker 数就是并发上限),每个都要走一遍 SDK 的
	// settlement(注入收尾词 + 禁 Bash + 写回成果 + 收尾总结)——那至少是
	// 1 轮 LLM 调用,而思考型模型(minimax-m3.1)一轮就要 30~60 秒。
	//
	// 实测线上任务 3：13:42:23 到点，13:43:53 就 drain 超时硬砍——90 秒里
	// 12 个 worker 只来得及各写回 1~3 条事实，正在写的成果直接丢了。
	// 收尾窗口必须按「并发 worker 数 × 单轮 LLM 耗时」来给，不能按单 worker 给。
	settleDrainGrace     = 300 * time.Second // 等在跑 worker 优雅收尾的上限;超过则硬 cancel
	deadlinePollInterval = 2 * time.Second   // deadline 未盖章/LLM 未就绪时的轮询间隔
	deadlineMaxSleep     = 30 * time.Second  // 单次最长睡眠(便于周期复查终态)
)

// ---------- settling 状态 ----------

func (e *Engine) isSettling(taskID string) bool {
	_, ok := e.settling.Load(taskID)
	return ok
}

// markSettling records the settle reason; returns true only for the first caller.
func (e *Engine) markSettling(taskID, reason string) bool {
	if reason == "" {
		reason = "timeout"
	}
	_, loaded := e.settling.LoadOrStore(taskID, reason)
	return !loaded
}

func (e *Engine) settleReason(taskID string) string {
	v, _ := e.settling.Load(taskID)
	s, _ := v.(string)
	return s
}

// ---------- 在跑计数(worker.Execute + planner.Plan),用于 drain ----------

func (e *Engine) inflightCounter(taskID string) *int64 {
	v, _ := e.inflight.LoadOrStore(taskID, new(int64))
	return v.(*int64)
}

// beginTaskOperation atomically registers a task-owned operation unless deletion
// has already installed its barrier. The delete handler can therefore wait for
// inflight==0 without a check-then-start race recreating files after cleanup.
func (e *Engine) beginTaskOperation(taskID string) bool {
	e.deleteMu.RLock()
	defer e.deleteMu.RUnlock()
	if e.IsDeleting(taskID) {
		return false
	}
	atomic.AddInt64(e.inflightCounter(taskID), 1)
	return true
}

func (e *Engine) decInflight(taskID string) { atomic.AddInt64(e.inflightCounter(taskID), -1) }
func (e *Engine) inflightCount(taskID string) int64 {
	return atomic.LoadInt64(e.inflightCounter(taskID))
}

// ---------- deadline ----------

// taskDeadline 优先读本轮盖章时钟，重启后回退到持久化快照。
// 读取不回填缓存，避免旧轮在终态复活清时钟之后重新缓存旧 deadline。
func (e *Engine) taskDeadline(t *Task) int64 {
	if v, ok := e.deadline.Load(t.ID); ok {
		return v.(int64)
	}
	return t.lifecycleSnapshot().DeadlineAt
}

// resetTerminalRevival 在终态准入提交成功后清理上一轮状态。配置预算保留，
// 下一次真实调用重新盖章；FIFO 等待期间仍由暂停门禁止执行。
func (e *Engine) resetTerminalRevival(t *Task) {
	e.stopDeadlineCoordinator(t.ID)
	e.deadline.Delete(t.ID)
	e.stamped.Delete(t.ID)
	e.plannerRound.Delete(t.ID)
	t.clearSettle()
	e.settling.Delete(t.ID)
}

// stampFirstRun records first_run_at + deadline_at on the FIRST real run (LLM ready)
// of a timeout task, once per process. No-op when the task has no timeout.
func (e *Engine) stampFirstRun(t *Task) {
	if t.TimeoutSeconds <= 0 {
		return
	}
	if _, loaded := e.stamped.LoadOrStore(t.ID, true); loaded {
		return
	}
	dl, err := e.m.StampTaskFirstRun(t.ID)
	if err != nil {
		log.Printf("[deadline] task %s 盖章 first_run 失败: %v", t.ID, err)
		e.stamped.Delete(t.ID) // 允许下次重试
		return
	}
	if dl > 0 {
		e.deadline.Store(t.ID, dl)
		log.Printf("[deadline] task %s 首次运行,截止于 %s", t.ID, time.Unix(dl, 0).Format("2006-01-02 15:04:05"))
	}
}

// clockCtx layers the task's TaskClock (absolute deadline) onto a run's context so
// worker/planner can clamp their wall-clock budget and pick per-run vs task-timeout
// wrap-up words. final marks the coordinator-driven terminal planner round.
func (e *Engine) clockCtx(base context.Context, t *Task, final bool, reason string) context.Context {
	dl := e.taskDeadline(t)
	if dl <= 0 && !final {
		return base // no timeout → unchanged behavior
	}
	return agent.WithTaskClock(base, agent.TaskClock{DeadlineUnix: dl, Final: final, FinalReason: reason})
}

// ---------- 协调器 ----------

type deadlineCoordinatorRun struct {
	cancel context.CancelFunc
}

func (e *Engine) stopDeadlineCoordinator(taskID string) {
	e.coordMu.Lock()
	defer e.coordMu.Unlock()
	if value, ok := e.coordStarted.LoadAndDelete(taskID); ok {
		if run, ok := value.(*deadlineCoordinatorRun); ok {
			run.cancel()
		}
	}
}

// startDeadlineCoordinator 每轮只启动一个协调器。标记保留至下一次终态续跑；
// 续跑取消旧轮的独立上下文，睡眠中的旧轮不能醒来收掉新一轮。
func (e *Engine) startDeadlineCoordinator(ctx context.Context, t *Task) {
	if t == nil || t.TimeoutSeconds <= 0 {
		return
	}
	e.deleteMu.RLock()
	defer e.deleteMu.RUnlock()
	if e.IsDeleting(t.ID) {
		return
	}
	e.coordMu.Lock()
	defer e.coordMu.Unlock()
	if _, started := e.coordStarted.Load(t.ID); started {
		return
	}
	rt := e.registerTaskRoutines(ctx, t.ID, 1)
	coordCtx, cancel := context.WithCancel(rt.ctx)
	run := &deadlineCoordinatorRun{cancel: cancel}
	e.coordStarted.Store(t.ID, run)
	runTaskRoutine(rt, func(context.Context) {
		defer cancel()
		e.deadlineCoordinator(coordCtx, t)
	})
}

// deadlineCoordinator waits until the task's absolute deadline, then runs the settle
// sequence. Absolute wall-clock: it keeps counting through pauses.
func (e *Engine) deadlineCoordinator(ctx context.Context, t *Task) {
	for {
		e.coordMu.Lock()
		if ctx.Err() != nil || isTerminalStatus(e.m.TaskStatus(t.ID)) {
			e.coordMu.Unlock()
			return
		}
		// 与换代清时钟共用锁，旧轮不能在 reset 之后回填旧 deadline。
		dl := e.taskDeadline(t)
		e.coordMu.Unlock()
		if dl <= 0 {
			if sleepCtx(ctx, deadlinePollInterval) { // not yet stamped (task hasn't really run)
				return
			}
			continue
		}
		if remaining := time.Until(time.Unix(dl, 0)); remaining > 0 {
			nap := remaining
			if nap > deadlineMaxSleep {
				nap = deadlineMaxSleep
			}
			if sleepCtx(ctx, nap) {
				return
			}
			continue
		}
		e.settleTask(ctx, t)
		return
	}
}

// settleTask runs the ordered settle sequence once (§4 steps ①–⑥).
func (e *Engine) settleTask(ctx context.Context, t *Task) {
	e.settleTaskWithReason(ctx, t, "timeout", "到达任务超时上限")
}

// settleTaskWithReason 是统一收尾入口。reason:
//   - timeout      任务绝对 deadline（终态 met?done:timeout）
//   - goal_met     planner 明确判定目标达成且无在跑意图（不再跑终局轮，直接 done）
//   - auto_idle / auto_coverage / auto_rounds 程序化自动收尾（终态 done）
func (e *Engine) settleTaskWithReason(ctx context.Context, t *Task, reason, detail string) {
	// 与协调器换代串行化：已取消的旧轮不得在新轮清门后重新写入 settling。
	e.coordMu.Lock()
	if ctx.Err() != nil || !e.markSettling(t.ID, reason) {
		e.coordMu.Unlock()
		return
	}
	t.clearSettle()
	e.coordMu.Unlock()
	label := reason
	switch reason {
	case "timeout":
		label = "到达超时上限"
	case "goal_met":
		label = "planner 判定目标达成且无在跑意图"
	case "auto_idle", "auto_coverage", "auto_rounds":
		label = "自动收尾：" + detail
	}
	log.Printf("[settle] task %s 进入收尾（%s）", t.ID, label)
	// 收官对账：只读清点「有多少方向没跑完、多少 finding 没证据」，写进 activity
	// 供交付时对照。不改任何状态——收尾阶段改状态的风险远大于收益。
	if tid, err := strconv.ParseInt(t.ID, 10, 64); err == nil && t.Store != nil {
		if rec, err := t.Store.ReconcileForSettle(tid); err == nil {
			log.Printf("[settle] task %s %s", t.ID, rec.Summary())
			e.emitActivity(t, db.Activity{Worker: "system", Kind: "text", Summary: rec.Summary()})
		}
		// 知识沉淀：把本任务里反复验证的手法（含否证边界）写进作用域知识库。
		// 只写不读，失败不阻断收尾——沉淀是加分项，不能成为收尾的失败点。
		if n, err := t.Store.DistillKnowledge(tid); err != nil {
			log.Printf("[settle] task %s 知识沉淀失败: %v", t.ID, err)
		} else if n > 0 {
			log.Printf("[settle] task %s 提炼知识 %d 条", t.ID, n)
		}
	}
	if reason != "timeout" {
		e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("自动收尾：%s", detail)})
	}
	// ④ 等在跑 worker/planner drain(在跑 run 因夹逼的 MaxDuration 自行进收尾);
	// 超过 grace 仍未清空 → 硬 cancel 该任务 exec ctx(settling-aware 分支正确归类)。
	hardStop := time.Now().Add(settleDrainGrace)
	for e.inflightCount(t.ID) > 0 {
		if time.Now().After(hardStop) {
			log.Printf("[settle] task %s drain 超时(%s),硬取消在跑 run", t.ID, settleDrainGrace)
			e.cancelExec(t.ID, agent.AbortSettleDrainTimeout)
			_ = sleepCtx(ctx, 3*time.Second) // 给 worker 分支一点时间落库/归类
			break
		}
		if sleepCtx(ctx, 500*time.Millisecond) {
			return // 引擎整体关停
		}
	}

	// ⑤ 终局一轮 planner。goal_met 已经是 planner 的最终判定，不再多跑一轮；
	// timeout 用超时收尾词，自动收尾用“按策略收尾”词。
	met := reason == "goal_met"
	if reason != "goal_met" {
		met = e.runFinalPlannerRound(ctx, t, reason)
	}
	if !e.beginTaskOperation(t.ID) {
		return
	}
	defer e.decInflight(t.ID)

	// ⑥ 定终态(带守卫)：timeout 保持 met?done:timeout；自动收尾统一 done。
	status := "done"
	if reason == "timeout" && !met {
		status = "timeout"
	}
	e.coordMu.Lock()
	if ctx.Err() != nil {
		e.coordMu.Unlock()
		return
	}
	won, err := e.m.SetTaskStatusGuarded(t.ID, status)
	e.coordMu.Unlock()
	switch {
	case err != nil:
		log.Printf("[settle] task %s 落终态失败: %v", t.ID, err)
	case won:
		log.Printf("[settle] task %s 收尾完成,终态=%s（%s）", t.ID, status, label)
		e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("任务收尾完成：%s；终态 %s", label, status)})
	default:
		log.Printf("[settle] task %s 收尾时已是终态,保留原状态", t.ID)
	}
}

// runFinalPlannerRound drives exactly ONE terminal planner round with the
// task-timeout planner words (final goal judgment; no new intents). Waits for the
// LLM to be ready (bounded by ctx) so a completable task isn't mis-judged timeout.
func (e *Engine) runFinalPlannerRound(ctx context.Context, t *Task, reason string) (met bool) {
	if e.IsDeleting(t.ID) {
		return false
	}
	planner, _ := e.snapshotFor(t)
	for planner == nil {
		if sleepCtx(ctx, deadlinePollInterval) {
			return false
		}
		if isTerminalStatus(e.m.TaskStatus(t.ID)) {
			return false
		}
		if e.IsDeleting(t.ID) {
			return false
		}
		planner, _ = e.snapshotFor(t)
	}
	// 独立 ctx(不挂 execCancel,避免 pause/硬 cancel 打断这最后一轮),带 Final 注入
	// 收尾词：timeout 用任务超时词，自动收尾用“按策略结束”词。
	fctx := e.clockCtx(ctx, t, true, reason)
	if !e.beginTaskOperation(t.ID) {
		return false
	}
	defer e.decInflight(t.ID)
	emit := func(r db.Activity) { e.emitActivity(t, r) }
	round := e.nextPlannerRound(t.ID)
	fctx = agent.WithDispatchPolicy(fctx, e.dispatchPolicy(t.ID, round))
	summary := fmt.Sprintf("任务超时收尾·终局判定(第 %d 轮)", round)
	if reason != "timeout" {
		summary = fmt.Sprintf("自动收尾·终局判定(第 %d 轮，原因 %s)", round, reason)
	}
	e.emitActivity(t, db.Activity{Worker: "planner", Kind: "round", Summary: summary})
	tTaskID, _ := strconv.ParseInt(t.ID, 10, 64)
	e.BeginLLMCall(t.ID)
	// 终局轮与普通规划轮同款墙钟护栏：fctx 是无 deadline 的 server 根 ctx，而
	// settleTask 在等这一步落终态——Plan 若卡死（上游半开连接/compactor 自死锁，
	// 两类都是线上发生过的事故），任务会永远停在 settling。超时=按「未达成」
	// 返回，走正常的超时收尾流程；卡死的 goroutine 泄漏是两害取其轻。
	roundCtx, roundCancel := context.WithTimeout(fctx, plannerRoundLimit())
	defer roundCancel()
	res := runPlannerRound(roundCtx, func(pctx context.Context) (bool, string, error) {
		return planner.Plan(pctx, tTaskID, e.m.assets, t.Store, t.Goal, t.drainTriggers(), emit)
	})
	e.EndLLMCall(t.ID)
	if res.err != nil && roundCtx.Err() != nil {
		log.Printf("[deadline] task %s 终局规划超时(%s)，按未达成继续收尾", t.ID, plannerRoundLimit())
		return false
	}
	if res.err != nil {
		log.Printf("[deadline] task %s 终局规划出错: %v", t.ID, res.err)
	} else if res.met {
		log.Printf("[deadline] task %s 终局判定目标达成: %s", t.ID, res.reason)
	}
	return res.met
}
