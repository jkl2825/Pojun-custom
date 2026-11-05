package server

import (
	"context"
	"testing"
	"time"
)

// TestDecideEscalation 锁死阶梯判定的核心语义。
//
// 三条不变量：
//  1. 没到 15 分钟什么都不做（我们刚因为「过早掐断」吃过亏）；
//  2. 只要还在产出，跑多久都不干预（慢 ≠ 卡住）；
//  3. 无产出满 45 分钟才停放，且同一档不重复干预。
func TestDecideEscalation(t *testing.T) {
	cases := []struct {
		name       string
		elapsed    time.Duration
		sinceYield time.Duration
		hasYield   bool
		level      int
		want       escalationAction
	}{
		{"刚开始跑", 5 * time.Minute, 0, false, 0, escalationNone},
		{"刚过 15 分钟但有产出", 20 * time.Minute, 2 * time.Minute, true, 0, escalationNone},
		{"20 分钟无产出", 20 * time.Minute, 0, false, 0, escalationSteer},
		{"20 分钟无产出但已纠偏过", 20 * time.Minute, 0, false, 1, escalationNone},
		{"25 分钟纠偏后无产出需评估", 25 * time.Minute, 0, false, 1, escalationReview},
		{"已评估不重复派事件", 30 * time.Minute, 0, false, 2, escalationNone},
		{"未纠偏不能跳过提醒", 30 * time.Minute, 0, false, 0, escalationSteer},
		{"新产出不评估协作", 30 * time.Minute, 2 * time.Minute, true, 1, escalationNone},
		{"产出停在 20 分钟前", 20 * time.Minute, 20 * time.Minute, true, 0, escalationSteer},
		{"50 分钟无产出", 50 * time.Minute, 0, false, 1, escalationPark},
		{"50 分钟但 3 分钟前刚有产出", 50 * time.Minute, 3 * time.Minute, true, 1, escalationNone},
		{"50 分钟且产出停在 46 分钟前", 50 * time.Minute, 46 * time.Minute, true, 1, escalationPark},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := decideEscalation(c.elapsed, c.sinceYield, c.hasYield, c.level)
			if got != c.want {
				t.Fatalf("decideEscalation(%v, %v, hasYield=%v, level=%d) = %v，期望 %v（reason=%q）",
					c.elapsed, c.sinceYield, c.hasYield, c.level, got, c.want, reason)
			}
			if got == escalationPark && reason == "" {
				t.Error("停放必须给出原因，否则 planner 无法判断能否重开")
			}
		})
	}
}

func TestEscalationTicksRunBetweenContinuousPlannerEdges(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres 不可用 (%v)", err)
	}
	defer m.Close()
	task, err := m.CreateTask("escalation ticker", "持续边沿不饿死监督", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	iid, err := task.Store.AddIntent(map[string]any{"summary": "无产出意图"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := task.Store.ClaimIntent(iid, "work#1"); err != nil || !claimed {
		t.Fatalf("领取: claimed=%v err=%v", claimed, err)
	}
	if _, err := m.pg.Exec(`UPDATE exploration_nodes SET first_run_at=now()-interval '20 minutes' WHERE id=$1`, iid); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(m)
	e.debounce = 0
	workCtx, workCancel := context.WithCancelCause(context.Background())
	defer workCancel(nil)
	e.registerWork(iid, workCancel)
	defer func() {
		_, complete := e.detachWork(iid)
		complete(nil)
	}()
	loopCtx, loopCancel := context.WithCancel(context.Background())
	edgesCtx, stopEdges := context.WithCancel(context.Background())
	done := make(chan struct{})
	edgesDone := make(chan struct{})
	ticks := make(chan time.Time)
	go func() {
		defer close(done)
		e.plannerLoopWithEscalationTicks(loopCtx, task, ticks)
	}()
	go func() {
		defer close(edgesDone)
		for {
			select {
			case <-edgesCtx.Done():
				return
			case task.notify <- struct{}{}:
			}
		}
	}()
	defer func() {
		stopEdges()
		loopCancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("取消后 planner 循环未退出")
		}
		<-edgesDone
	}()
	select {
	case ticks <- time.Now():
	case <-time.After(5 * time.Second):
		t.Fatal("持续边沿阻止独立监督 tick 被接收")
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for {
		e.steerMu.Lock()
		messages := append([]string(nil), e.steerBox[iid]...)
		e.steerMu.Unlock()
		if len(messages) > 0 {
			if messages[0] != escalationSteerMessage {
				t.Fatalf("监督消息=%q", messages[0])
			}
			if workCtx.Err() != nil {
				t.Fatalf("L1 纠偏意外取消 worker: %v", context.Cause(workCtx))
			}
			return
		}
		select {
		case <-poll.C:
		case <-deadline.C:
			t.Fatal("独立监督 tick 未执行阶梯检查")
		}
	}
}

// TestEscalationThresholdOrdering 保证阈值顺序不会被误改成一个倒挂的配置。
func TestEscalationThresholdOrdering(t *testing.T) {
	if escalationSteerAfter >= escalationReviewAfter || escalationReviewAfter >= escalationParkAfter {
		t.Fatal("纠偏、协作评估、停放必须按顺序推进")
	}
	if escalationSteerAfter >= escalationParkAfter {
		t.Fatalf("纠偏阈值(%v)必须小于停放阈值(%v)", escalationSteerAfter, escalationParkAfter)
	}
	// 停放阈值至少要是实测均值（4.2 分钟/意图）的 5 倍，否则会重演 idle-stop 误杀。
	if escalationParkAfter < 5*4*time.Minute {
		t.Fatalf("停放阈值 %v 过小，实测平均意图执行 4.2 分钟，过小会误杀慢速利用链", escalationParkAfter)
	}
}

func TestEscalationReviewQueuesOneDecisionWithoutSpawning(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	task, err := m.CreateTask("collaboration review", "bounded review", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	iid, err := task.Store.AddIntent(map[string]any{"summary": "progress is stalled"}, 9, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := task.Store.ClaimIntent(iid, "work#1"); err != nil || !ok {
		t.Fatalf("claim=%v err=%v", ok, err)
	}
	if _, err := m.pg.Exec(`UPDATE exploration_nodes SET first_run_at=now()-interval '30 minutes', escalation_level=1 WHERE id=$1`, iid); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(m)
	e.checkEscalation(task)
	e.checkEscalation(task)
	events := task.drainTriggers()
	if len(events) != 1 || events[0].Kind != "collaboration" || events[0].IntentID != iid {
		t.Fatalf("review events=%+v", events)
	}
	open, running, collaborating, err := task.Store.IntentAdmissionStats()
	if err != nil || open != 0 || running != 1 || collaborating != 0 {
		t.Fatalf("review must not spawn: %d/%d/%d err=%v", open, running, collaborating, err)
	}
}

func TestDispatchPolicyUsesStartedRuntimeCapacity(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	e := NewEngine(m)
	rt := e.registerTaskRoutines(context.Background(), "capacity-snapshot", 0)
	e.runtimeMu.Lock()
	rt.workers = 2
	e.runtimeMu.Unlock()
	p := e.dispatchPolicy("capacity-snapshot", 7)
	if p.WorkerSlots != 2 || p.Round != 7 {
		t.Fatalf("policy=%+v", p)
	}
	rt.cancel()
}
