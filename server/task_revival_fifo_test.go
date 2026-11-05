package server

import "testing"

// TestTerminalTaskRevivalResetsClockAndSettlingAcrossFIFO 守住「开并发、走 FIFO
// 队列」这条复活路径。
//
// 为什么单独保留：上游的 task_revival_deadline_test.go 只覆盖 concurrency
// disabled 的立即起跑路径；排队路径上还要清掉旧收尾门、旧规划轮、旧进度与
// 旧的协调器标记，否则复活的跟进任务会在队列里被上一轮的残留卡住
// （timeout 复活被 residue settling 挡住 worker；done 复活拿过期 deadline
// 当场再收尾一次，人工跟进意图被静默吞掉）。
//
// 2026-11-06 上游删掉了 deadlineCoordinatorRun（协调器改成 bool 标记 +
// runtime cancel），本测试随之改写成不依赖内部类型。
func TestTerminalTaskRevivalResetsClockAndSettlingAcrossFIFO(t *testing.T) {
	for _, status := range []string{"done", "failed"} {
		t.Run(status, func(t *testing.T) {
			testTerminalTaskRevivalResetsClockAndSettlingAcrossFIFO(t, status)
		})
	}
}

func testTerminalTaskRevivalResetsClockAndSettlingAcrossFIFO(t *testing.T, status string) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	defer restoreConcurrencySetting(t, m)()
	if err := m.SetConcurrency(true, 1); err != nil {
		t.Fatal(err)
	}

	// 一个占位任务塞满唯一并发槽，让被复活的跟进任务必须排队。
	holder, err := m.CreateTask("timeout revival holder", "occupy slot", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	task, err := m.CreateTask("timed out follow-up", "run with a fresh clock", nil, 120, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = m.DeleteTask(holder.ID, DeleteTaskOptions{})
		_, _ = m.DeleteTask(task.ID, DeleteTaskOptions{})
	}()

	if _, err := m.StampTaskFirstRun(task.ID); err != nil {
		t.Fatal(err)
	}
	oldClock := task.lifecycleSnapshot()
	if oldClock.FirstRunAt == 0 || oldClock.DeadlineAt == 0 {
		t.Fatalf("测试前置没盖上原始时钟: %+v", oldClock)
	}
	if err := m.SetTaskStatus(task.ID, status); err != nil {
		t.Fatal(err)
	}

	// 模拟上一轮留下的残渣：收尾门、内存 deadline、首跑标记、规划轮数、进度行。
	s := newAdmissionTestServer(m, nil)
	s.engine.settling.Store(task.ID, "goal_met")
	s.engine.deadline.Store(task.ID, oldClock.DeadlineAt)
	s.engine.stamped.Store(task.ID, true)
	s.engine.plannerRound.Store(task.ID, 80)
	s.engine.coordStarted.Store(task.ID, true)
	if _, err := m.pg.RecordTaskProgress(task.ID, 80, 1, 1, 1); err != nil {
		t.Fatal(err)
	}
	task.requestSettle("auto_idle", "上一轮挂起收尾")

	result, err := s.applyTaskControl(task, "resume")
	if err != nil {
		t.Fatal(err)
	}
	queued := result.Queued

	// 旧协调器标记必须清掉：不清的话复活轮次会以为协调器还在，新的 deadline 无人执行。
	if _, ok := s.engine.coordStarted.Load(task.ID); ok {
		t.Fatal("排队期间仍保留旧协调器标记")
	}
	if reason, _ := task.peekSettle(); reason != "" {
		t.Fatalf("终态续跑仍保留挂起收尾 %q", reason)
	}
	if round := s.engine.nextPlannerRound(task.ID); round != 1 {
		t.Fatalf("终态续跑沿用旧规划轮数: %d", round)
	}
	if progress, err := m.pg.GetTaskProgress(task.ID); err != nil || progress != nil {
		t.Fatalf("终态续跑保留旧轮进度: progress=%+v err=%v", progress, err)
	}
	queuedState := task.lifecycleSnapshot()
	if !queued || !queuedState.Queued || queuedState.Status != "running" ||
		queuedState.FirstRunAt != 0 || queuedState.DeadlineAt != 0 {
		t.Fatalf("复活任务在排队前没有被重置: queued=%v state=%+v", queued, queuedState)
	}
	if s.engine.isSettling(task.ID) {
		t.Fatal("复活任务在排队期间仍带着旧收尾门")
	}
	if _, ok := s.engine.deadline.Load(task.ID); ok {
		t.Fatal("复活任务仍带着旧内存 deadline")
	}
	if _, ok := s.engine.stamped.Load(task.ID); ok {
		t.Fatal("复活任务仍带着旧首跑标记")
	}
	stored, err := m.pg.GetTask(mustTaskID(t, task.ID))
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil || stored.TimeoutSeconds != 120 || stored.FirstRunAt != nil || stored.DeadlineAt != nil {
		t.Fatalf("持久化的复活时钟/配置不符: %+v", stored)
	}
}
