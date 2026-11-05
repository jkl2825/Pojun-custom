package server

import (
	"testing"
	"time"
)

// TestTerminalRevivalResetsDeadline 是任务 13（2026-11-05）事故的回归测试：
//
// 复现：任务在 11-04 因「目标已全部达成」落 done，但 first_run_at/deadline_at
// 仍留在 11-04 的 8 小时预算上；11-05 人类提交「深入漏洞」跟进意图 → admitTask
// 把 done 复活为 running，旧代码只对 timeout 复活重置时钟 → 复活的 coordinator
// 读到已过期的 deadline，1 秒后再次收尾（终局轮「不要再生成新意图」），
// 人工意图被静默吞掉，任务终态 timeout。
//
// 修复后：任何终态（done/failed/timeout）复活都清空 first_run_at/deadline_at，
// 清掉 Engine per-run 闸门（settling/deadline/stamped/coordStarted）与残留的
// 挂起收尾请求；下一次真实运行重新盖章整套预算。
func TestTerminalRevivalResetsDeadline(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	defer restoreConcurrencySetting(t, m)()
	// 关掉并发限制：复活直接启动，不进 FIFO（本测试只关心时钟/闸门重置）。
	if err := m.SetConcurrency(false, 0); err != nil {
		t.Fatal(err)
	}

	task, err := m.CreateTask("terminal revival deadline regression", "follow-up must get a fresh budget", nil, 3600, 0)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()

	// 模拟事故前现场：任务已跑过（盖过章）、因目标全达成落 done，且 deadline 已过期。
	if _, err := m.StampTaskFirstRun(task.ID); err != nil {
		t.Fatalf("initial stamp: %v", err)
	}
	// 终态走正式路径（DB+内存同步），时钟再改成过期值。
	if err := m.SetTaskStatus(task.ID, "done"); err != nil {
		t.Fatalf("mark done: %v", err)
	}
	expiredFirst := time.Now().Add(-26 * time.Hour)
	expiredDeadline := time.Now().Add(-18 * time.Hour)
	if _, err := m.pg.Exec(
		`UPDATE tasks SET first_run_at=$2, deadline_at=$3 WHERE id=$1`,
		task.ID, expiredFirst, expiredDeadline); err != nil {
		t.Fatalf("seed expired clocks: %v", err)
	}

	// 旧一轮留在 Engine 内存里的残留态：deadline 映射、首次盖章、协调器标记、
	// 挂起收尾请求——事故当天四者都会让复活立刻再收尾。
	s := newAdmissionTestServer(m, nil)
	s.engine.deadline.Store(task.ID, expiredDeadline.Unix())
	s.engine.stamped.Store(task.ID, true)
	s.engine.coordStarted.Store(task.ID, true)
	s.engine.settling.Store(task.ID, true)
	task.requestSettle("auto_idle", "stale settle from the previous life")

	// 走 UI「深入漏洞」同款入口：admitTask(resume)。
	queued, err := s.admitTask(task, "resume")
	if err != nil {
		t.Fatalf("admit revived task: %v", err)
	}
	if queued {
		t.Fatal("revived task should start immediately with concurrency disabled")
	}

	// DB：两个时钟必须清零，状态为 running。
	var status string
	var firstNull, deadlineNull bool
	if err := m.pg.QueryRow(
		`SELECT status, first_run_at IS NULL, deadline_at IS NULL FROM tasks WHERE id=$1`,
		task.ID).Scan(&status, &firstNull, &deadlineNull); err != nil {
		t.Fatalf("read back task: %v", err)
	}
	if status != "running" {
		t.Fatalf("status = %q, want running", status)
	}
	if !firstNull || !deadlineNull {
		t.Fatalf("terminal revival must clear clocks: first_run_at null=%v deadline_at null=%v", firstNull, deadlineNull)
	}

	// 内存态同步：deadline 协调器读 lifecycleSnapshot，必须同步清零。
	state := task.lifecycleSnapshot()
	if state.Status != "running" {
		t.Fatalf("memory status = %q, want running", state.Status)
	}
	if state.FirstRunAt != 0 || state.DeadlineAt != 0 {
		t.Fatalf("memory clocks not reset: FirstRunAt=%d DeadlineAt=%d", state.FirstRunAt, state.DeadlineAt)
	}

	// Engine 闸门：四项残留全部清掉，否则复活任务会被旧 deadline/settling 卡死。
	if s.engine.isSettling(task.ID) {
		t.Fatal("revival retained the stale settling gate")
	}
	if _, ok := s.engine.deadline.Load(task.ID); ok {
		t.Fatal("revival retained the stale in-memory deadline")
	}
	if _, ok := s.engine.stamped.Load(task.ID); ok {
		t.Fatal("revival retained the stale first-run stamp")
	}
	// 新规划/执行开始时会重新登记协调器；此处只保证旧标记已清。
	if reason, _ := task.peekSettle(); reason != "" {
		t.Fatalf("revival retained stale pending settle %q", reason)
	}

	// 重新盖章应得到「从现在起算」的新预算，而不是沿用旧 deadline。
	dl, err := m.StampTaskFirstRun(task.ID)
	if err != nil {
		t.Fatalf("re-stamp first run: %v", err)
	}
	if dl <= 0 {
		t.Fatal("stamp returned no deadline for a task with timeout_seconds=3600")
	}
	if dl < time.Now().Add(50*time.Minute).Unix() {
		t.Fatalf("fresh deadline %d looks stale (expected ≈ now+1h)", dl)
	}
}
