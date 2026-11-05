package db

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestTaskProgressCounters(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	taskID := fmt.Sprintf("progress-test-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = d.DeleteTaskProgress(taskID) })

	// 首轮建立基线，不立即计 idle。
	if idle, err := d.RecordTaskProgress(taskID, 1, 10, 5, 20); err != nil || idle != 0 {
		t.Fatalf("round1 idle=%d err=%v want 0", idle, err)
	}
	// 连续零增长 → 1、2。
	if idle, _ := d.RecordTaskProgress(taskID, 2, 10, 5, 20); idle != 1 {
		t.Fatalf("round2 idle=%d want 1", idle)
	}
	if idle, _ := d.RecordTaskProgress(taskID, 3, 10, 5, 20); idle != 2 {
		t.Fatalf("round3 idle=%d want 2", idle)
	}
	// 迟到的旧轮次不得重复累计。
	if idle, _ := d.RecordTaskProgress(taskID, 2, 10, 5, 20); idle != 2 {
		t.Fatalf("duplicate round idle=%d want 2", idle)
	}
	// 任一计数增长 → idle 归零。
	if idle, _ := d.RecordTaskProgress(taskID, 4, 11, 5, 20); idle != 0 {
		t.Fatalf("progress round idle=%d want 0", idle)
	}
	p, err := d.GetTaskProgress(taskID)
	if err != nil || p == nil || p.RoundNo != 4 || p.FactCount != 11 {
		t.Fatalf("get progress=%+v err=%v", p, err)
	}
	// Reset 只清 idle，保留计数基线。
	if _, err := d.RecordTaskProgress(taskID, 5, 11, 5, 20); err != nil {
		t.Fatalf("round5: %v", err)
	}
	if err := d.ResetTaskProgress(taskID); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if p, _ := d.GetTaskProgress(taskID); p == nil || p.IdleRounds != 0 || p.FactCount != 11 {
		t.Fatalf("after reset progress=%+v", p)
	}
	// 删除后不存在。
	_ = d.DeleteTaskProgress(taskID)
	if p, _ := d.GetTaskProgress(taskID); p != nil {
		t.Fatalf("progress should be deleted, got %+v", p)
	}
}

func TestCountExplorationProgress(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	facts, findings, err := d.CountExplorationProgress(-12345)
	if err != nil || facts != 0 || findings != 0 {
		t.Fatalf("empty exploration facts=%d findings=%d err=%v", facts, findings, err)
	}
}

func TestCollaborationRuntimeAccumulatesAndCapsAcrossResumes(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	exp, err := d.CreateExploration("runtime accounting", "bounded retries")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, exp)
	s := d.Exploration(exp)
	id, err := s.AddIntent(map[string]any{"summary": "bounded", "collaborates_with": 10, "collaboration_wall_ms": 0}, 8, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	readUsed := func() int64 {
		n, err := s.GetNode(id)
		if err != nil || n == nil {
			t.Fatalf("read: %v", err)
		}
		var fields struct {
			Used int64 `json:"collaboration_wall_ms"`
		}
		if err := json.Unmarshal(n.Payload, &fields); err != nil {
			t.Fatal(err)
		}
		return fields.Used
	}
	if err := s.RecordCollaborationRuntime(id, 125000); err != nil {
		t.Fatal(err)
	}
	if err := s.SetIntentState(id, "paused"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordCollaborationRuntime(id, 70000); err != nil {
		t.Fatal(err)
	}
	if got := readUsed(); got != 195000 {
		t.Fatalf("pause/retry reset the meter: %d", got)
	}
	if err := s.RecordCollaborationRuntime(id, 600000); err != nil {
		t.Fatal(err)
	}
	if got := readUsed(); got != 600000 {
		t.Fatalf("cap=%d", got)
	}
	if err := s.MergeIntentPayload(id, map[string]any{"collaboration_wall_ms": "invalid"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordCollaborationRuntime(id, 1); err != nil {
		t.Fatal(err)
	}
	if got := readUsed(); got != 600000 {
		t.Fatalf("malformed accounting reopened budget: %d", got)
	}
}
