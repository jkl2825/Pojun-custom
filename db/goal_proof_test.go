package db

import "testing"

// TestRecordGoalProof 验证「凭什么判目标达成」被留痕，且对账能区分
// 「留有证明理由」和「仅为模型声称」。
//
// 背景（2026-11-05 实测）：任务 404 的 5 个目标里 3 个，挂的证据与目标要求
// 并不对应（目标要求经 8001 网关取 flag，证据却是 l1-jump 的 flag07）。
// 而 prove_goal 的 reason 参数解析后从未落库，事后只能靠人工逐条比对才看得出。
func TestRecordGoalProof(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("goal-proof-test", "验证证明留痕")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	// 目标 A：走 prove_goal 路径，带理由 → 算「留有理由」
	goalA, err := es.AddGoal(map[string]any{"text": "经 8001 网关取得 flag"}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := es.AddNode("fact", map[string]any{"summary": "flag07 提交成功"}, 0, "confirmed", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := es.SetNodeState(goalA, "met"); err != nil {
		t.Fatal(err)
	}
	if err := es.RecordGoalProof(goalA, ev, "flag07 的提交回包本身就是证据"); err != nil {
		t.Fatal(err)
	}

	// 目标 B：直接改成 met，没有留痕 → 算「仅声称」
	goalB, err := es.AddGoal(map[string]any{"text": "产出完整报告"}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := es.SetNodeState(goalB, "met"); err != nil {
		t.Fatal(err)
	}

	rec, err := es.ReconcileForSettle(-1)
	if err != nil {
		t.Fatal(err)
	}
	if rec.GoalsMet != 2 {
		t.Fatalf("GoalsMet=%d，期望 2", rec.GoalsMet)
	}
	if rec.GoalsNoReason != 1 {
		t.Fatalf("GoalsNoReason=%d，期望 1（只有 B 没留理由）", rec.GoalsNoReason)
	}
}
