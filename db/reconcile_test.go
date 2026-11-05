package db

import "testing"

// TestReconcileForSettle 验证收尾对账能正确清点三类方向。
//
// 只测节点计数部分：findings 需要真实 task 行（FK），而这里关心的是
// 「有多少方向没跑完」——那才是收尾报告里最容易被漏掉的信息。
func TestReconcileForSettle(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("reconcile-test", "验证收官对账")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	openID, _ := es.AddIntent(map[string]any{"summary": "never ran"}, 5, nil, "planner")
	blockedID, _ := es.AddIntent(map[string]any{"summary": "hit a wall"}, 5, nil, "planner")
	doneID, _ := es.AddIntent(map[string]any{"summary": "finished"}, 5, nil, "planner")

	if ok, err := es.ClaimIntent(blockedID, "w"); err != nil || !ok {
		t.Fatalf("claim blocked candidate: %v %v", ok, err)
	}
	if _, err := es.ParkIntent(blockedID, "45 分钟无产出"); err != nil {
		t.Fatal(err)
	}
	if ok, err := es.ClaimIntent(doneID, "w"); err != nil || !ok {
		t.Fatalf("claim done candidate: %v %v", ok, err)
	}
	if _, err := d.Exec(`UPDATE exploration_nodes SET state='done' WHERE id=$1`, doneID); err != nil {
		t.Fatalf("conclude done intent: %v", err)
	}
	_ = openID

	rec, err := es.ReconcileForSettle(-1) // -1：不存在的 task，只看方向计数
	if err != nil {
		t.Fatal(err)
	}
	if rec.OpenIntents != 1 || rec.BlockedIntents != 1 || rec.ExecutedIntents != 1 {
		t.Fatalf("对账计数不对: open=%d blocked=%d executed=%d",
			rec.OpenIntents, rec.BlockedIntents, rec.ExecutedIntents)
	}
	if rec.TotalFindings != 0 || rec.NoEvidence != 0 {
		t.Fatalf("无 finding 时应为 0: total=%d noEvidence=%d", rec.TotalFindings, rec.NoEvidence)
	}
	if s := rec.Summary(); s == "" {
		t.Fatal("Summary 不应为空")
	}
}
