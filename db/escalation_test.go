package db

import "testing"

// TestEscalationStorePrimitives 验证阶梯用到的四个存储原语真的能跑通。
//
// 为什么必须测：server/escalation.go 里每处 store 调用失败都只是 `continue`
// （不能让一条意图的查询失败打断整轮巡查），所以 SQL 写错（列名、类型、
// GREATEST 语义）在生产里不会报错，只会让阶梯**静默失效**。
func TestEscalationStorePrimitives(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("escalation-test", "验证阶梯原语")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	id, err := es.AddIntent(map[string]any{"summary": "stuck intent"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}

	// 领取后必须带上 first_run_at，否则 RunningIntentsWithClock 会漏掉它。
	ok, err := es.ClaimIntent(id, "worker-1")
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	clocks, err := es.RunningIntentsWithClock()
	if err != nil {
		t.Fatal(err)
	}
	if len(clocks) != 1 || clocks[0].ID != id || clocks[0].FirstRunAt.IsZero() {
		t.Fatalf("running 意图的时钟不对（领取时应落 first_run_at）: %+v", clocks)
	}

	// 没有产出时 LastYieldAt 返回零值（而不是报错）。
	if ts, err := es.LastYieldAt(id); err != nil || !ts.IsZero() {
		t.Fatalf("无产出时 LastYieldAt 应返回零值: ts=%v err=%v", ts, err)
	}

	// 档位只升不降。
	if err := es.SetEscalationLevel(id, 1); err != nil {
		t.Fatal(err)
	}
	if err := es.SetEscalationLevel(id, 0); err != nil { // 试图回退
		t.Fatal(err)
	}
	if got, _ := es.RunningIntentsWithClock(); len(got) != 1 || got[0].EscalationLevel != 1 {
		t.Fatalf("escalation_level 应保持 1（GREATEST 只升不降），实际 %+v", got)
	}

	// 停放：状态转 blocked、写原因、档位推到 3。
	parked, err := es.ParkIntent(id, "已运行 45 分钟无任何产出")
	if err != nil || !parked {
		t.Fatalf("park: parked=%v err=%v", parked, err)
	}
	var state, reason string
	var level int
	if err := d.QueryRow(`SELECT state, COALESCE(blocked_reason,''), escalation_level FROM exploration_nodes WHERE id=$1`, id).
		Scan(&state, &reason, &level); err != nil {
		t.Fatal(err)
	}
	if state != "blocked" || reason == "" || level != 3 {
		t.Fatalf("停放结果不对: state=%q reason=%q level=%d", state, reason, level)
	}

	// 重开要清掉时钟与档位，否则第二轮会立刻又被停放。
	if ok, err := es.ReopenIntent(id); err != nil || !ok {
		t.Fatalf("reopen: ok=%v err=%v", ok, err)
	}
	var firstRun *string
	var level2 int
	if err := d.QueryRow(`SELECT first_run_at::text, escalation_level FROM exploration_nodes WHERE id=$1`, id).
		Scan(&firstRun, &level2); err != nil {
		t.Fatal(err)
	}
	if firstRun != nil || level2 != 0 {
		t.Fatalf("重开应清空 first_run_at 与档位: first_run_at=%v level=%d", firstRun, level2)
	}
}
