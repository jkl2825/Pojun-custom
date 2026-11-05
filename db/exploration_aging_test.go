package db

import "testing"

// TestFrontierAgingBeatsFreshHighPriority 验证 frontier 的等待时间加权（aging）。
//
// 背景（2026-11-05 实测任务 333）：纯 `priority DESC, id ASC` 会让早期派出的
// 低优先级意图永久饥饿——78 条意图等了 5.7-11.6 小时一次没被领取，而同期
// 343 条更新的高优先级意图全部跑完。修法是每等 30 分钟折算 +1 有效优先级。
//
// 这个用例锁死核心语义：等够久的低优先级必须压过刚创建的高优先级；
// 同时「新意图仍按优先级排序」由 TestExplorationFlow 覆盖（新意图 age≈0，
// 加权为 0，顺序不变）。
func TestFrontierAgingBeatsFreshHighPriority(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("aging-test", "验证 frontier 防饥饿")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) // cascades nodes/edges/activity
	es := d.Exploration(expID)

	oldLow, err := es.AddIntent(map[string]any{"summary": "old low priority"}, 3, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	freshHigh, err := es.AddIntent(map[string]any{"summary": "fresh high priority"}, 9, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}

	// 让低优先级那条等 6 小时：有效优先级 3 + 12 = 15 > 9。
	if _, err := d.Exec(
		`UPDATE exploration_nodes SET created_at = now() - interval '6 hours' WHERE id=$1`, oldLow); err != nil {
		t.Fatal(err)
	}

	fr, err := es.Frontier(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(fr) != 2 {
		t.Fatalf("frontier 应返回 2 条，实际 %d", len(fr))
	}
	if fr[0].ID != oldLow {
		t.Fatalf("等待 6 小时的低优先级意图应排第一，实际第一是 #%d（期望 #%d，另一条 #%d）",
			fr[0].ID, oldLow, freshHigh)
	}
}

// TestFrontierAgingKeepsFreshOrder 确认 aging 不破坏「新意图按优先级排序」。
func TestFrontierAgingKeepsFreshOrder(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("aging-fresh", "验证新意图排序不变")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	low, err := es.AddIntent(map[string]any{"summary": "fresh low"}, 3, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	high, err := es.AddIntent(map[string]any{"summary": "fresh high"}, 9, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}

	fr, err := es.Frontier(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(fr) != 2 || fr[0].ID != high {
		t.Fatalf("新意图必须仍按优先级降序（期望 #%d 在前，实际 #%d；低优先级 #%d）",
			high, fr[0].ID, low)
	}
}
