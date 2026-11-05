package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIntentDeleteRejectsClaimBeforeWorkRegistration(t *testing.T) {
	for _, mode := range []string{"soft", "hard"} {
		t.Run(mode, func(t *testing.T) {
			d, err := Open(testDSN(t))
			if err != nil {
				t.Skipf("postgres 不可用 (%v)", err)
			}
			defer d.Close()
			expID, err := d.CreateExploration("claim then cancel", "保护尚未注册 work 的领取者")
			if err != nil {
				t.Fatal(err)
			}
			defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
			store := d.Exploration(expID)
			iid, err := store.AddIntent(map[string]any{"summary": "取消与领取竞争"}, 1, nil, "planner")
			if err != nil {
				t.Fatal(err)
			}
			before, err := store.GetNode(iid)
			if err != nil || before == nil || before.State != "open" {
				t.Fatalf("取消前快照: node=%+v err=%v", before, err)
			}
			if claimed, err := store.ClaimIntent(iid, "work#1"); err != nil || !claimed {
				t.Fatalf("领取: claimed=%v err=%v", claimed, err)
			}
			if mode == "hard" {
				_, err = store.CancelIntent(iid)
			} else {
				_, err = store.SoftDeleteIntent(iid, "取消旧快照")
			}
			if !errors.Is(err, ErrIntentStateConflict) {
				t.Fatalf("已领取意图删除错误=%v，期望状态冲突", err)
			}
			current, err := store.GetNode(iid)
			if err != nil || current == nil || current.State != "running" {
				t.Fatalf("活跃意图被清理: node=%+v err=%v", current, err)
			}
		})
	}
}

func TestHardDeleteRejectsRunningDescendant(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres 不可用 (%v)", err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("running descendant", "级联不得删除活跃后代")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	store := d.Exploration(expID)
	root := mustIntent(t, store, "根意图")
	fact := mustNode(t, store, KindFact, "已有产出")
	child := mustIntent(t, store, "活跃后代")
	mustLink(t, store, root, RelYields, fact)
	mustLink(t, store, fact, RelDerivedFrom, child)
	if claimed, err := store.ClaimIntent(child, "work#2"); err != nil || !claimed {
		t.Fatalf("后代领取: claimed=%v err=%v", claimed, err)
	}
	if _, err := store.CancelIntent(root); !errors.Is(err, ErrIntentStateConflict) {
		t.Fatalf("删除运行中后代错误=%v，期望状态冲突", err)
	}
	for _, id := range []int64{root, fact, child} {
		if gone(t, store, id) {
			t.Fatalf("冲突事务仍删除节点 %d", id)
		}
	}
}

func TestCompareAndSetIntentStateAllowsSingleWinner(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("intent CAS", "only one controller wins")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	store := d.Exploration(expID)
	intentID, err := store.AddIntent(map[string]any{"summary": "controlled"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := store.ClaimIntent(intentID, "worker"); err != nil || !claimed {
		t.Fatalf("claim: claimed=%v err=%v", claimed, err)
	}

	const contenders = 12
	var winners atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			changed, transitionErr := store.CompareAndSetIntentState(intentID, "running", "paused")
			if transitionErr != nil {
				t.Errorf("transition: %v", transitionErr)
				return
			}
			if changed {
				winners.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := winners.Load(); got != 1 {
		t.Fatalf("CAS winners=%d, want 1", got)
	}
	node, err := store.GetNode(intentID)
	if err != nil || node == nil || node.State != "paused" {
		t.Fatalf("node=%+v err=%v, want paused", node, err)
	}
}

func TestCancelIntentPreservesTokenMeteringWithoutDoubleCount(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("cancel token rollup", "preserve consumed tokens")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	store := d.Exploration(expID)
	intentID, err := store.AddIntent(map[string]any{"summary": "cancelled"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := store.ClaimIntent(intentID, "work#1"); err != nil || !claimed {
		t.Fatalf("claim: claimed=%v err=%v", claimed, err)
	}

	baselineDaily, err := d.TokenDailyAll(30)
	if err != nil {
		t.Fatal(err)
	}
	baseline := dailyTokenBuckets(baselineDaily)

	appendUsage := func(kind string, at time.Time, input, output, read, write *int) {
		t.Helper()
		activityID, appendErr := store.AppendActivity(Activity{
			NodeID: &intentID, Worker: "work#1", Kind: kind,
			InputTokens: input, OutputTokens: output,
			CacheReadTokens: read, CacheWriteTokens: write,
		})
		if appendErr != nil {
			t.Fatal(appendErr)
		}
		if _, updateErr := d.Exec(`UPDATE activity SET created_at=$1 WHERE id=$2`, at, activityID); updateErr != nil {
			t.Fatal(updateErr)
		}
	}
	values := func(input, output, read, write int) (*int, *int, *int, *int) {
		return &input, &output, &read, &write
	}

	now := time.Now().UTC()
	atUTCNoon := func(daysAgo int) time.Time {
		at := now.AddDate(0, 0, -daysAgo)
		return time.Date(at.Year(), at.Month(), at.Day(), 12, 0, 0, 0, time.UTC)
	}
	authoritativeDay := atUTCNoon(6)
	fallbackDay := atUTCNoon(4)
	trailingDay := atUTCNoon(2)

	// Run 1 has an authoritative result; its preceding cumulative frame must not
	// be counted a second time or move usage to the frame's earlier date.
	i, o, r, w := values(100, 100, 100, 100)
	appendUsage("usage", atUTCNoon(7), i, o, r, w)
	i, o, r, w = values(10, 11, 12, 13)
	appendUsage("result", authoritativeDay, i, o, r, w)
	// Run 2 models a legacy failed result that omitted usage. Its fallback belongs
	// to the result's date, not the cumulative frame's date.
	i, o, r, w = values(20, 21, 22, 23)
	appendUsage("usage", atUTCNoon(5), i, o, r, w)
	appendUsage("result", fallbackDay, nil, nil, nil, nil)
	// Run 3 was interrupted before a terminal result was persisted.
	i, o, r, w = values(30, 31, 32, 33)
	appendUsage("usage", trailingDay, i, o, r, w)

	beforeCancelDaily, err := d.TokenDailyAll(30)
	if err != nil {
		t.Fatal(err)
	}
	beforeCancel := dailyTokenBuckets(beforeCancelDaily)
	assertDailyTokenDelta(t, beforeCancel, baseline, authoritativeDay, 10, 11, 12)
	assertDailyTokenDelta(t, beforeCancel, baseline, fallbackDay, 0, 0, 0)
	assertDailyTokenDelta(t, beforeCancel, baseline, trailingDay, 0, 0, 0)

	if err := store.SetIntentState(intentID, "paused"); err != nil {
		t.Fatal(err)
	}
	cleanup, err := store.CancelIntent(intentID)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup.Activities != 5 {
		t.Fatalf("deleted activities=%d, want 5", cleanup.Activities)
	}
	total, err := store.TokenTotal()
	if err != nil {
		t.Fatal(err)
	}
	assertTokenUsage(t, total, 60, 63, 66, 69)
	afterCancelDaily, err := d.TokenDailyAll(30)
	if err != nil {
		t.Fatal(err)
	}
	afterCancel := dailyTokenBuckets(afterCancelDaily)
	assertDailyTokenDelta(t, afterCancel, baseline, authoritativeDay, 10, 11, 12)
	assertDailyTokenDelta(t, afterCancel, baseline, fallbackDay, 20, 21, 22)
	assertDailyTokenDelta(t, afterCancel, baseline, trailingDay, 30, 31, 32)
	assertDailyTokenDelta(t, afterCancel, baseline, now, 0, 0, 0)

	sessions, err := store.TokenStatsBySession()
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("cancelled intent leaked into sessions: %+v", sessions)
	}
	var rollups, datedRollups int
	if err := d.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (
			WHERE metadata->>'token_day'=TO_CHAR(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD')
		) FROM activity
		WHERE exploration_id=$1 AND worker='token-ledger' AND kind='result'
		  AND metadata->>'cancelled_intent_id'=$2`, expID, fmt.Sprint(intentID)).Scan(&rollups, &datedRollups); err != nil {
		t.Fatal(err)
	}
	if rollups != 3 || datedRollups != rollups {
		t.Fatalf("token rollups=%d dated=%d, want three correctly dated rows", rollups, datedRollups)
	}
	if _, err := store.CancelIntent(intentID); err == nil {
		t.Fatal("second cancellation unexpectedly succeeded")
	}
	afterRetry, err := store.TokenTotal()
	if err != nil {
		t.Fatal(err)
	}
	assertTokenUsage(t, afterRetry, 60, 63, 66, 69)
	afterRetryDaily, err := d.TokenDailyAll(30)
	if err != nil {
		t.Fatal(err)
	}
	assertDailyTokenBucketsEqual(t, dailyTokenBuckets(afterRetryDaily), afterCancel)
}

func dailyTokenBuckets(items []DailyTokenBucket) map[string]DailyTokenBucket {
	out := make(map[string]DailyTokenBucket, len(items))
	for _, item := range items {
		out[item.Day] = item
	}
	return out
}

func assertDailyTokenDelta(t *testing.T, got, baseline map[string]DailyTokenBucket, at time.Time, input, output, read int) {
	t.Helper()
	day := at.UTC().Format(time.DateOnly)
	actual, initial := got[day], baseline[day]
	if actual.InputTokens-initial.InputTokens != input ||
		actual.OutputTokens-initial.OutputTokens != output ||
		actual.CacheReadTokens-initial.CacheReadTokens != read {
		t.Fatalf("token delta for %s = input:%d output:%d cache-read:%d, want %d/%d/%d",
			day, actual.InputTokens-initial.InputTokens, actual.OutputTokens-initial.OutputTokens,
			actual.CacheReadTokens-initial.CacheReadTokens, input, output, read)
	}
}

func assertDailyTokenBucketsEqual(t *testing.T, got, want map[string]DailyTokenBucket) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("daily token buckets changed after retry: got=%+v want=%+v", got, want)
	}
	for day, expected := range want {
		if actual, ok := got[day]; !ok || actual != expected {
			t.Fatalf("daily token bucket %s changed after retry: got=%+v want=%+v", day, actual, expected)
		}
	}
}

func TestCancelIntentPreservesOutputsYieldedByAnotherIntent(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("shared intent output", "preserve shared facts and findings")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	store := d.Exploration(expID)
	first, err := store.AddIntent(map[string]any{"summary": "first"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AddIntent(map[string]any{"summary": "second"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	fact, err := store.AddNode(KindFact, map[string]any{"text": "shared fact"}, 1, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := store.AddNode(KindFinding, map[string]any{"summary": "shared finding"}, 1, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, intentID := range []int64{first, second} {
		if err := store.Link(intentID, RelYields, fact); err != nil {
			t.Fatal(err)
		}
		if err := store.Link(intentID, RelYields, finding); err != nil {
			t.Fatal(err)
		}
	}
	if claimed, err := store.ClaimIntent(first, "work#1"); err != nil || !claimed {
		t.Fatalf("claim: claimed=%v err=%v", claimed, err)
	}
	if err := store.SetIntentState(first, "paused"); err != nil {
		t.Fatal(err)
	}

	cleanup, err := store.CancelIntent(first)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup.Intents != 1 || cleanup.Facts != 0 || cleanup.Findings != 0 {
		t.Fatalf("cleanup=%+v, want only the cancelled intent", cleanup)
	}
	for _, nodeID := range []int64{fact, finding} {
		node, getErr := store.GetNode(nodeID)
		if getErr != nil || node == nil {
			t.Fatalf("shared node %d was removed: node=%+v err=%v", nodeID, node, getErr)
		}
	}
}

func newIntentAdmissionTestStore(t *testing.T) (*DB, *ExplorationStore) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres 不可用 (%v)", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	expID, err := d.CreateExploration("意图准入隔离测试", "验证派单边界")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	return d, d.Exploration(expID)
}

func mustAdmissionAsset(t *testing.T, d *DB, store *ExplorationStore, suffix string) int64 {
	t.Helper()
	id, err := d.Assets().UpsertRootDomain(UpsertRootDomainReq{Domain: fmt.Sprintf("intent-admission-%d-%s.invalid", store.ID(), suffix)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteAsset(d, id) })
	return id
}

func mustCollaborationSource(t *testing.T, d *DB, store *ExplorationStore) (source, fact, asset int64) {
	t.Helper()
	asset = mustAdmissionAsset(t, d, store, "source")
	source, err := store.AddIntent(map[string]any{
		"summary": "核查现有入口中的会话状态边界", "asset_ids": []int64{asset},
	}, 8, []int64{asset}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := store.ClaimIntent(source, "work#source"); err != nil || !claimed {
		t.Fatalf("领取协作源: claimed=%v err=%v", claimed, err)
	}
	if err := store.SetEscalationLevel(source, 2); err != nil {
		t.Fatal(err)
	}
	fact, err = store.AddNode(KindFact, map[string]any{
		"summary": "已确认存在独立事件记录", "evidence": "隔离测试观测：记录包含可核对的时间字段",
	}, 0, "confirmed", "work#source", nil)
	if err != nil {
		t.Fatal(err)
	}
	mustLink(t, store, source, RelYields, fact)
	return source, fact, asset
}

func collaborationAdmissionPayload(source, fact, asset int64) map[string]any {
	return map[string]any{
		"summary":             "从数据一致性视角复核事件先后顺序",
		"collaborates_with":   source,
		"collaboration_angle": "对照独立的历史记录与当前观测",
		"hypothesis":          "状态变化可能未被事件记录完整覆盖",
		"success_criteria":    "形成可复核的时序差异事实或否定证据",
		"briefing_ids":        []int64{fact},
		"asset_ids":           []int64{asset},
	}
}

func TestIntentAdmissionConcurrentLimitAndManualCompatibility(t *testing.T) {
	_, store := newIntentAdmissionTestStore(t)
	const limit, contenders = 3, 16
	var admitted atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range contenders {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			id, err := store.AddIntentAdmitted(map[string]any{"summary": fmt.Sprintf("独立候选方向编号%04d完成核验", index)}, 5, nil, "planner", IntentAdmission{MaxOpen: limit, Autonomous: true})
			if err == nil && id > 0 {
				admitted.Add(1)
			} else if err == nil || !strings.Contains(err.Error(), "queue_backpressure") {
				t.Errorf("并发准入 id=%d err=%v", id, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if got := admitted.Load(); got != limit {
		t.Fatalf("并发准入=%d，期望 %d", got, limit)
	}
	if _, err := store.AddIntentAdmitted(map[string]any{"summary": "用户明确投递的额外方向"}, 5, nil, "human", IntentAdmission{MaxOpen: limit}); err != nil {
		t.Fatalf("人工派单不应受自主队列上限限制: %v", err)
	}
	if _, err := store.AddIntent(map[string]any{"summary": "旧入口仍可写入"}, 5, nil, "human"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddIntentAdmitted(map[string]any{"summary": "没有有效队列上限的自主方向"}, 5, nil, "planner", IntentAdmission{Autonomous: true}); err == nil || !strings.Contains(err.Error(), "queue_backpressure") {
		t.Fatalf("缺少 MaxOpen 应拒绝: %v", err)
	}
	open, running, collaborating, err := store.IntentAdmissionStats()
	if err != nil || open != limit+2 || running != 0 || collaborating != 0 {
		t.Fatalf("完整计数: open=%d running=%d collab=%d err=%v", open, running, collaborating, err)
	}
}

func TestIntentAdmissionDeadlineUsesEarlierDatabaseBudget(t *testing.T) {
	d, store := newIntentAdmissionTestStore(t)
	if _, err := d.Exec(`INSERT INTO tasks(description,goal,exploration_id) VALUES ('准入截止测试','预算边界',$1)`, store.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM tasks WHERE exploration_id=$1`, store.ID()) })
	setDeadline := func(deadline any) {
		t.Helper()
		if _, err := d.Exec(`UPDATE tasks SET deadline_at=$2 WHERE exploration_id=$1`, store.ID(), deadline); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name       string
		stored     any
		requested  int64
		wantReject bool
	}{
		{"数据库已过期", time.Now().Add(-time.Minute), time.Now().Add(time.Hour).Unix(), true},
		{"数据库剩余一分钟", time.Now().Add(time.Minute), time.Now().Add(time.Hour).Unix(), true},
		{"调用端更早", time.Now().Add(time.Hour), time.Now().Add(time.Minute).Unix(), true},
		{"数据库无截止", nil, 0, false},
		{"预算充足", time.Now().Add(time.Hour), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setDeadline(tc.stored)
			_, err := store.AddIntentAdmitted(map[string]any{"summary": tc.name + "对应的独立核验方向"}, 5, nil, "planner", IntentAdmission{MaxOpen: 10, Autonomous: true, DeadlineUnix: tc.requested})
			if tc.wantReject {
				if err == nil || !strings.Contains(err.Error(), "deadline_backpressure") {
					t.Fatalf("期望截止拒绝，得到 %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
	setDeadline(time.Now().Add(-time.Hour))
	if _, err := store.AddIntentAdmitted(map[string]any{"summary": "人工请求保持历史兼容"}, 5, nil, "human", IntentAdmission{}); err != nil {
		t.Fatal(err)
	}
	source, fact, asset := mustCollaborationSource(t, d, store)
	setDeadline(time.Now().Add(4 * time.Minute))
	_, err := store.AddIntentAdmitted(collaborationAdmissionPayload(source, fact, asset), 8, []int64{asset}, "planner", IntentAdmission{Autonomous: true, CollaboratesWith: source, DeadlineUnix: time.Now().Add(time.Hour).Unix()})
	if err == nil || !strings.Contains(err.Error(), "deadline_backpressure") {
		t.Fatalf("协作剩余不足五分钟应拒绝: %v", err)
	}
}

func TestIntentAdmissionPreservesConservativeDedupRules(t *testing.T) {
	_, store := newIntentAdmissionTestStore(t)
	base := "核对目标资产的事件时间字段是否完整"
	if _, err := store.AddIntentAdmitted(map[string]any{"summary": base}, 5, nil, "planner", IntentAdmission{MaxOpen: 20, Autonomous: true}); err != nil {
		t.Fatal(err)
	}
	for _, summary := range []string{base + "。", "  " + base + " ", base + "并补充当前观测"} {
		if _, err := store.AddIntentAdmitted(map[string]any{"summary": summary}, 5, nil, "planner", IntentAdmission{MaxOpen: 20, Autonomous: true}); err == nil || !strings.Contains(err.Error(), "duplicate_intent") {
			t.Fatalf("摘要 %q 应去重，得到 %v", summary, err)
		}
	}
	for range 2 {
		if _, err := store.AddIntentAdmitted(map[string]any{"summary": "短句"}, 5, nil, "human", IntentAdmission{}); err != nil {
			t.Fatalf("保留短摘要不判重规则: %v", err)
		}
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.AddIntentAdmitted(map[string]any{"summary": "并发提交同一个新的完整方向"}, 5, nil, "planner", IntentAdmission{MaxOpen: 20, Autonomous: true})
			if err == nil {
				winners.Add(1)
			} else if !strings.Contains(err.Error(), "duplicate_intent") {
				t.Errorf("并发判重错误: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("同摘要并发准入成功=%d，期望 1", winners.Load())
	}
}

func TestCollaborationAdmissionRejectsStageRecursiveAndForeignSources(t *testing.T) {
	for _, tc := range []struct {
		name, state                string
		priority, level            int
		recursive, foreign, manual bool
	}{
		{name: "未运行", state: "open", priority: 8, level: 1},
		{name: "尚未纠偏", state: "running", priority: 8, level: 0},
		{name: "L1不能跳过评估", state: "running", priority: 8, level: 1},
		{name: "价值不足", state: "running", priority: 7, level: 2},
		{name: "递归协作", state: "running", priority: 8, level: 2, recursive: true},
		{name: "外图源", state: "running", priority: 8, level: 2, foreign: true},
		{name: "人工不能绕过协作准入", state: "running", priority: 8, level: 2, manual: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, store := newIntentAdmissionTestStore(t)
			source, fact, asset := mustCollaborationSource(t, d, store)
			if _, err := d.Exec(`UPDATE exploration_nodes SET state=$2, priority=$3, escalation_level=$4 WHERE id=$1`, source, tc.state, tc.priority, tc.level); err != nil {
				t.Fatal(err)
			}
			if tc.recursive {
				if err := store.MergeIntentPayload(source, map[string]any{"collaborates_with": int64(1)}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.foreign {
				expID, err := d.CreateExploration("外图", "不可作为协作源")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
				if _, err := d.Exec(`UPDATE exploration_nodes SET exploration_id=$2 WHERE id=$1`, source, expID); err != nil {
					t.Fatal(err)
				}
			}
			id, err := store.AddIntentAdmitted(collaborationAdmissionPayload(source, fact, asset), 8, []int64{asset}, "planner", IntentAdmission{MaxOpen: 10, Autonomous: !tc.manual, CollaboratesWith: source})
			if id != 0 || err == nil || !strings.Contains(err.Error(), "collaboration_rejected") {
				t.Fatalf("越界协作应拒绝: id=%d err=%v", id, err)
			}
		})
	}
}

func TestCollaborationAdmissionRequiresEvidenceAndBoundedScope(t *testing.T) {
	for _, mode := range []string{"无源证据", "空壳证据", "跨图交接", "扩展锚点", "源无锚点", "payload扩大目标", "targets改变", "角度复读"} {
		t.Run(mode, func(t *testing.T) {
			d, store := newIntentAdmissionTestStore(t)
			source, fact, asset := mustCollaborationSource(t, d, store)
			payload := collaborationAdmissionPayload(source, fact, asset)
			anchors := []int64{asset}
			switch mode {
			case "无源证据", "空壳证据":
				evidence := `"   "`
				if mode == "空壳证据" {
					evidence = `{"by":"worker","poc":""}`
				}
				if _, err := d.Exec(`UPDATE exploration_nodes SET payload=jsonb_set(payload,'{evidence}',$2::jsonb) WHERE id=$1`, fact, evidence); err != nil {
					t.Fatal(err)
				}
			case "跨图交接":
				expID, err := d.CreateExploration("外图事实", "交接只能本图授权")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
				foreign, err := d.Exploration(expID).AddNode(KindFact, map[string]any{"summary": "外图观测", "evidence": "有效但外图的证据"}, 0, "confirmed", "worker", nil)
				if err != nil {
					t.Fatal(err)
				}
				payload["briefing_ids"] = []int64{foreign}
			case "扩展锚点", "payload扩大目标":
				extra := mustAdmissionAsset(t, d, store, "extra")
				if mode == "扩展锚点" {
					anchors = append(anchors, extra)
				} else {
					payload["asset_ids"] = []int64{asset, extra}
				}
			case "源无锚点":
				if _, err := d.Exec(`DELETE FROM exploration_anchors WHERE node_id=$1`, source); err != nil {
					t.Fatal(err)
				}
			case "targets改变":
				payload["targets"] = []string{"新的无关目标"}
			case "角度复读":
				payload["collaboration_angle"] = "核查现有入口中的会话状态边界。"
			}
			id, err := store.AddIntentAdmitted(payload, 8, anchors, "planner", IntentAdmission{Autonomous: true, CollaboratesWith: source})
			if id != 0 || err == nil || !strings.Contains(err.Error(), "collaboration_rejected") {
				t.Fatalf("无证据或越界协作应拒绝: id=%d err=%v", id, err)
			}
			_, _, collaborating, err := store.IntentAdmissionStats()
			if err != nil || collaborating != 0 {
				t.Fatalf("拒绝后仍有协作: n=%d err=%v", collaborating, err)
			}
		})
	}
}

func TestCollaborationAdmissionReservedSlotAndHistoricalSourceLimit(t *testing.T) {
	d, store := newIntentAdmissionTestStore(t)
	source, fact, asset := mustCollaborationSource(t, d, store)
	for i := range 150 {
		if _, err := store.AddIntent(map[string]any{"summary": fmt.Sprintf("迁移遗留待领方向%04d", i)}, 3, nil, "planner"); err != nil {
			t.Fatal(err)
		}
	}
	// A stuck source may have no yield of its own: existing, explicit local
	// evidence is enough to support a genuinely different angle.
	if _, err := d.Exec(`DELETE FROM exploration_edges WHERE exploration_id=$1 AND src_id=$2 AND rel=$3`, store.ID(), source, RelYields); err != nil {
		t.Fatal(err)
	}
	payload := collaborationAdmissionPayload(source, fact, asset)
	delete(payload, "briefing_ids")
	id, err := store.AddIntentAdmitted(payload, 8, []int64{asset}, "planner", IntentAdmission{MaxOpen: 2, Autonomous: true, CollaboratesWith: source, ParentIDs: []int64{fact}})
	if err != nil || id == 0 {
		t.Fatalf("旧队列150条时应保留一个协作位: id=%d err=%v", id, err)
	}
	node, err := store.GetNode(id)
	if err != nil || node == nil {
		t.Fatalf("读取协作: node=%+v err=%v", node, err)
	}
	var stored struct {
		RunBudgetSeconds int `json:"run_budget_seconds"`
	}
	if err := json.Unmarshal(node.Payload, &stored); err != nil || stored.RunBudgetSeconds != 600 {
		t.Fatalf("协作短单预算=%d err=%v", stored.RunBudgetSeconds, err)
	}
	if _, mutated := payload["run_budget_seconds"]; mutated {
		t.Fatal("准入不应修改调用端 payload")
	}
	frontier, err := store.Frontier(1)
	if err != nil || len(frontier) != 1 || frontier[0].ID != id {
		t.Fatalf("保留位协作必须可被现有worker及时领取: %+v %v", frontier, err)
	}
	var edges int
	if err := d.QueryRow(`SELECT COUNT(*) FROM exploration_edges WHERE exploration_id=$1 AND dst_id=$2 AND rel=$3 AND src_id IN ($4,$5)`, store.ID(), id, RelDerivedFrom, source, fact).Scan(&edges); err != nil || edges != 2 {
		t.Fatalf("协作源和事实必须原子连入血缘: edges=%d err=%v", edges, err)
	}
	open, running, collaborating, err := store.IntentAdmissionStats()
	if err != nil || open != 151 || running != 1 || collaborating != 1 {
		t.Fatalf("保留位计数 open=%d running=%d collab=%d err=%v", open, running, collaborating, err)
	}
	second, err := store.AddIntent(map[string]any{"summary": "复核另一个独立的重要业务步骤", "asset_ids": []int64{asset}}, 8, []int64{asset}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := store.ClaimIntent(second, "work#second"); err != nil || !claimed {
		t.Fatalf("领取第二个源: claimed=%v err=%v", claimed, err)
	}
	if err := store.SetEscalationLevel(second, 2); err != nil {
		t.Fatal(err)
	}
	mustLink(t, store, second, RelYields, fact)
	other := collaborationAdmissionPayload(second, fact, asset)
	other["summary"] = "验证独立记录中的计数差异"
	if _, err := store.AddIntentAdmitted(other, 8, []int64{asset}, "planner", IntentAdmission{Autonomous: true, CollaboratesWith: second}); err == nil || !strings.Contains(err.Error(), "collaboration_rejected") {
		t.Fatalf("已有活跃协作必须拒绝另一个源: %v", err)
	}
	if err := store.SetIntentState(id, "paused"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddIntentAdmitted(other, 8, []int64{asset}, "planner", IntentAdmission{Autonomous: true, CollaboratesWith: second}); err == nil {
		t.Fatal("暂停的协作仍须占用保留位")
	}
	if err := store.SetIntentState(id, "blocked"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReopenBlockedIntents(); err != nil {
		t.Fatal(err)
	}
	if still, _ := store.GetNode(id); still == nil || still.State != "blocked" {
		t.Fatal("批量故障重跑不得绕过协作准入")
	}
	if err := store.SetIntentState(id, "done"); err != nil {
		t.Fatal(err)
	}
	retry := collaborationAdmissionPayload(source, fact, asset)
	retry["summary"] = "换个文字仍不可重复为同一源派协作"
	if _, err := store.AddIntentAdmitted(retry, 8, []int64{asset}, "planner", IntentAdmission{Autonomous: true, CollaboratesWith: source}); err == nil || !strings.Contains(err.Error(), "collaboration_rejected") {
		t.Fatalf("终态协作仍须占用源历史配额: %v", err)
	}
	if _, err := d.Exec(`DELETE FROM exploration_nodes WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddIntentAdmitted(retry, 8, []int64{asset}, "planner", IntentAdmission{Autonomous: true, CollaboratesWith: source}); err == nil {
		t.Fatal("删除子单不得刷新源协作配额")
	}
}

func TestIntentAdmissionRollbackLeavesNoNodeAnchorOrEdge(t *testing.T) {
	d, store := newIntentAdmissionTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if id, err := store.AddIntentAdmittedContext(ctx, map[string]any{"summary": "取消后不得迟到写入"}, 5, nil, "planner", IntentAdmission{MaxOpen: 10, Autonomous: true}); id != 0 || err == nil {
		t.Fatalf("已取消准入仍写入: id=%d err=%v", id, err)
	}
	asset := mustAdmissionAsset(t, d, store, "rollback")
	root, err := store.AddNode(KindFact, map[string]any{"summary": "原始任务"}, 0, "origin", "system", nil)
	if err != nil {
		t.Fatal(err)
	}
	counts := func() (nodes, anchors, edges int) {
		t.Helper()
		if err := d.QueryRow(`SELECT
 (SELECT COUNT(*) FROM exploration_nodes WHERE exploration_id=$1),
 (SELECT COUNT(*) FROM exploration_anchors a JOIN exploration_nodes n ON n.id=a.node_id WHERE n.exploration_id=$1),
 (SELECT COUNT(*) FROM exploration_edges WHERE exploration_id=$1)`, store.ID()).Scan(&nodes, &anchors, &edges); err != nil {
			t.Fatal(err)
		}
		return
	}
	nodesBefore, anchorsBefore, edgesBefore := counts()
	id, err := store.AddIntentAdmitted(map[string]any{"summary": "链路写入失败必须完整回滚"}, 5, []int64{asset}, "planner", IntentAdmission{MaxOpen: 10, Autonomous: true, ParentIDs: []int64{root, -1}})
	if id != 0 || err == nil {
		t.Fatalf("坏父链应回滚: id=%d err=%v", id, err)
	}
	nodesAfter, anchorsAfter, edgesAfter := counts()
	if nodesAfter != nodesBefore || anchorsAfter != anchorsBefore || edgesAfter != edgesBefore {
		t.Fatalf("事务残留: nodes %d/%d anchors %d/%d edges %d/%d", nodesAfter, nodesBefore, anchorsAfter, anchorsBefore, edgesAfter, edgesBefore)
	}
	id, err = store.AddIntentAdmitted(map[string]any{"summary": "无显式父节点时连入根事实"}, 5, []int64{asset}, "planner", IntentAdmission{MaxOpen: 10, Autonomous: true})
	if err != nil {
		t.Fatal(err)
	}
	var linked int
	if err := d.QueryRow(`SELECT COUNT(*) FROM exploration_edges WHERE exploration_id=$1 AND src_id=$2 AND dst_id=$3 AND rel=$4`, store.ID(), root, id, RelDerivedFrom).Scan(&linked); err != nil || linked != 1 {
		t.Fatalf("根事实兜底血缘: linked=%d err=%v", linked, err)
	}
}
