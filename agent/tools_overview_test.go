package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/chu0119/pojun/db"
)

func TestOverviewTextBudgetIsFairAndUTF8Safe(t *testing.T) {
	if got := relatedOverviewBudgetForSources(1); got != relatedOverviewMaxTextPerSource {
		t.Fatalf("single source budget=%d want=%d", got, relatedOverviewMaxTextPerSource)
	}
	perSource := relatedOverviewBudgetForSources(db.MaxTaskSourceCount)
	if perSource*db.MaxTaskSourceCount > relatedOverviewTotalTextRunes {
		t.Fatalf("aggregate budget exceeded: per_source=%d", perSource)
	}

	budget := overviewTextBudget{remaining: 5}
	got := budget.take(strings.Repeat("中", 10), 20)
	if !utf8.ValidString(got) {
		t.Fatalf("budget truncation produced invalid UTF-8: %q", got)
	}
	if utf8.RuneCountInString(got) != 5 || !budget.truncated || budget.remaining != 0 {
		t.Fatalf("unexpected truncation: got=%q budget=%+v", got, budget)
	}
	if tail := budget.take("more", 20); tail != "" {
		t.Fatalf("exhausted budget returned more text: %q", tail)
	}
}

func dispatchTestTools(t *testing.T) (*ToolSet, *db.DB) {
	t.Helper()
	dsn := os.Getenv("POJUN_TEST_PG_DSN")
	if !db.IsTestDatabase(dsn) {
		t.Skip("requires explicit POJUN_TEST_PG_DSN ending in _test")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	expID, err := d.CreateExploration("dispatch contract", "bounded reasoning")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	return NewToolSet(d.Exploration(expID), "planner"), d
}

func TestDispatchRoundLimitCountsSuccessfulBatchAndRepeatedCalls(t *testing.T) {
	tools, _ := dispatchTestTools(t)
	tools.SetDispatchPolicy(DispatchPolicy{WorkerSlots: 4, Round: 1, MaxRounds: 20}, TaskClock{})
	// Rejected items do not spend allowance; one batch and later tool calls do.
	if _, err := tools.addOneIntent(intentItem{}); err == nil {
		t.Fatal("empty item accepted")
	}
	items := []map[string]any{{"summary": "观察日志中的进度变化"}, {"summary": "比较任务输入格式"}}
	raw, _ := json.Marshal(map[string]any{"intents": items})
	res, err := tools.addIntent().Call(context.Background(), raw, nil)
	if err != nil || strings.Contains(res.Flatten(), "errors") {
		t.Fatalf("initial batch: %s %v", res.Flatten(), err)
	}
	for _, summary := range []string{"核对依赖版本的公开说明", "检查本地记录的时间范围"} {
		if _, err := tools.addOneIntent(intentItem{Summary: summary}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tools.addOneIntent(intentItem{Summary: "第五项不能再派发"}); err == nil || !strings.Contains(err.Error(), "dispatch_round_limit") {
		t.Fatalf("missing shared round limit: %v", err)
	}
	if n, _ := tools.ts.CountOpenIntents(); n != 4 {
		t.Fatalf("persisted=%d want=4", n)
	}
}

func TestDispatchBackpressureAndHumanOverride(t *testing.T) {
	tools, _ := dispatchTestTools(t)
	for i := 0; i < 6; i++ {
		if _, err := tools.ts.AddIntent(map[string]any{"summary": fmt.Sprintf("historical queued %d", i)}, 5, nil, "planner"); err != nil {
			t.Fatal(err)
		}
	}
	tools.SetDispatchPolicy(DispatchPolicy{WorkerSlots: 3}, TaskClock{})
	if _, err := tools.addOneIntent(intentItem{Summary: "自主规划不扩大积压"}); err == nil || !strings.Contains(err.Error(), "queue_backpressure") {
		t.Fatalf("missing queue gate: %v", err)
	}
	human := NewToolSet(tools.ts, "main")
	id, err := human.addOneIntent(intentItem{Summary: "用户指定的独立检查"})
	if err != nil {
		t.Fatalf("human path changed: %v", err)
	}
	n, _ := tools.ts.GetNode(id)
	if n == nil || n.Origin != "human" {
		t.Fatalf("human origin not retained: %+v", n)
	}
	view := tools.dispatchOverview()
	if view["open"] != 7 || view["backpressure"] != true || view["round_created"] != 0 {
		t.Fatalf("budget snapshot disagrees with writes: %+v", view)
	}
}

func TestDispatchFinalRoundAndDeadlineCannotCreateWork(t *testing.T) {
	tools, _ := dispatchTestTools(t)
	cases := []struct {
		name  string
		p     DispatchPolicy
		clock TaskClock
	}{
		{"final", DispatchPolicy{WorkerSlots: 3}, TaskClock{Final: true}},
		{"capacity missing", DispatchPolicy{}, TaskClock{}},
		{"round ceiling", DispatchPolicy{WorkerSlots: 3, Round: 10, MaxRounds: 10}, TaskClock{}},
		{"deadline", DispatchPolicy{WorkerSlots: 3}, TaskClock{DeadlineUnix: time.Now().Add(time.Minute).Unix()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tools.SetDispatchPolicy(tc.p, tc.clock)
			if _, err := tools.addOneIntent(intentItem{Summary: "不应在终局增加方向"}); err == nil {
				t.Fatal("terminal budget accepted new work")
			}
		})
	}
	if n, _ := tools.ts.CountOpenIntents(); n != 0 {
		t.Fatalf("terminal refusals left %d rows", n)
	}
	tools.SetDispatchPolicy(DispatchPolicy{WorkerSlots: 3}, TaskClock{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tools.addOneIntentContext(ctx, intentItem{Summary: "已取消的规划轮不能迟到写入"}); err == nil {
		t.Fatal("cancelled planning round wrote an intent")
	}
}

func TestDispatchBriefingReferencesPersistWithoutChangingLineage(t *testing.T) {
	tools, _ := dispatchTestTools(t)
	fact, err := tools.ts.AddNode(db.KindFact, map[string]any{"summary": "confirmed observation", "evidence": "local test output"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := json.RawMessage(fmt.Sprint(fact))
	id, err := tools.addOneIntent(intentItem{Summary: "根据已确认观察检查差异", ParentIDs: []json.RawMessage{raw}, BriefingIDs: []json.RawMessage{raw}})
	if err != nil {
		t.Fatal(err)
	}
	n, _ := tools.ts.GetNode(id)
	var payload map[string]any
	_ = json.Unmarshal(n.Payload, &payload)
	if payload["parent_ids"] == nil || payload["briefing_ids"] == nil {
		t.Fatalf("missing briefing references: %s", n.Payload)
	}
	if _, err := tools.addOneIntent(intentItem{Summary: "错误引用意图不得透传", BriefingIDs: []json.RawMessage{json.RawMessage(fmt.Sprint(id))}}); err == nil {
		t.Fatal("intent accepted as briefing evidence")
	}
	trigger := renderTriggers(tools.ts, []TriggerEvent{{Kind: "collaboration", IntentID: id, Detail: "review marker"}})
	if !strings.Contains(trigger, "独立的验证角度") || !strings.Contains(trigger, "untrusted_data") {
		t.Fatalf("review trigger lacks decision framing: %s", trigger)
	}
}
