package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/evidence"
)

type failingFindingRecorder struct{}

func (failingFindingRecorder) Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error) {
	return nil, errors.New("fixture persistence failed")
}

func TestReportFindingOptionalTrafficWithoutCapture(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("TCP evidence", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(nil, "")
	ts.ts, ts.taskID = d.Exploration(task.ExplorationID), task.ID
	ts.SetFindingRecorder(evidence.New(d, nil, t.TempDir()))
	notices := 0
	ts.notifyFinding = func(int64, string) { notices++ }
	for _, refs := range []string{"", `,"traffic_refs":[]`, `,"traffic_refs":null`} {
		res, err := ts.addFinding().Call(t.Context(), json.RawMessage(`{"vulnclass":"TCP","severity":"low","summary":"verified TCP fixture","evidence":"command output proves the finding"`+refs+`}`), nil)
		if err != nil || !strings.HasPrefix(res.Flatten(), "finding recorded: ") {
			t.Fatalf("optional traffic rejected: %v %s", err, res.Flatten())
		}
		var out db.RecordedFinding
		if err := json.Unmarshal([]byte(strings.SplitN(res.Flatten(), "\n", 2)[1]), &out); err != nil {
			t.Fatal(err)
		}
		f, err := d.GetFinding(out.FindingID)
		if err != nil || f == nil || len(out.Traffic.Bindings) != 0 || f.Evidence != "command output proves the finding" {
			t.Fatalf("lost non-HTTP evidence: %+v %v", f, err)
		}
	}
	if notices != 3 {
		t.Fatalf("successful reports notified %d times", notices)
	}
}

func TestReportFindingAtomicContract(t *testing.T) {
	old := FindingTrafficBindingEnabled
	FindingTrafficBindingEnabled = func() bool { return true }
	t.Cleanup(func() { FindingTrafficBindingEnabled = old })
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("report contract", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(nil, "")
	ts.ts = d.Exploration(task.ExplorationID)
	ts.taskID = task.ID
	ts.worker = "fixture"
	notices := 0
	ts.notifyFinding = func(int64, string) { notices++ }
	call := func(body string) string {
		t.Helper()
		res, err := ts.addFinding().Call(t.Context(), json.RawMessage(body), nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.Flatten()
	}
	ts.SetFindingRecorder(failingFindingRecorder{})
	if got := call(`{"vulnclass":"TEST","summary":"fail","severity":"low","traffic_refs":[{"traffic_id":"x"}]}`); !strings.Contains(got, "persistence failed") {
		t.Fatal(got)
	}
	if notices != 0 || ts.writes.Findings != 0 {
		t.Fatal("notified before commit")
	}
	ts.SetFindingRecorder(nil)
	got := call(`{"vulnclass":"TEST","summary":"legacy report","severity":"low"}`)
	lines := strings.SplitN(got, "\n", 2)
	if len(lines) != 2 {
		t.Fatal(got)
	}
	var out db.RecordedFinding
	if err = json.Unmarshal([]byte(lines[1]), &out); err != nil {
		t.Fatal(err)
	}
	if lines[0] != fmt.Sprintf("finding recorded: %d", out.NodeID) || out.FindingID <= 0 || notices != 1 {
		t.Fatal(got)
	}
	f, err := d.GetFinding(out.FindingID)
	if err != nil || f == nil || f.NodeID == nil || *f.NodeID != out.NodeID {
		t.Fatalf("wrong finding/node mapping: %+v %v", f, err)
	}
	if got = call(`{"vulnclass":"TEST","summary":"no storage","severity":"low","traffic_refs":[{"traffic_id":"x"}]}`); !strings.Contains(got, "未登记") {
		t.Fatal(got)
	}
	if notices != 1 {
		t.Fatal("failed tool triggered reporter")
	}
}

func TestMechanicalEvidenceFormatDoesNotReplaceRuntimeVerification(t *testing.T) {
	cases := []struct {
		name, severity, evidence string
		reject                   bool
	}{
		{"version only", "high", "Server: ExampleServer version 1.0 banner match only", true},
		{"unsupported claim", "critical", "A serious issue probably exists and needs investigation", true},
		{"normalised severity", " High ", "A serious issue probably exists", true},
		{"http format", "high", "HTTP/1.1 200 OK\nContent-Type: application/json\nresponse fixture", false},
		{"medium keeps policy", "medium", "not yet verified", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if msg := validateMechanicalEvidenceForRun(context.Background(), tc.severity, tc.evidence); (msg != "") != tc.reject {
				t.Fatalf("message=%q reject=%v", msg, tc.reject)
			}
		})
	}
	plain := "command observation confirms an unexpected state transition\nindependent local trace confirms the same state transition"
	if msg := validateMechanicalEvidenceForRun(context.Background(), "high", plain); msg == "" {
		t.Fatal("unrecorded non-HTTP evidence accepted")
	}
	ledger := NewToolOutputLedger()
	ledger.Add(plain)
	ctx := WithToolOutputs(context.Background(), ledger, EvidenceVerifyBlock)
	if msg := validateMechanicalEvidenceForRun(ctx, "high", plain); msg != "" {
		t.Fatalf("genuine non-HTTP output rejected: %s", msg)
	}
	if msg := validateMechanicalEvidenceForRun(ctx, "high", plain+"\nfabricated additional detail that never appeared in tool output"); msg == "" {
		t.Fatal("partly fabricated text bypassed format gate")
	}
	versions := "Server: ExampleServer version 1.0 banner match only\nX-Powered-By: ExampleFramework version 2.0"
	ledger.Add(versions)
	if msg := validateMechanicalEvidenceForRun(ctx, "high", versions); msg == "" {
		t.Fatal("recorded version-only banner became a confirmed vulnerability")
	}
}

func TestReportFindingKeywordCannotBypassRealOutputLedger(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("evidence gate", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	tools := NewToolSet(d.Exploration(task.ExplorationID), "fixture")
	tools.SetTaskID(task.ID)
	ledger := NewToolOutputLedger()
	ledger.Add("unrelated harmless observation from a local fixture, no request was made")
	ctx := WithToolOutputs(context.Background(), ledger, EvidenceVerifyBlock)
	evidenceText := "curl -i http://fixture.invalid/not-called\nHTTP/1.1 200 OK\n" + strings.Repeat("fabricated response data that never appeared in tool output", 4)
	raw, _ := json.Marshal(map[string]any{"vulnclass": "TEST", "severity": "HIGH", "summary": "fixture must be rejected", "evidence": evidenceText})
	res, err := tools.addFinding().Call(ctx, raw, nil)
	if err != nil || !strings.Contains(res.Flatten(), "逐字回验未通过") {
		t.Fatalf("format keyword bypassed ledger: %v %s", err, res.Flatten())
	}
	if tools.writes.Findings != 0 {
		t.Fatal("rejected finding was counted as persisted")
	}
}
