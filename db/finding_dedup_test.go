package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// 同任务同指纹的重复上报:不插新行,证据合并,返回原 finding_id + Duplicate。
func TestRecordFindingDedup(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ctx := context.Background()

	task, err := d.CreateTask("dedup test", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	// 真实资产行(anchors 有 asset 外键)
	var assetA, assetB int64
	if err := d.QueryRow(`INSERT INTO assets (type, domain, root_domain) VALUES ('service','a.dedup.test','dedup.test') RETURNING id`).Scan(&assetA); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO assets (type, domain, root_domain) VALUES ('service','b.dedup.test','dedup.test') RETURNING id`).Scan(&assetB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id IN ($1,$2)`, assetA, assetB) })

	in := RecordFindingInput{
		TaskID:        task.ID,
		ExplorationID: task.ExplorationID,
		VulnClass:     "sqli",
		Name:          "Union-based SQLi on /login",
		Severity:      "high",
		Summary:       "classic union sqli",
		Evidence:      "' OR 1=1 -- returned admin row",
		Worker:        "work#1",
		AssetIDs:      []int64{assetB, assetA},
	}

	r1, err := d.Exploration(in.ExplorationID).RecordFinding(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Duplicate {
		t.Fatal("first report must not be duplicate")
	}

	// 同指纹再来一次(不同 worker/证据/资产顺序)
	in2 := in
	in2.Worker = "work#2"
	in2.Evidence = "second confirmation with time-based blind sqli"
	in2.AssetIDs = []int64{assetA, assetB} // 顺序不同,指纹必须相同
	r2, err := d.Exploration(in2.ExplorationID).RecordFinding(ctx, in2)
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Duplicate || r2.FindingID != r1.FindingID {
		t.Fatalf("second report: duplicate=%v id=%d want dup of %d", r2.Duplicate, r2.FindingID, r1.FindingID)
	}

	// 库里只有一行,且证据含两次内容
	var rows int
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("rows=%d want 1", rows)
	}
	var ev string
	if err := d.QueryRow(`SELECT evidence FROM findings WHERE task_id=$1`, task.ID).Scan(&ev); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ev, "second confirmation") || !strings.Contains(ev, "OR 1=1") {
		t.Fatal("evidence merge lost one of the reports")
	}

	// 不同指纹(换 name)→ 新行
	in3 := in
	in3.Name = "Boolean-based SQLi on /search"
	r3, err := d.Exploration(in3.ExplorationID).RecordFinding(ctx, in3)
	if err != nil {
		t.Fatal(err)
	}
	if r3.Duplicate || r3.FindingID == r1.FindingID {
		t.Fatalf("different fingerprint must create new finding: dup=%v id=%d", r3.Duplicate, r3.FindingID)
	}
}

func TestRecordFindingDedupCleansAppendixAndRollsBack(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask("二次证据文本回归", "本地证据", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var assetID int64
	domain := "dedup-text-" + strconv.FormatInt(task.ID, 10) + ".test"
	if err := d.QueryRow(`INSERT INTO assets(type,domain,root_domain) VALUES ('service',$1,$1) RETURNING id`, domain).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.DeleteTask(task.ID)
		_, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, assetID)
	})
	es := d.Exploration(task.ExplorationID)
	intentIDs := make([]int64, 3)
	for i := range intentIDs {
		id, err := es.AddNode(KindIntent, map[string]any{"summary": "文本证据"}, 5, "running", "worker", nil)
		if err != nil {
			t.Fatal(err)
		}
		intentIDs[i] = id
	}
	in := RecordFindingInput{TaskID: task.ID, IntentID: intentIDs[0], VulnClass: "sqli",
		Name: "同指纹证据文本", Severity: "low", Summary: "首次摘要", Evidence: "原始证据\x00字节\xff保留", Worker: "worker:first", AssetIDs: []int64{assetID}}
	first, err := es.RecordFinding(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	var originalWorker, originalSummary, originalSeverity, originalEvidence string
	if err := d.QueryRow(`SELECT worker,summary,severity,evidence FROM findings WHERE id=$1`, first.FindingID).
		Scan(&originalWorker, &originalSummary, &originalSeverity, &originalEvidence); err != nil {
		t.Fatal(err)
	}
	var originalPayload []byte
	if err := d.QueryRow(`SELECT payload FROM exploration_nodes WHERE id=$1`, first.NodeID).Scan(&originalPayload); err != nil {
		t.Fatal(err)
	}
	if originalEvidence != "原始证据字节�保留" {
		t.Fatalf("首次证据归一不符：%q", originalEvidence)
	}
	second := in
	second.IntentID = intentIDs[1]
	second.Worker = "worker:second\x00\xff"
	second.Evidence = "二次\x00证据\xfe保留"
	second.Summary = "二次摘要"
	second.Severity = "high"
	duplicate, err := es.RecordFinding(t.Context(), second)
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate.Duplicate || duplicate.FindingID != first.FindingID || duplicate.NodeID != first.NodeID {
		t.Fatalf("二次上报未命中原漏洞：%+v", duplicate)
	}
	var worker, summary, severity, evidence string
	if err := d.QueryRow(`SELECT worker,summary,severity,evidence FROM findings WHERE id=$1`, first.FindingID).
		Scan(&worker, &summary, &severity, &evidence); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(evidence, 0) || !utf8.ValidString(evidence) || !strings.HasPrefix(evidence, originalEvidence) || !strings.Contains(evidence, "worker=worker:second�") || !strings.HasSuffix(evidence, "二次证据�保留") {
		t.Fatalf("二次证据未统一清理或丢失内容：%q", evidence)
	}
	if worker != originalWorker || summary != originalSummary || severity != "high" || originalSeverity != "low" {
		t.Fatalf("首次记录字段被二次上报意外覆盖：worker=%q summary=%q severity=%q", worker, summary, severity)
	}
	var payload []byte
	if err := d.QueryRow(`SELECT payload FROM exploration_nodes WHERE id=$1`, first.NodeID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var originalJSON, currentJSON any
	if err := json.Unmarshal(originalPayload, &originalJSON); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &currentJSON); err != nil {
		t.Fatal(err)
	}
	originalRaw, _ := json.Marshal(originalJSON)
	currentRaw, _ := json.Marshal(currentJSON)
	if string(originalRaw) != string(currentRaw) {
		t.Fatal("二次上报不能覆盖首次漏洞节点")
	}
	var yields int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_edges WHERE src_id=$1 AND rel=$2 AND dst_id=$3`, intentIDs[1], RelYields, first.NodeID).Scan(&yields); err != nil || yields != 1 {
		t.Fatalf("二次确认的意图血缘丢失：n=%d err=%v", yields, err)
	}
	// 流量快照失败发生在文字追加与血缘写入之后，整个事务必须一起回滚。
	failing := second
	failing.ExplorationID = task.ExplorationID
	failing.IntentID = intentIDs[2]
	failing.Evidence = "失败事务不应追加\x00\xff"
	failing.Severity = "critical"
	badEvidence := PreparedTrafficEvidence{Ref: TrafficRef{Role: "proof"}, Snapshot: TrafficEvidenceSnapshot{ID: "invalid-snapshot-hash"}}
	err = d.WithEvidenceTx(t.Context(), func(tx *sql.Tx) error {
		_, err := RecordFindingTx(t.Context(), tx, failing, []PreparedTrafficEvidence{badEvidence})
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "哈希不匹配") {
		t.Fatalf("无效快照应阻止提交：%v", err)
	}
	var afterEvidence, afterSeverity string
	if err := d.QueryRow(`SELECT evidence,severity FROM findings WHERE id=$1`, first.FindingID).Scan(&afterEvidence, &afterSeverity); err != nil {
		t.Fatal(err)
	}
	if afterEvidence != evidence || afterSeverity != severity {
		t.Fatal("失败事务泄漏了追加证据或严重程度")
	}
	if err := d.QueryRow(`SELECT count(*) FROM exploration_edges WHERE src_id=$1 AND rel=$2 AND dst_id=$3`, intentIDs[2], RelYields, first.NodeID).Scan(&yields); err != nil || yields != 0 {
		t.Fatalf("失败事务泄漏意图血缘：n=%d err=%v", yields, err)
	}
	var rows int
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("重复上报不能新增漏洞：n=%d err=%v", rows, err)
	}
}
