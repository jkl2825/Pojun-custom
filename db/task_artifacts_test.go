package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTaskArtifactProvenanceJSON(t *testing.T) {
	original := TaskArtifact{
		ID: 7, TaskID: "17", FindingID: 9, IntentID: 42,
		SourcePath: "tasks/17/i42/proof.png", Storage: "tasks/17/artifacts/copy.png",
		Name: "proof.png", Kind: "image",
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var restored TaskArtifact
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.IntentID != original.IntentID || restored.SourcePath != original.SourcePath || restored.Storage != "" {
		t.Fatalf("来源序列化不符：%+v", restored)
	}
	var legacy TaskArtifact
	if err := json.Unmarshal([]byte(`{"id":8,"task_id":"17","name":"legacy-i42.png","kind":"image"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.IntentID != 0 || legacy.SourcePath != "" {
		t.Fatalf("旧格式不能猜测来源：%+v", legacy)
	}
	legacyJSON, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(legacyJSON), "intent_id") || strings.Contains(string(legacyJSON), "source_path") {
		t.Fatalf("旧格式的未知来源应保持省略：%s", legacyJSON)
	}
}

func TestEnsureTaskArtifactsTableMigratesProvenance(t *testing.T) {
	sqlDB, err := sql.Open("pgx", testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	// 单连接的独立 schema 模拟旧表升级，不改其它用例的附件表。
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	d := &DB{DB: sqlDB}
	schema := fmt.Sprintf("artifact_migration_%d", time.Now().UnixNano())
	if _, err := d.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
	if _, err := d.Exec(`SET search_path TO ` + schema); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`CREATE TABLE task_artifacts (
 id BIGSERIAL PRIMARY KEY, task_id TEXT NOT NULL, name TEXT NOT NULL,
 kind TEXT NOT NULL DEFAULT 'other', mime TEXT, size_bytes BIGINT NOT NULL DEFAULT 0,
 sha256 TEXT, source_url TEXT, note TEXT, storage_path TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`); err != nil {
		t.Fatal(err)
	}
	var oldID int64
	if err := d.QueryRow(`INSERT INTO task_artifacts(task_id,name,storage_path)
VALUES ('17','legacy-i42.png','tasks/17/i42/copied-name.png') RETURNING id`).Scan(&oldID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := d.EnsureTaskArtifactsTable(); err != nil {
			t.Fatal(err)
		}
	}
	var intent sql.NullInt64
	var source sql.NullString
	if err := d.QueryRow(`SELECT intent_id,source_path FROM task_artifacts WHERE id=$1`, oldID).Scan(&intent, &source); err != nil {
		t.Fatal(err)
	}
	if intent.Valid || source.Valid {
		t.Fatal("迁移不能根据旧路径填充未知来源")
	}
	if n, err := d.RetroBindIntentEvidence("17", 42, 91); err != nil || n != 0 {
		t.Fatalf("旧路径不能触发来源补绑：n=%d err=%v", n, err)
	}
	for _, args := range [][2]int64{{0, 91}, {42, 0}, {-1, 91}, {42, -1}} {
		if n, err := d.RetroBindIntentEvidence("17", args[0], args[1]); err != nil || n != 0 {
			t.Fatalf("无效意图或漏洞不应补绑：args=%v n=%d err=%v", args, n, err)
		}
	}
	a := &TaskArtifact{TaskID: "17", Name: "proof.png", Kind: "image", IntentID: 42,
		SourcePath: "tasks/17/i42/proof.png", Storage: "tasks/17/artifacts/copy.png", PreviewState: "pending"}
	if err := d.InsertTaskArtifact(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if n, err := d.RetroBindIntentEvidence("18", 42, 91); err != nil || n != 0 {
		t.Fatalf("其它任务不能补绑：n=%d err=%v", n, err)
	}
	if n, err := d.RetroBindIntentEvidence("17", 42, 91); err != nil || n != 1 {
		t.Fatalf("新来源应精确补绑：n=%d err=%v", n, err)
	}
	got, err := d.GetTaskArtifact(a.ID)
	if err != nil || got.IntentID != 42 || got.SourcePath != a.SourcePath || got.FindingID != 91 {
		t.Fatalf("升级后登记读回不符：%+v err=%v", got, err)
	}
	updated, err := d.UpdateTaskArtifactBinding(a.ID, 92, "补充说明", "source:later")
	if err != nil || updated.FindingID != 91 || updated.IntentID != 42 || updated.SourcePath != a.SourcePath {
		t.Fatalf("后续补绑应保留首次非空归属与来源：%+v err=%v", updated, err)
	}
}
