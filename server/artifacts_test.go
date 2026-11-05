package server

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/chu0119/pojun/db"
)

// TestArtifactKindDocument v0.4.21：Office/PDF 归入可预览类型。
func TestArtifactKindDocument(t *testing.T) {
	cases := map[string]string{
		"a.docx": "document", "a.xlsx": "spreadsheet", "a.pptx": "presentation", "a.pdf": "pdf", "a.csv": "spreadsheet",
		"a.png": "image", "a.json": "data", "a.bin": "other",
	}
	for name, want := range cases {
		if got, _ := artifactKindByExt(name); got != want {
			t.Fatalf("artifactKindByExt(%q)=%q want %q", name, got, want)
		}
	}
}

// TestWriteThumbnail 验证缩略图：长边缩到 480 内、输出是合法 JPEG。
func TestWriteThumbnail(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "big.png")
	img := image.NewRGBA(image.Rect(0, 0, 1600, 900))
	for x := 0; x < 1600; x += 40 {
		for y := 0; y < 900; y++ {
			img.Set(x, y, color.RGBA{200, 30, 30, 255})
		}
	}
	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
	f.Close()

	dst := filepath.Join(dir, "big.png.thumb.jpg")
	if err := writeThumbnail(src, dst, 480); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dst)
	if err != nil || len(raw) == 0 {
		t.Fatalf("thumb missing: %v", err)
	}
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("thumb not jpeg: %v", err)
	}
	if cfg.Width != 480 || cfg.Height != 270 {
		t.Fatalf("thumb size=%dx%d want 480x270", cfg.Width, cfg.Height)
	}
	// 坏图返回错误（调用方退回原图）。
	bad := filepath.Join(dir, "bad.jpg")
	_ = os.WriteFile(bad, []byte("not-an-image"), 0o644)
	if err := writeThumbnail(bad, filepath.Join(dir, "bad.thumb.jpg"), 480); err == nil {
		t.Fatal("invalid image must error")
	}
}

func TestArtifactSourceCanonicalIntent(t *testing.T) {
	s := &Server{m: &Manager{dir: t.TempDir()}}
	root := filepath.Join(s.m.dir, "tasks", "17")
	for _, tc := range []struct {
		path string
		want int64
	}{
		{"i42/nested/proof.png", 42},
		{"i42.png", 0},
		{"proof-i42.png", 0},
		{"other/i42/proof.png", 0},
		{"artifacts/i42/proof.png", 0},
		{"i042/proof.png", 0},
		{"i+42/proof.png", 0},
		{"i0/proof.png", 0},
		{"i-42/proof.png", 0},
		{"i9223372036854775808/proof.png", 0},
	} {
		t.Run(tc.path, func(t *testing.T) {
			path := filepath.Join(root, filepath.FromSlash(tc.path))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("proof"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, intentID, sourcePath, err := s.artifactSource(path, "17")
			if err != nil {
				t.Fatal(err)
			}
			if intentID != tc.want || sourcePath != "tasks/17/"+tc.path {
				t.Fatalf("来源不符：intent=%d source=%q", intentID, sourcePath)
			}
		})
	}
	outside := filepath.Join(s.m.dir, "tasks", "18", "i42", "proof.png")
	if err := os.MkdirAll(filepath.Dir(outside), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("proof"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.artifactSource(outside, "17"); err == nil {
		t.Fatal("其它任务的文件不能作为本任务来源")
	}
}

func TestArtifactSourceResolvesSymlinks(t *testing.T) {
	s := &Server{m: &Manager{dir: t.TempDir()}}
	root := filepath.Join(s.m.dir, "tasks", "17")
	realFile := filepath.Join(root, "i42", "proof.png")
	if err := os.MkdirAll(filepath.Dir(realFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realFile, []byte("proof"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias.png")
	if err := os.Symlink(realFile, link); err != nil {
		t.Skipf("当前环境不支持创建符号链接：%v", err)
	}
	_, intentID, sourcePath, err := s.artifactSource(link, "17")
	if err != nil || intentID != 42 || sourcePath != "tasks/17/i42/proof.png" {
		t.Fatalf("符号链接应使用真实来源：intent=%d source=%q err=%v", intentID, sourcePath, err)
	}
	outside := filepath.Join(t.TempDir(), "outside.png")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(root, "i42", "escape.png")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.artifactSource(escape, "17"); err == nil {
		t.Fatal("符号链接不能把任务外文件伪装成意图来源")
	}
}

func artifactEvidenceTestServer(t *testing.T) (*Server, *db.Task) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil || !db.IsTestDatabase(dsn) {
		t.Skip("附件回归需要隔离测试库")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	for i := 0; i < 2; i++ {
		if err := pg.EnsureTaskArtifactsTable(); err != nil {
			t.Fatal(err)
		}
	}
	task, err := pg.CreateTask("附件意图来源回归", "本地附件", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskKey := strconv.FormatInt(task.ID, 10)
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM task_artifacts WHERE task_id=$1`, taskKey)
		_ = pg.DeleteTask(task.ID)
	})
	return &Server{m: &Manager{dir: t.TempDir(), pg: pg}}, task
}

func TestRecordArtifactIntentProvenance(t *testing.T) {
	s, task := artifactEvidenceTestServer(t)
	pg := s.m.pg
	taskKey := strconv.FormatInt(task.ID, 10)
	root := filepath.Join(s.m.dir, "tasks", taskKey)
	es := pg.Exploration(task.ExplorationID)
	intentIDs := make([]int64, 2)
	for i := range intentIDs {
		id, err := es.AddNode(db.KindIntent, map[string]any{"summary": "附件来源"}, 5, "running", "worker", nil)
		if err != nil {
			t.Fatal(err)
		}
		intentIDs[i] = id
	}
	content := []byte("same evidence in different intents")
	writeSource := func(dir, name string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeSource(root, "legacy.png")
	legacy, err := s.RecordArtifact(task.ID, 0, root, "legacy.png", "legacy-i"+strconv.FormatInt(intentIDs[0], 10)+".png", "auto", "", "旧附件")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`UPDATE task_artifacts SET intent_id=NULL,source_path=NULL WHERE id=$1`, legacy.ID); err != nil {
		t.Fatal(err)
	}
	var artifacts [2]*db.TaskArtifact
	for i, intentID := range intentIDs {
		runDir := filepath.Join(root, "i"+strconv.FormatInt(intentID, 10))
		writeSource(runDir, "proof.png")
		a, err := s.RecordArtifact(task.ID, 0, runDir, "proof.png", "", "auto", "source:first", "首次说明")
		if err != nil {
			t.Fatal(err)
		}
		wantSource := "tasks/" + taskKey + "/i" + strconv.FormatInt(intentID, 10) + "/proof.png"
		if a.IntentID != intentID || a.SourcePath != wantSource || filepath.Dir(a.Storage) != filepath.Join("tasks", taskKey, "artifacts") {
			t.Fatalf("复制后的附件丢失来源：%+v", a)
		}
		stored, err := os.ReadFile(filepath.Join(s.m.dir, a.Storage))
		if err != nil || !bytes.Equal(stored, content) {
			t.Fatalf("复制的附件内容不符：%q err=%v", stored, err)
		}
		writeSource(runDir, "same-copy.png")
		again, err := s.RecordArtifact(task.ID, 0, runDir, "same-copy.png", "renamed.png", "auto", "source:later", "后续说明")
		if err != nil || again.ID != a.ID || again.SourcePath != a.SourcePath || again.Note != a.Note || again.SourceURL != a.SourceURL {
			t.Fatalf("同意图去重应保留首次来源和说明：%+v err=%v", again, err)
		}
		artifacts[i] = a
	}
	if artifacts[0].ID == artifacts[1].ID || artifacts[0].ID == legacy.ID || artifacts[1].ID == legacy.ID {
		t.Fatal("不同意图及未知历史来源的同内容附件必须独立登记")
	}
	var findings [2]*db.RecordedFinding
	for i := range findings {
		f, err := es.RecordFinding(t.Context(), db.RecordFindingInput{TaskID: task.ID, IntentID: intentIDs[i], Name: "附件归属" + strconv.Itoa(i), Severity: "low", Worker: "worker"})
		if err != nil {
			t.Fatal(err)
		}
		findings[i] = f
	}
	if n, err := es.RetroBindIntentEvidence(task.ID, intentIDs[0], findings[0].FindingID); err != nil || n != 1 {
		t.Fatalf("ExplorationStore补绑数量=%d err=%v", n, err)
	}
	if n, err := pg.RetroBindIntentEvidence(taskKey, intentIDs[0], findings[1].FindingID); err != nil || n != 0 {
		t.Fatalf("已归属附件不能被同意图第二个漏洞抢占：n=%d err=%v", n, err)
	}
	if n, err := pg.RetroBindIntentEvidence(taskKey, intentIDs[1], findings[1].FindingID); err != nil || n != 1 {
		t.Fatalf("DB补绑数量=%d err=%v", n, err)
	}
	late, err := pg.UpdateTaskArtifactBinding(artifacts[0].ID, findings[1].FindingID, "后续覆盖", "source:later")
	if err != nil || late.FindingID != findings[0].FindingID || late.IntentID != intentIDs[0] || late.SourcePath != artifacts[0].SourcePath || late.Note != "首次说明" || late.SourceURL != "source:first" {
		t.Fatalf("后到的去重补绑应保留数据库已有归属和来源：%+v err=%v", late, err)
	}
	changed, err := pg.UpdateTaskArtifactFinding(artifacts[1].ID, 0)
	if err != nil || changed.FindingID != 0 || changed.IntentID != intentIDs[1] || changed.SourcePath != artifacts[1].SourcePath {
		t.Fatalf("手动修改归属应保留来源：%+v err=%v", changed, err)
	}
	if n, err := pg.RetroBindIntentEvidence(taskKey, intentIDs[1], findings[1].FindingID); err != nil || n != 1 {
		t.Fatalf("重新补绑数量=%d err=%v", n, err)
	}
	for i, a := range artifacts {
		got, err := pg.GetTaskArtifact(a.ID)
		if err != nil || got.FindingID != findings[i].FindingID || got.IntentID != intentIDs[i] || got.SourcePath != a.SourcePath {
			t.Fatalf("读取附件来源不符：%+v err=%v", got, err)
		}
	}
	old, err := pg.GetTaskArtifact(legacy.ID)
	if err != nil || old.FindingID != 0 || old.IntentID != 0 || old.SourcePath != "" {
		t.Fatalf("历史未知来源不能自动推断或补绑：%+v err=%v", old, err)
	}
	list, err := pg.ListTaskArtifacts(taskKey)
	if err != nil || len(list) != 3 || list[1].IntentID != intentIDs[0] || list[2].SourcePath != artifacts[1].SourcePath {
		t.Fatalf("附件列表丢失来源：%+v err=%v", list, err)
	}
	if err := pg.SetTaskArtifactPreview(artifacts[1].ID, "pending", 0, ""); err != nil {
		t.Fatal(err)
	}
	pending, err := pg.ListPendingPreviewArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range pending {
		if a.ID == artifacts[1].ID {
			if a.IntentID != intentIDs[1] || a.SourcePath != artifacts[1].SourcePath {
				t.Fatalf("待预览列表丢失来源：%+v", a)
			}
			return
		}
	}
	t.Fatal("待预览列表缺少附件")
}

func TestScanTaskArtifactsKeepsIntentProvenance(t *testing.T) {
	s, task := artifactEvidenceTestServer(t)
	taskKey := strconv.FormatInt(task.ID, 10)
	root := filepath.Join(s.m.dir, "tasks", taskKey)
	for _, dir := range []string{"i41", "i42"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "proof.png"), []byte("same scan content"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	added, _, truncated, err := s.scanTaskArtifactDir(taskKey)
	if err != nil || added != 2 || truncated != 0 {
		t.Fatalf("跨意图扫描被错误去重：added=%d truncated=%d err=%v", added, truncated, err)
	}
	added, skipped, _, err := s.scanTaskArtifactDir(taskKey)
	if err != nil || added != 0 || skipped != 2 {
		t.Fatalf("重复扫描不应新增：added=%d skipped=%d err=%v", added, skipped, err)
	}
	list, err := s.m.pg.ListTaskArtifacts(taskKey)
	if err != nil || len(list) != 2 || list[0].IntentID != 41 || list[1].IntentID != 42 || !strings.HasSuffix(list[1].SourcePath, "/i42/proof.png") {
		t.Fatalf("扫描来源不符：%+v err=%v", list, err)
	}
}
