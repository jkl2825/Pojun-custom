package db

import (
	"context"
	"time"
)

// TaskArtifact 是任务级证据附件（v0.5.0）：worker 扒到的数据样本、截图、
// 日志等，落盘到任务目录并登记，随报告导出成证据包。默认只存"证明性样本"
// （敏感数据前 N 条），全量数据留在任务工作目录，不随报告分发（合规）。
type TaskArtifact struct {
	ID     int64  `json:"id"`
	TaskID string `json:"task_id"`
	// FindingID 可选：这张图/这个样本证明哪个漏洞（worker 报完漏洞后登记时带上）。
	// 0 = 任务级材料（如目标首页截图），不进单个漏洞的详情页。
	FindingID int64 `json:"finding_id,omitempty"`
	// 来源只在首次登记时写入；旧附件无法确认来源时保持零值。
	IntentID   int64  `json:"intent_id,omitempty"`
	SourcePath string `json:"source_path,omitempty"` // data 目录下原文件的相对路径
	Name       string `json:"name"`                  // 展示名（含扩展名）
	Kind       string `json:"kind"`                  // image|data|log|html|other
	Mime       string `json:"mime,omitempty"`
	SizeBytes  int64  `json:"size_bytes"`
	SHA256     string `json:"sha256,omitempty"`
	SourceURL  string `json:"source_url,omitempty"`
	Note       string `json:"note,omitempty"` // 报告图注/附件说明
	// 文档预览（v0.4.21）：Office/PDF 取样渲染成图片，sidecar 落盘不进附件限额。
	// state: ""（非文档/未处理）| pending | ready | failed | skipped
	PreviewState string    `json:"preview_state,omitempty"`
	PreviewPages int       `json:"preview_pages,omitempty"`
	PreviewError string    `json:"preview_error,omitempty"`
	Storage      string    `json:"-"` // data 目录下的相对路径（不对外）
	CreatedAt    time.Time `json:"created_at"`
}

// EnsureTaskArtifactsTable 幂等建表（服务启动时调用）。
func (d *DB) EnsureTaskArtifactsTable() error {
	_, err := d.Exec(`
CREATE TABLE IF NOT EXISTS task_artifacts (
    id          BIGSERIAL PRIMARY KEY,
    task_id     TEXT NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'other',
    mime        TEXT,
    size_bytes  BIGINT NOT NULL DEFAULT 0,
    sha256      TEXT,
    source_url  TEXT,
    note        TEXT,
    storage_path TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_task_artifacts_task ON task_artifacts(task_id);
ALTER TABLE task_artifacts ADD COLUMN IF NOT EXISTS finding_id BIGINT;
CREATE INDEX IF NOT EXISTS idx_task_artifacts_finding ON task_artifacts(finding_id);
ALTER TABLE task_artifacts ADD COLUMN IF NOT EXISTS preview_state TEXT;
ALTER TABLE task_artifacts ADD COLUMN IF NOT EXISTS preview_pages INT NOT NULL DEFAULT 0;
ALTER TABLE task_artifacts ADD COLUMN IF NOT EXISTS preview_error TEXT;
ALTER TABLE task_artifacts ADD COLUMN IF NOT EXISTS previewed_at TIMESTAMPTZ;
ALTER TABLE task_artifacts ADD COLUMN IF NOT EXISTS intent_id BIGINT;
ALTER TABLE task_artifacts ADD COLUMN IF NOT EXISTS source_path TEXT;
CREATE INDEX IF NOT EXISTS idx_task_artifacts_unbound_intent ON task_artifacts(task_id,intent_id) WHERE finding_id IS NULL;
`)
	return err
}

// InsertTaskArtifact 登记一个附件（文件已由 host 落盘）。
func (d *DB) InsertTaskArtifact(ctx context.Context, a *TaskArtifact) error {
	return d.QueryRowContext(ctx, `
INSERT INTO task_artifacts(task_id,finding_id,name,kind,mime,size_bytes,sha256,source_url,note,storage_path,preview_state,intent_id,source_path)
VALUES ($1,NULLIF($2,0),$3,$4,NULLIF($5,''),$6,NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),$10,NULLIF($11,''),NULLIF($12,0),NULLIF($13,''))
RETURNING id, created_at`,
		a.TaskID, a.FindingID, a.Name, a.Kind, a.Mime, a.SizeBytes, a.SHA256, a.SourceURL, a.Note, a.Storage, a.PreviewState, a.IntentID, a.SourcePath).
		Scan(&a.ID, &a.CreatedAt)
}

// ListTaskArtifacts 按时间列出任务附件。
func (d *DB) ListTaskArtifacts(taskID string) ([]TaskArtifact, error) {
	rows, err := d.Query(`
SELECT id,task_id,COALESCE(finding_id,0),name,kind,COALESCE(mime,''),size_bytes,COALESCE(sha256,''),
       COALESCE(source_url,''),COALESCE(note,''),COALESCE(preview_state,''),COALESCE(preview_pages,0),COALESCE(preview_error,''),storage_path,created_at,COALESCE(intent_id,0),COALESCE(source_path,'')
FROM task_artifacts WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskArtifact
	for rows.Next() {
		var a TaskArtifact
		if err := rows.Scan(&a.ID, &a.TaskID, &a.FindingID, &a.Name, &a.Kind, &a.Mime, &a.SizeBytes,
			&a.SHA256, &a.SourceURL, &a.Note, &a.PreviewState, &a.PreviewPages, &a.PreviewError, &a.Storage, &a.CreatedAt, &a.IntentID, &a.SourcePath); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetTaskArtifact 取单个附件元数据（导出/报告嵌图用）。
func (d *DB) GetTaskArtifact(id int64) (*TaskArtifact, error) {
	var a TaskArtifact
	err := d.QueryRow(`
SELECT id,task_id,COALESCE(finding_id,0),name,kind,COALESCE(mime,''),size_bytes,COALESCE(sha256,''),
       COALESCE(source_url,''),COALESCE(note,''),COALESCE(preview_state,''),COALESCE(preview_pages,0),COALESCE(preview_error,''),storage_path,created_at,COALESCE(intent_id,0),COALESCE(source_path,'')
FROM task_artifacts WHERE id=$1`, id).
		Scan(&a.ID, &a.TaskID, &a.FindingID, &a.Name, &a.Kind, &a.Mime, &a.SizeBytes,
			&a.SHA256, &a.SourceURL, &a.Note, &a.PreviewState, &a.PreviewPages, &a.PreviewError, &a.Storage, &a.CreatedAt, &a.IntentID, &a.SourcePath)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// CountTaskArtifacts 返回任务附件数量与总字节数（限额检查用）。
func (d *DB) CountTaskArtifacts(taskID string) (count int, bytes int64, err error) {
	err = d.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size_bytes),0) FROM task_artifacts WHERE task_id=$1`, taskID).
		Scan(&count, &bytes)
	return
}

// UpdateTaskArtifactFinding 修改附件归属（v0.4.20）：findingID=0 表示任务级。
// 返回更新后的完整元数据，供 PATCH 接口与去重补绑复用。
func (d *DB) UpdateTaskArtifactFinding(id int64, findingID int64) (*TaskArtifact, error) {
	var a TaskArtifact
	err := d.QueryRow(`
UPDATE task_artifacts SET finding_id=NULLIF($2,0) WHERE id=$1
RETURNING id,task_id,COALESCE(finding_id,0),name,kind,COALESCE(mime,''),size_bytes,COALESCE(sha256,''),
          COALESCE(source_url,''),COALESCE(note,''),COALESCE(preview_state,''),COALESCE(preview_pages,0),COALESCE(preview_error,''),storage_path,created_at,COALESCE(intent_id,0),COALESCE(source_path,'')`, id, findingID).
		Scan(&a.ID, &a.TaskID, &a.FindingID, &a.Name, &a.Kind, &a.Mime, &a.SizeBytes,
			&a.SHA256, &a.SourceURL, &a.Note, &a.PreviewState, &a.PreviewPages, &a.PreviewError, &a.Storage, &a.CreatedAt, &a.IntentID, &a.SourcePath)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// UpdateTaskArtifactBinding 补绑归属并补空字段（v0.4.20 去重路径用）：
// 只补空归属与 note/source_url，避免并发补绑覆盖首次归属或说明；来源不变。
func (d *DB) UpdateTaskArtifactBinding(id int64, findingID int64, note, sourceURL string) (*TaskArtifact, error) {
	var a TaskArtifact
	err := d.QueryRow(`
UPDATE task_artifacts SET finding_id=COALESCE(finding_id,NULLIF($2,0)),
       note=COALESCE(NULLIF(note,''),NULLIF($3,'')),
       source_url=COALESCE(NULLIF(source_url,''),NULLIF($4,''))
WHERE id=$1
RETURNING id,task_id,COALESCE(finding_id,0),name,kind,COALESCE(mime,''),size_bytes,COALESCE(sha256,''),
          COALESCE(source_url,''),COALESCE(note,''),COALESCE(preview_state,''),COALESCE(preview_pages,0),COALESCE(preview_error,''),storage_path,created_at,COALESCE(intent_id,0),COALESCE(source_path,'')`, id, findingID, note, sourceURL).
		Scan(&a.ID, &a.TaskID, &a.FindingID, &a.Name, &a.Kind, &a.Mime, &a.SizeBytes,
			&a.SHA256, &a.SourceURL, &a.Note, &a.PreviewState, &a.PreviewPages, &a.PreviewError, &a.Storage, &a.CreatedAt, &a.IntentID, &a.SourcePath)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// ListPendingPreviewArtifacts 返回所有 pending 的文档预览（服务启动恢复队列用）。
func (d *DB) ListPendingPreviewArtifacts() ([]TaskArtifact, error) {
	rows, err := d.Query(`
SELECT id,task_id,COALESCE(finding_id,0),name,kind,COALESCE(mime,''),size_bytes,COALESCE(sha256,''),
       COALESCE(source_url,''),COALESCE(note,''),COALESCE(preview_state,''),COALESCE(preview_pages,0),COALESCE(preview_error,''),storage_path,created_at,COALESCE(intent_id,0),COALESCE(source_path,'')
FROM task_artifacts WHERE preview_state='pending' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskArtifact
	for rows.Next() {
		var a TaskArtifact
		if err := rows.Scan(&a.ID, &a.TaskID, &a.FindingID, &a.Name, &a.Kind, &a.Mime, &a.SizeBytes,
			&a.SHA256, &a.SourceURL, &a.Note, &a.PreviewState, &a.PreviewPages, &a.PreviewError, &a.Storage, &a.CreatedAt, &a.IntentID, &a.SourcePath); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetTaskArtifactPreview 更新文档预览状态（v0.4.21）。
func (d *DB) SetTaskArtifactPreview(id int64, state string, pages int, errMsg string) error {
	_, err := d.Exec(`
UPDATE task_artifacts
SET preview_state=$2, preview_pages=$3, preview_error=NULLIF($4,''), previewed_at=now()
WHERE id=$1`, id, state, pages, errMsg)
	return err
}

// ListArtifactTaskIDs 返回有证据附件的任务 ID（离线补预览用）。
func (d *DB) ListArtifactTaskIDs() ([]string, error) {
	rows, err := d.Query(`SELECT DISTINCT task_id FROM task_artifacts ORDER BY task_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RetroBindIntentEvidence 按首次登记时确认的意图来源补绑未归属附件。
// 保留同意图的 first-unbound 行为；旧附件来源未知时不根据存储路径或文件名猜测。
func (d *DB) RetroBindIntentEvidence(taskID string, intentID int64, findingID int64) (int, error) {
	if intentID <= 0 || findingID <= 0 {
		return 0, nil
	}
	res, err := d.Exec(`
UPDATE task_artifacts
SET finding_id=$3
WHERE task_id=$1 AND finding_id IS NULL AND intent_id=$2`,
		taskID, intentID, findingID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
