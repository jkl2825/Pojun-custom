package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/docpreview"
)

// 证据附件限额（v0.5.0）。默认"样本策略"：worker 只保存证明性样本，全量
// 数据留在任务工作目录、不随报告分发。限额防的是误存全量 PII/超大文件。
const (
	maxArtifactFileBytes = 20 << 20  // 单文件 20MB
	maxTaskArtifactCount = 300       // 每任务最多 300 个（实战任务证据量常超 100）
	maxTaskArtifactBytes = 500 << 20 // 每任务总量 500MB
)

// artifactKindByExt 按扩展名推断附件类型（报告里分区展示用）。
func artifactKindByExt(name string) (kind, mime string) {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png":
		return "image", "image/png"
	case ".jpg", ".jpeg":
		return "image", "image/jpeg"
	case ".gif":
		return "image", "image/gif"
	case ".webp":
		return "image", "image/webp"
	case ".json":
		return "data", "application/json"
	case ".csv":
		return "spreadsheet", "text/csv"
	case ".txt", ".log":
		return "log", "text/plain"
	case ".html", ".htm":
		return "html", "text/html"
	case ".xml":
		return "data", "application/xml"
	case ".pdf":
		return "pdf", "application/pdf"
	case ".doc":
		return "document", "application/msword"
	case ".docx":
		return "document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case ".odt":
		return "document", "application/vnd.oasis.opendocument.text"
	case ".rtf":
		return "document", "application/rtf"
	case ".xls":
		return "spreadsheet", "application/vnd.ms-excel"
	case ".xlsx":
		return "spreadsheet", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case ".ods":
		return "spreadsheet", "application/vnd.oasis.opendocument.spreadsheet"
	case ".ppt":
		return "presentation", "application/vnd.ms-powerpoint"
	case ".pptx":
		return "presentation", "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	case ".odp":
		return "presentation", "application/vnd.oasis.opendocument.presentation"
	}
	return "other", "application/octet-stream"
}

// sanitizeArtifactName 去掉路径分隔符与控制字符，限制长度。
func sanitizeArtifactName(name string) string {
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		name = "artifact"
	}
	if len([]rune(name)) > 120 {
		name = string([]rune(name)[:120])
	}
	return name
}

// taskArtifactsDir 任务的附件目录（data/tasks/<taskID>/artifacts）。
func (s *Server) taskArtifactsDir(taskID string) string {
	return filepath.Join(s.m.dir, "tasks", taskID, "artifacts")
}

// artifactSource 从真实源路径保留来源，只认任务根第一层规范的 i<ID> 目录。
func (s *Server) artifactSource(abs, taskKey string) (resolved string, intentID int64, sourcePath string, err error) {
	taskRoot, err := filepath.EvalSymlinks(filepath.Join(s.m.dir, "tasks", taskKey))
	if err != nil {
		return "", 0, "", fmt.Errorf("解析任务目录失败：%w", err)
	}
	resolved, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return "", 0, "", fmt.Errorf("解析源文件失败：%w", err)
	}
	rel, err := filepath.Rel(taskRoot, resolved)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return "", 0, "", fmt.Errorf("path 超出任务目录范围")
	}
	sourcePath = filepath.ToSlash(filepath.Join("tasks", taskKey, rel))
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) > 1 && strings.HasPrefix(parts[0], "i") {
		id, parseErr := strconv.ParseInt(strings.TrimPrefix(parts[0], "i"), 10, 64)
		if parseErr == nil && id > 0 && parts[0] == "i"+strconv.FormatInt(id, 10) {
			intentID = id
		}
	}
	return resolved, intentID, sourcePath, nil
}

// RecordArtifact 把任务工作目录里的一个文件登记为证据附件：校验路径边界与
// 限额 → 计算 sha256（同任务同意图同内容去重）→ 复制到任务附件目录 → 落库。
// relPath 相对 runDir（worker 的工作目录）；必须落在 tasks/<taskID>/ 之内。
func (s *Server) RecordArtifact(taskID, findingID int64, runDir, relPath, name, kind, sourceURL, note string) (*db.TaskArtifact, error) {
	pg := s.m.PG()
	if pg == nil {
		return nil, fmt.Errorf("PG 不可用")
	}
	taskKey := strconv.FormatInt(taskID, 10)
	if strings.TrimSpace(relPath) == "" {
		return nil, fmt.Errorf("path 不能为空")
	}
	clean := filepath.Clean(relPath)
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return nil, fmt.Errorf("path 必须是工作目录内的相对路径")
	}
	abs := filepath.Join(runDir, clean)
	// 路径边界：必须落在 tasks/<taskID>/ 之下（防穿越到其他任务/data 其他区域）。
	// 两边都做 symlink 解析后再比较，避免用链接绕出任务目录。
	taskRoot := filepath.Join(s.m.dir, "tasks", taskKey)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	if resolved, err := filepath.EvalSymlinks(taskRoot); err == nil {
		taskRoot = resolved
	}
	relToTask, err := filepath.Rel(taskRoot, abs)
	if err != nil || strings.HasPrefix(relToTask, "..") {
		return nil, fmt.Errorf("path 超出任务目录范围")
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("文件不存在或不可读：%w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("只支持普通文件")
	}
	if info.Size() <= 0 {
		return nil, fmt.Errorf("文件为空")
	}
	if info.Size() > maxArtifactFileBytes {
		return nil, fmt.Errorf("文件超过单附件上限（20MB）：%d 字节", info.Size())
	}
	if count, total, err := pg.CountTaskArtifacts(taskKey); err == nil {
		if count >= maxTaskArtifactCount {
			return nil, fmt.Errorf("本任务附件已达上限（%d 个），请合并或删除后再存", maxTaskArtifactCount)
		}
		if total+info.Size() > maxTaskArtifactBytes {
			return nil, fmt.Errorf("本任务附件总量将超过上限（500MB）")
		}
	}

	return s.recordArtifactAbs(abs, taskKey, findingID, name, kind, sourceURL, note, info.Size())
}

// listTaskArtifacts 任务附件列表（不含存储路径）。
func (s *Server) listTaskArtifacts(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	pg := s.m.PG()
	if pg == nil {
		writeErr(w, 500, "PG 不可用")
		return
	}
	list, err := pg.ListTaskArtifacts(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if list == nil {
		list = []db.TaskArtifact{}
	}
	writeJSON(w, 200, map[string]any{"artifacts": list})
}

// patchTaskArtifact 修改附件归属（v0.4.20）。body {finding_id}：
// 0 = 改回任务级；非 0 必须是本任务下的漏洞。
func (s *Server) patchTaskArtifact(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	aid, err := strconv.ParseInt(r.PathValue("aid"), 10, 64)
	if err != nil || aid <= 0 {
		writeErr(w, 400, "bad artifact id")
		return
	}
	pg := s.m.PG()
	if pg == nil {
		writeErr(w, 500, "PG 不可用")
		return
	}
	a, err := pg.GetTaskArtifact(aid)
	if err != nil || a == nil || a.TaskID != taskID {
		writeErr(w, 404, "artifact not found")
		return
	}
	var req struct {
		FindingID int64 `json:"finding_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if req.FindingID < 0 {
		writeErr(w, 400, "finding_id 不能为负")
		return
	}
	if req.FindingID > 0 {
		f, err := pg.GetFinding(req.FindingID)
		if err != nil || f == nil || f.TaskID == nil || strconv.FormatInt(*f.TaskID, 10) != taskID {
			writeErr(w, 400, "finding 不属于该任务")
			return
		}
	}
	updated, err := pg.UpdateTaskArtifactFinding(aid, req.FindingID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"artifact": updated})
}

// serveTaskArtifact 提供单个附件：
//   - 图片默认 inline（前端 <img> 可直接预览），?download=1 强制下载；
//   - ?thumb=1 返回长边 480 的 JPEG 缩略图（磁盘缓存 .thumb.jpg）——列表页
//     用缩略图，避免一次加载几十张 3MB 原图导致部分加载失败；
//   - 非图片一律 attachment 下载。
func (s *Server) serveTaskArtifact(w http.ResponseWriter, r *http.Request) {
	pg := s.m.PG()
	if pg == nil {
		writeErr(w, 500, "PG 不可用")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("aid"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid artifact id")
		return
	}
	a, err := pg.GetTaskArtifact(id)
	if err != nil || a == nil || a.TaskID != r.PathValue("id") {
		writeErr(w, 404, "artifact not found")
		return
	}
	abs := filepath.Join(s.m.dir, a.Storage)
	if _, err := os.Stat(abs); err != nil {
		writeErr(w, 404, "attachment file missing")
		return
	}
	// MIME 可能为空（历史登记/扫描补登记），此时按 kind 判断——否则图片会被
	// 当成普通文件走 attachment，浏览器直接报错（v0.4.16 修复）。
	isImage := a.Kind == "image" || strings.HasPrefix(strings.ToLower(a.Mime), "image/")
	q := r.URL.Query()
	switch {
	case isImage && q.Get("thumb") != "":
		thumb := abs + ".thumb.jpg"
		if _, err := os.Stat(thumb); err != nil {
			if err := writeThumbnail(abs, thumb, 480); err != nil {
				// 缩略图生成失败退回原图，至少能显示。
				w.Header().Set("Content-Type", a.Mime)
				w.Header().Set("Cache-Control", "private, max-age=300")
				http.ServeFile(w, r, abs)
				return
			}
		}
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Cache-Control", "private, max-age=3600")
		http.ServeFile(w, r, thumb)
	case isImage && q.Get("download") == "":
		w.Header().Set("Content-Type", a.Mime)
		w.Header().Set("Content-Disposition", "inline")
		w.Header().Set("Cache-Control", "private, max-age=600")
		http.ServeFile(w, r, abs)
	default:
		w.Header().Set("Content-Type", a.Mime)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, sanitizeArtifactName(a.Name)))
		http.ServeFile(w, r, abs)
	}
}

// writeThumbnail 生成 JPEG 缩略图（长边 maxEdge），写磁盘缓存。
// 优先调用 ImageMagick（4K 大图毫秒级；Go 逐像素缩放会慢到请求超时——
// 实测 3072x4096 图单张 1–2s，前端并发加载 6–12 张时大量失败，v0.4.16 修复）。
// ImageMagick 不可用或失败时回退到纯 Go 实现。
func writeThumbnail(src, dst string, maxEdge int) error {
	if bin := findImageMagick(); bin != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, src,
			"-auto-orient",
			"-resize", fmt.Sprintf("%dx%d>", maxEdge, maxEdge),
			"-quality", "82",
			dst)
		if err := cmd.Run(); err == nil {
			if st, err := os.Stat(dst); err == nil && st.Size() > 0 {
				return nil
			}
		}
		_ = os.Remove(dst)
	}
	return writeThumbnailGo(src, dst, maxEdge)
}

// findImageMagick 返回可用的 ImageMagick 命令路径（空 = 不可用）。
// 必须校验 -version 输出：Windows 自带的 convert.exe 是磁盘转换工具，
// 名字相同但绝不是 ImageMagick（误用有破坏磁盘的风险）。
func findImageMagick() string {
	for _, name := range []string{"magick", "convert"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		out, err := exec.Command(p, "-version").Output()
		if err != nil || !strings.Contains(string(out), "ImageMagick") {
			continue
		}
		return p
	}
	return ""
}

// writeThumbnailGo 是纯 Go 回退实现（双线性缩放）。
func writeThumbnailGo(src, dst string, maxEdge int) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	img, _, err := image.Decode(f)
	f.Close()
	if err != nil {
		return err
	}
	b := img.Bounds()
	sw, sh := b.Dx(), b.Dy()
	if sw <= 0 || sh <= 0 {
		return fmt.Errorf("empty image")
	}
	scale := math.Min(float64(maxEdge)/float64(sw), float64(maxEdge)/float64(sh))
	if scale >= 1 {
		scale = 1
	}
	tw, th := int(float64(sw)*scale), int(float64(sh)*scale)
	if tw < 1 {
		tw = 1
	}
	if th < 1 {
		th = 1
	}
	out := image.NewRGBA(image.Rect(0, 0, tw, th))
	for y := 0; y < th; y++ {
		sy := (float64(y)+0.5)*float64(sh)/float64(th) - 0.5
		y0 := int(math.Floor(sy))
		fy := sy - float64(y0)
		if y0 < 0 {
			y0 = 0
			fy = 0
		}
		y1 := y0 + 1
		if y1 >= sh {
			y1 = sh - 1
		}
		for x := 0; x < tw; x++ {
			sx := (float64(x)+0.5)*float64(sw)/float64(tw) - 0.5
			x0 := int(math.Floor(sx))
			fx := sx - float64(x0)
			if x0 < 0 {
				x0 = 0
				fx = 0
			}
			x1 := x0 + 1
			if x1 >= sw {
				x1 = sw - 1
			}
			r0, g0, b0, _ := img.At(b.Min.X+x0, b.Min.Y+y0).RGBA()
			r1, g1, b1, _ := img.At(b.Min.X+x1, b.Min.Y+y0).RGBA()
			r2, g2, b2, _ := img.At(b.Min.X+x0, b.Min.Y+y1).RGBA()
			r3, g3, b3, _ := img.At(b.Min.X+x1, b.Min.Y+y1).RGBA()
			topR := float64(r0)*(1-fx) + float64(r1)*fx
			topG := float64(g0)*(1-fx) + float64(g1)*fx
			topB := float64(b0)*(1-fx) + float64(b1)*fx
			botR := float64(r2)*(1-fx) + float64(r3)*fx
			botG := float64(g2)*(1-fx) + float64(g3)*fx
			botB := float64(b2)*(1-fx) + float64(b3)*fx
			out.SetRGBA(x, y, color.RGBA{
				R: uint8((topR*(1-fy) + botR*fy) / 257),
				G: uint8((topG*(1-fy) + botG*fy) / 257),
				B: uint8((topB*(1-fy) + botB*fy) / 257),
				A: 255,
			})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, out, &jpeg.Options{Quality: 80}); err != nil {
		return err
	}
	return os.WriteFile(dst, buf.Bytes(), 0o644)
}

// exportTaskArtifacts 把任务全部附件打成 zip：artifacts/<name> + manifest.json。
// manifest 记录来源 URL、采集时间、sha256 与说明——SRC 取证提交需要这些。
func (s *Server) exportTaskArtifacts(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	pg := s.m.PG()
	if pg == nil {
		writeErr(w, 500, "PG 不可用")
		return
	}
	list, err := pg.ListTaskArtifacts(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if len(list) == 0 {
		writeErr(w, 404, "该任务没有证据附件")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="task-%s-artifacts.zip"`, taskID))
	zw := zip.NewWriter(w)
	defer zw.Close()
	manifest := make([]map[string]any, 0, len(list))
	seen := map[string]int{}
	for _, a := range list {
		abs := filepath.Join(s.m.dir, a.Storage)
		data, err := os.ReadFile(abs)
		if err != nil {
			continue // 文件丢失的登记跳过，manifest 里如实缺席
		}
		name := a.Name
		if n := seen[name]; n > 0 {
			ext := filepath.Ext(name)
			name = strings.TrimSuffix(name, ext) + fmt.Sprintf("-%d", n+1) + ext
		}
		seen[a.Name]++
		fw, err := zw.Create("artifacts/" + name)
		if err != nil {
			continue
		}
		_, _ = fw.Write(data)
		manifest = append(manifest, map[string]any{
			"id": a.ID, "finding_id": a.FindingID, "file": "artifacts/" + name, "name": a.Name, "kind": a.Kind,
			"mime": a.Mime, "size_bytes": a.SizeBytes, "sha256": a.SHA256,
			"source_url": a.SourceURL, "note": a.Note,
			"created_at": a.CreatedAt.Format(time.RFC3339),
		})
	}
	mf, _ := json.MarshalIndent(map[string]any{
		"task_id":     taskID,
		"exported_at": time.Now().UTC().Format(time.RFC3339),
		"policy":      "证据政策（v0.4.34）：第一方递交官方，附件一律明文保真、不打码不脱敏；大数据集可整份保存（上限 300 件/500MB），超限优先保留关键样本与清单。",
		"artifacts":   manifest,
	}, "", "  ")
	if fw, err := zw.Create("manifest.json"); err == nil {
		_, _ = fw.Write(mf)
	}
}

// artifactImageData 读一张图片附件（报告 docx 嵌图用）。
func (s *Server) artifactImageData(a *db.TaskArtifact) ([]byte, bool) {
	if a == nil || a.Kind != "image" {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(s.m.dir, a.Storage))
	if err != nil {
		return nil, false
	}
	return data, true
}

// artifactListJSON 供报告生成时把附件清单写进"附件"章节。
func artifactListJSON(list []db.TaskArtifact) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, a := range list {
		out = append(out, map[string]any{
			"id": a.ID, "finding_id": a.FindingID, "name": a.Name, "kind": a.Kind, "size_bytes": a.SizeBytes,
			"note": a.Note, "source_url": a.SourceURL,
		})
	}
	return out
}

// recordArtifactAbs 以绝对路径登记附件，并从校验后的真实路径保留来源。
func (s *Server) recordArtifactAbs(abs, taskKey string, findingID int64, name, kind, sourceURL, note string, size int64) (*db.TaskArtifact, error) {
	pg := s.m.PG()
	if pg == nil {
		return nil, fmt.Errorf("PG 不可用")
	}
	abs, intentID, sourcePath, err := s.artifactSource(abs, taskKey)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败：%w", err)
	}
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])

	// 同意图同内容复用首次登记；跨意图或历史来源未知的附件不合并，保留独立来源。
	// v0.4.20：截图常发生在 report_finding 之前（拿不到 finding_id），事后补登记
	// 同一文件时不能因为去重把归属丢掉——旧记录还是任务级就补绑；已归属其他
	// 漏洞的不抢占（避免把 A 漏洞的证据挪给 B）。
	if list, err := pg.ListTaskArtifacts(taskKey); err == nil {
		for i := range list {
			if list[i].SHA256 == sha && list[i].SizeBytes == size && list[i].IntentID == intentID {
				existing := &list[i]
				if findingID > 0 && existing.FindingID == 0 {
					if updated, uerr := pg.UpdateTaskArtifactBinding(existing.ID, findingID, note, sourceURL); uerr == nil {
						s.enqueueArtifactPreview(updated, false)
						return updated, nil
					}
				}
				s.enqueueArtifactPreview(existing, false)
				return existing, nil
			}
		}
	}

	if strings.TrimSpace(name) == "" {
		name = filepath.Base(abs)
	}
	name = sanitizeArtifactName(name)
	autoKind, autoMime := artifactKindByExt(name)
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" || kind == "auto" {
		kind = autoKind
	}
	dir := s.taskArtifactsDir(taskKey)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建附件目录失败：%w", err)
	}
	storage := filepath.Join("tasks", taskKey, "artifacts",
		fmt.Sprintf("%d-%s", time.Now().UnixNano(), name))
	dst := filepath.Join(s.m.dir, storage)
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return nil, fmt.Errorf("写入附件失败：%w", err)
	}
	a := &db.TaskArtifact{
		TaskID: taskKey, FindingID: findingID, IntentID: intentID, SourcePath: sourcePath,
		Name: name, Kind: kind, Mime: autoMime,
		SizeBytes: int64(len(data)), SHA256: sha, SourceURL: sourceURL,
		Note: note, Storage: storage,
	}
	if docpreview.Supports(name) {
		a.PreviewState = "pending" // 前端立即显示“生成中”，worker 接上后覆盖
	}
	if err := pg.InsertTaskArtifact(context.Background(), a); err != nil {
		_ = os.Remove(dst)
		return nil, fmt.Errorf("登记附件失败：%w", err)
	}
	// Office/PDF 附件异步生成取样预览（v0.4.21），不阻塞 save_evidence。
	s.enqueueArtifactPreview(a, false)
	return a, nil
}

// scanTaskArtifactDir 扫描任务工作目录里的历史图片并补登记（v0.4.10）。
// 场景：老任务在附件功能上线前就把照片抓到了工作目录，需要让它们立刻出现在
// 前端与报告里。限量 60 张、跳过已有（sha256 去重）、跳过 artifacts 自身。
func (s *Server) scanTaskArtifactDir(taskID string) (added, skipped, truncated int, err error) {
	pg := s.m.PG()
	if pg == nil {
		return 0, 0, 0, fmt.Errorf("PG 不可用")
	}
	root := filepath.Join(s.m.dir, "tasks", taskID)
	artifactsDir := s.taskArtifactsDir(taskID)
	type sourceHash struct {
		intentID int64
		sha256   string
	}
	existing := map[sourceHash]bool{}
	if list, e := pg.ListTaskArtifacts(taskID); e == nil {
		for _, a := range list {
			existing[sourceHash{a.IntentID, a.SHA256}] = true
		}
	}
	const limit = 60
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if path == artifactsDir {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".png", ".jpg", ".jpeg", ".gif", ".webp",
			".pdf", ".doc", ".docx", ".odt", ".rtf",
			".xls", ".xlsx", ".ods", ".csv",
			".ppt", ".pptx", ".odp":
		default:
			return nil
		}
		if added >= limit {
			truncated++
			return nil
		}
		info, e := d.Info()
		if e != nil || info.Size() <= 0 || info.Size() > maxArtifactFileBytes {
			return nil
		}
		// sha256 预检（避免读大文件后才发现重复）
		f, e := os.Open(path)
		if e != nil {
			return nil
		}
		h := sha256.New()
		if _, e = io.Copy(h, f); e != nil {
			f.Close()
			return nil
		}
		f.Close()
		sum := hex.EncodeToString(h.Sum(nil))
		_, intentID, _, e := s.artifactSource(path, taskID)
		if e != nil {
			return nil
		}
		key := sourceHash{intentID, sum}
		if existing[key] {
			skipped++
			return nil
		}
		// 文件名 URL 解码（历史照片常见 %E7%AD%BE 形式），让图注可读。
		base := filepath.Base(path)
		if decoded, e := url.QueryUnescape(base); e == nil && decoded != "" {
			base = decoded
		}
		rel, _ := filepath.Rel(root, path)
		_, e = s.recordArtifactAbs(path, taskID, 0, base, "auto", "", "工作目录历史文件："+rel, info.Size())
		if e != nil {
			return nil
		}
		existing[key] = true
		added++
		return nil
	})
	return added, skipped, truncated, walkErr
}

// scanTaskArtifacts 扫描任务工作目录里的历史图片并补登记（v0.4.10）。
// POST /api/tasks/{id}/artifacts/scan
func (s *Server) scanTaskArtifacts(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	added, skipped, truncated, err := s.scanTaskArtifactDir(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"added": added, "skipped": skipped, "truncated": truncated,
		"note": "已把任务工作目录里的图片与文档（Word/Excel/PPT/PDF）补登记为证据附件（单次最多 60 个）；建议在任务结束后执行，避免把临时文件也收进来。",
	})
}
