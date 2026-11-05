package db

import (
	"fmt"
	"sort"
	"strings"
)

// KnowledgeEntry 是一条可跨任务复用的判别式。
//
// 沉淀的不是「某次结果」，而是「什么条件下会成立 + 什么条件下不成立」——
// 后者我们最容易丢，却恰恰是最值钱的部分：上一轮任务里成片的否证
// （「40301 是通用凭据错误，不是口令错误」「old_pubkeys 是已轮换公钥，不能当
// HMAC 密钥」）任务一结束就沉底了。
type KnowledgeEntry struct {
	ID        int64  `json:"id"`
	ScopeKey  string `json:"-"`
	VulnClass string `json:"vuln_class"`
	Method    string `json:"method"`
	Boundary  string `json:"boundary,omitempty"`
	Hits      int    `json:"hits"`
	LastTask  int64  `json:"last_task_id,omitempty"`
}

// knowledgeScope 解析本任务的知识作用域。
//
// 有公司 → company:<id>（同一甲方的多次交战互相复用，不跨客户泄漏）；
// 无公司 → task:<id>（退回单任务，不外溢）。
func (s *ExplorationStore) knowledgeScope(taskID int64) string {
	var companyID *int64
	if err := s.db.QueryRow(`SELECT company_id FROM tasks WHERE id=$1`, taskID).Scan(&companyID); err != nil {
		return fmt.Sprintf("task:%d", taskID)
	}
	if companyID != nil && *companyID > 0 {
		return fmt.Sprintf("company:%d", *companyID)
	}
	return fmt.Sprintf("task:%d", taskID)
}

// DistillKnowledge 在收尾时把本任务里【反复出现】的手法沉淀成知识。
//
// 门槛：同一漏洞类至少命中 2 次才算「手法」，避免把一次性观察灌进知识库。
// 否证边界取自同类里被判误报/重复的条目——它们是「这条打法什么时候不成立」
// 的直接证据。返回写入/更新的条目数。
func (s *ExplorationStore) DistillKnowledge(taskID int64) (int, error) {
	type agg struct {
		methods  []string
		boundary []string
		total    int
	}
	groups := map[string]*agg{}

	rows, err := s.db.Query(`SELECT COALESCE(vulnclass,''), COALESCE(name,''), COALESCE(summary,''),
  COALESCE(status,'pending')
FROM findings WHERE task_id=$1`, taskID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var class, name, summary, status string
		if err := rows.Scan(&class, &name, &summary, &status); err != nil {
			return 0, err
		}
		class = strings.TrimSpace(class)
		if class == "" {
			continue
		}
		a := groups[class]
		if a == nil {
			a = &agg{}
			groups[class] = a
		}
		a.total++
		switch status {
		case FindingFalsePositive, FindingDuplicate, FindingIgnored:
			if t := firstLine(summary, name); t != "" {
				a.boundary = append(a.boundary, t)
			}
		default:
			if t := firstLine(name, summary); t != "" {
				a.methods = append(a.methods, t)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	scope := s.knowledgeScope(taskID)
	n := 0
	for class, a := range groups {
		if a.total < 2 {
			continue
		}
		method := joinTop(a.methods, 3)
		boundary := joinTop(a.boundary, 2)
		if method == "" && boundary == "" {
			continue
		}
		if _, err := s.db.Exec(`INSERT INTO knowledge(scope_key, vuln_class, method, boundary, hits, last_task_id)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (scope_key, vuln_class) DO UPDATE SET
  method = CASE WHEN EXCLUDED.method <> '' THEN EXCLUDED.method ELSE knowledge.method END,
  boundary = CASE WHEN EXCLUDED.boundary <> '' THEN EXCLUDED.boundary ELSE knowledge.boundary END,
  hits = knowledge.hits + EXCLUDED.hits,
  last_task_id = EXCLUDED.last_task_id,
  updated_at = now()`,
			scope, class, method, boundary, a.total, taskID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// RecallKnowledge 按本任务作用域召回知识，命中次数高的优先。
//
// 召回依据暂用「同作用域 + 命中次数」：这是我们手上唯一结构化、无需向量的
// 信号。资产指纹级匹配要等指纹字段结构化之后再做。
func (s *ExplorationStore) RecallKnowledge(taskID int64, limit int) ([]KnowledgeEntry, error) {
	if limit <= 0 {
		limit = 5
	}
	scope := s.knowledgeScope(taskID)
	rows, err := s.db.Query(`SELECT id, scope_key, vuln_class, method, boundary, hits, COALESCE(last_task_id,0)
FROM knowledge WHERE scope_key=$1 ORDER BY hits DESC, updated_at DESC LIMIT $2`, scope, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KnowledgeEntry
	for rows.Next() {
		var e KnowledgeEntry
		if err := rows.Scan(&e.ID, &e.ScopeKey, &e.VulnClass, &e.Method, &e.Boundary, &e.Hits, &e.LastTask); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func firstLine(vals ...string) string {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if i := strings.IndexByte(v, '\n'); i > 0 {
			v = v[:i]
		}
		if r := []rune(v); len(r) > 120 {
			v = string(r[:120]) + "…"
		}
		return v
	}
	return ""
}

// joinTop 取前 n 条去重后拼成一行，避免把整批结论塞进知识条。
func joinTop(items []string, n int) string {
	seen := map[string]bool{}
	var out []string
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" || seen[it] {
			continue
		}
		seen[it] = true
		out = append(out, it)
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) < len(out[j]) })
	if len(out) > n {
		out = out[:n]
	}
	return strings.Join(out, "；")
}
