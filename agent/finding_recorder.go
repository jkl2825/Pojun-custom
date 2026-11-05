package agent

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/chu0119/pojun/db"
)

// validateFindingEvidence 高严重度证据门槛（v0.4.5，借鉴 Shannon 的 L3 门槛）：
// critical/high 必须有达到最低篇幅的可核验证据，挡住"一句话上报严重漏洞"。
// medium/low 不设门槛——低危经常只有一句说明，过度校验会阻碍正常上报。
// 返回空串表示通过，否则是回灌给模型的中文纠正提示（模型可在同会话补证据或降级）。
func validateFindingEvidence(severity, evidence string) string {
	n := utf8.RuneCountInString(strings.TrimSpace(evidence))
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		if n < 200 {
			return "证据不足以支撑 critical 级别：evidence 至少需要 200 字的可核验原始证据（请求/响应原文、命令输出、回显片段）。请补全证据后重新调用 report_finding；若实际只达到 L2（证明输入影响了后端逻辑但未拿到真实影响），请把 severity 降为 medium 并写明利用条件。"
		}
	case "high":
		if n < 120 {
			return "证据不足以支撑 high 级别：evidence 至少需要 120 字的可核验原始证据（请求/响应原文、命令输出或回显片段）。请补全后重新调用 report_finding；若只是间接推断，请把 severity 降为 medium 并注明。"
		}
	}
	return ""
}

// ═══ v0.4.52：机械验证凭据（借鉴 raptor 认识论闸门 + CVEngine triage 三重夹逼）═══

// EvidenceGrade 是证据的确定性等级（floor：由工具输出决定，AI 不能高于它）。
type EvidenceGrade int

const (
	EvidenceNone     EvidenceGrade = iota // 没有机械验证凭据
	EvidenceVersion                       // 只有版本/banner 匹配（不可靠：发行版 backport 不改版本号）
	EvidenceBehavior                      // 有行为级验证（nuclei 命中/HTTP 200+特征/CVSS 触发）
	EvidenceReplay                        // 有可复现回放（curl 命令+响应、截图、流量 ID）
)

// hasMechanicalVerification checks a format hint, NOT evidence authenticity.
// Tool names and response headers can be fabricated; the independent run ledger,
// provenance storage and manual retest remain authoritative.
func hasMechanicalVerification(evidence string) bool {
	lower := strings.ToLower(evidence)
	signals := []string{
		"http/1.", "http/2", // HTTP 原始响应头
		"curl -", "curl ", // curl 命令
		"sqlmap",                                                   // sqlmap 输出
		"nuclei",                                                   // nuclei 模板命中
		"status: 200", "status: 403", "status: 301", "status: 302", // 状态码
		"\"code\":", "\"status\":", // JSON 响应字段
		"location:", "set-cookie:", "content-type:", // HTTP 响应头字段
	}
	for _, sig := range signals {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}

// hasVersionOnlyEvidence 检查是否只有版本匹配（借鉴 CVEngine match_policy 的
// "version ≠ vulnerability" 规则——发行版 backport 不改版本号）。
func hasVersionOnlyEvidence(evidence string) bool {
	lower := strings.ToLower(evidence)
	versionSignals := []string{"version", "banner", "server:", "x-powered-by", "powered-by"}
	hasVersion := false
	hasExploit := false
	for _, sig := range versionSignals {
		if strings.Contains(lower, sig) {
			hasVersion = true
			break
		}
	}
	exploitSignals := []string{"curl -", "200", "403", "http/1.", "response", "output"}
	for _, sig := range exploitSignals {
		if strings.Contains(lower, sig) {
			hasExploit = true
			break
		}
	}
	return hasVersion && !hasExploit
}

// validateMechanicalEvidence 机械验证凭据校验（v0.4.52，借鉴 raptor 认识论闸门）：
// critical/high 漏洞必须附可机械复现的验证凭据（HTTP 响应/curl 输出/工具输出）。
// 纯版本匹配不能作为漏洞证据（CVEngine match_policy：发行版 backport 不改版本号）。
// 返回空串表示通过，否则是回灌给模型的纠正提示。
func validateMechanicalEvidence(severity, evidence string) string {
	if strings.TrimSpace(evidence) == "" {
		return "" // 空 evidence 由 validateFindingEvidence 处理
	}
	lower := strings.ToLower(strings.TrimSpace(severity))
	if lower != "critical" && lower != "high" {
		return "" // medium/low 不做机械验证校验
	}
	if hasMechanicalVerification(evidence) {
		return "" // 有机械验证凭据，通过
	}
	if hasVersionOnlyEvidence(evidence) {
		return "证据只有版本/banner 匹配，没有行为级验证——发行版 backport 补丁不改版本号，版本匹配 ≠ 漏洞。" +
			"请用 http_probe 或 curl 对目标实际发送请求，把 HTTP 状态码/响应特征/命令输出写进 evidence。" +
			"如果只是版本匹配没有验证，请降为 medium 并注明「版本匹配，行为未验证」。"
	}
	return "critical/high 证据缺少可机械复现的验证凭据（HTTP 状态码/curl 命令输出/工具命中结果）。" +
		"请用工具实际触发目标，把返回的状态码/响应头/关键字段写入 evidence——" +
		"「可能存在」不是 finding，「实际拿到」才是。或者降级为 medium。"
}

// Non-HTTP evidence need not name an HTTP client. Permit it only when at least
// two meaningful lines are completely backed by this run's recorded output.
// This does not bypass the existing evidence verifier or grade a finding true.
func validateMechanicalEvidenceForRun(ctx context.Context, severity, evidence string) string {
	msg := validateMechanicalEvidence(severity, evidence)
	if msg == "" || hasVersionOnlyEvidence(evidence) {
		return msg
	}
	if ledger, mode := ToolOutputsFromContext(ctx); ledger != nil && mode != EvidenceVerifyOff {
		matched, total := ledger.VerifyEvidence(evidence)
		if total >= 2 && matched == total {
			return ""
		}
	}
	return msg
}

// FindingRecorder is injected by the host; agents never synthesize or copy
// evidence bodies themselves. Its implementation owns the atomic write.
type FindingRecorder interface {
	Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error)
}

const findingTrafficGuidance = "\n\n**漏洞流量证据（可选）**：调用 report_finding 上报漏洞时，如有已查看并确认支持漏洞结论的 HTTP 请求/响应，可用 traffic_refs 按复现顺序绑定真实 ID；域名和时间只作候选筛选，不推定关联。TCP 等非 HTTP 漏洞、未采集或无确切匹配时省略或传 []，在 evidence 保留命令输出、日志等其他可验证证据，建议说明未绑定原因。不要猜测 ID，也不要仅为补包重复探测。"

func (t *ToolSet) SetFindingRecorder(r FindingRecorder)   { t.findingRecorder = r }
func (w *Worker) SetFindingRecorder(r FindingRecorder)    { w.findingRecorder = r }
func (p *Planner) SetFindingRecorder(r FindingRecorder)   { p.findingRecorder = r }
func (m *MainAgent) SetFindingRecorder(r FindingRecorder) { m.findingRecorder = r }
