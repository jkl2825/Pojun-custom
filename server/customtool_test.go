package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/chu0119/pojun/db"
)

func TestRenderTemplateCommand(t *testing.T) {
	// command: string params shell-quoted; array → JSON (also quoted).
	got := renderTemplate("nmap -p {ports} {target}", map[string]any{
		"target": "10.0.0.1; rm -rf /", // injection attempt → must be single-quoted
		"ports":  []any{80.0, 443.0},
	}, shellQuote)
	if !strings.Contains(got, `'10.0.0.1; rm -rf /'`) {
		t.Fatalf("target not shell-quoted: %q", got)
	}
	if strings.Contains(got, "rm -rf /'") && !strings.Contains(got, `'10.0.0.1; rm -rf /'`) {
		t.Fatalf("possible injection leak: %q", got)
	}
	if strings.Contains(got, "{target}") || strings.Contains(got, "{ports}") {
		t.Fatalf("placeholders not replaced: %q", got)
	}
}

func TestRenderTemplateHTTP(t *testing.T) {
	// http: identity (no shell quoting) — raw substitution into url/body.
	got := renderTemplate("https://x/submit?flag={flag}", map[string]any{"flag": "CTF{abc}"}, identity)
	if got != "https://x/submit?flag=CTF{abc}" {
		t.Fatalf("http render: %q", got)
	}
}

// 跨参数污染:参数值里的 {token} 是数据不是占位符,渲染后必须原样保留,
// 不得被后续参数(token)替换掉。
func TestCustomToolRenderNoCrossParamPollution(t *testing.T) {
	got := renderTemplate("?flag={flag}", map[string]any{
		"flag":  "CTF{token}",
		"token": "s3cr3t",
	}, identity)
	if got != "?flag=CTF{token}" {
		t.Fatalf("cross-param pollution: %q", got)
	}
	// 同样适用于 command(shellQuote)路径。
	gotCmd := renderTemplate("submit {flag} {token}", map[string]any{
		"flag":  "CTF{token}",
		"token": "s3cr3t",
	}, shellQuote)
	if !strings.Contains(gotCmd, `'CTF{token}'`) || strings.Contains(gotCmd, "s3cr3t{token}") {
		t.Fatalf("cross-param pollution (command): %q", gotCmd)
	}
}

// 确定性:同一输入连续渲染 20 次结果必须一致(此前 map 遍历序随机会导致漂移)。
func TestCustomToolRenderDeterministic(t *testing.T) {
	tmpl := "nmap -p {ports} {target} --name {name} {missing}"
	params := map[string]any{
		"target": "10.0.0.1; rm -rf /",
		"ports":  []any{80.0, 443.0},
		"name":   "a'b {target}",
	}
	first := renderTemplate(tmpl, params, shellQuote)
	for i := 0; i < 20; i++ {
		if got := renderTemplate(tmpl, params, shellQuote); got != first {
			t.Fatalf("render %d differs:\nfirst: %q\ngot:   %q", i, first, got)
		}
	}
}

// URL 按位置编码:query 部分用 QueryEscape、path 部分用 PathEscape。
func TestCustomToolURLQuote(t *testing.T) {
	got := renderTemplate("https://x/api/{path}?q={q}&r={r}", map[string]any{
		"path": "a b/c?d",
		"q":    "a&b=c d",
		"r":    "x\r\nHost: evil",
	}, urlQuote)
	want := "https://x/api/" + url.PathEscape("a b/c?d") +
		"?q=" + url.QueryEscape("a&b=c d") +
		"&r=" + url.QueryEscape("x\r\nHost: evil")
	if got != want {
		t.Fatalf("urlQuote:\n got: %q\nwant: %q", got, want)
	}
	// 参数值中的结构字符(?、&、/、空格、CR/LF)必须全部被转义,不得原样出现。
	for _, leak := range []string{" ", "\r", "\n"} {
		if strings.Contains(got, leak) {
			t.Fatalf("unescaped char %q leaked into url: %q", leak, got)
		}
	}
}

// 保存期与编辑器测试的校验应识别真实引号、转义及 shell word 边界。
func TestCustomToolLintCommandTemplate(t *testing.T) {
	bad := []string{
		`curl "{url}"`,
		`curl '{url}'`,
		`curl -H "X: {token}"`,
		`printf '%s' 'prefix {value} suffix'`,
		`printf '%s' "prefix \"quoted\" {value}"`,
		`printf '%s' "prefix \\ {value}"`,
		`printf '%s' \" {value}"`,
		`printf '%s' \{value}`,
		`printf '%s' prefix\ {value}`,
		`printf '%s' {value}\ suffix`,
		`printf '%s' prefix{value}`,
		`printf '%s' {value}suffix`,
		`printf '%s' {a}{b}`,
		`printf '%s' ""{value}`,
		`printf '%s' {value}''`,
		`printf '%s' --value={value}`,
		`printf '%s' {value}#suffix`,
		"printf '%s' \r{value}",
		"printf '%s' {value}\r",
		"printf '%s' prefix\\\n{value}",
		"printf '%s' {value}\\\nsuffix",
		"printf '%s' {value}\\\n{other}",
		"printf '%s' `{value}`",
		"printf '%s' `printf 'prefix %s' {value}`",
		`printf '%s' ${value}`,
		`printf '%s' ${other:- {value}}`,
		`printf '%s' $(printf '%s' {value})`,
		`printf '%s' $[1 + {value}]`,
		`printf '%s' $'prefix {value}'`,
		`printf '%s' $"prefix {value}"`,
		"printf '%s' $\\\n'prefix {value}'",
		`printf '%s' "$(printf '%s' {value})"`,
		`printf '%s' $(printf static) {value}`,
		`(printf '%s' {value})`,
		"cat <<EOF\n{value}\nEOF",
		"cat <\\\n<EOF\n{value}\nEOF",
		`cat <<< {value}`,
		`printf '%s' # {value}`,
		`printf '%s' {value} "unterminated`,
		"printf '%s' {value} \\",
	}
	for _, cmd := range bad {
		t.Run("reject_"+cmd, func(t *testing.T) {
			if err := lintCommandTemplate(cmd); err == nil {
				t.Fatalf("应拒绝不安全模板 %q", cmd)
			}
			raw, err := json.Marshal(commandExec{Command: cmd})
			if err != nil {
				t.Fatal(err)
			}
			if err := lintCustomToolExec("command", raw); err == nil {
				t.Fatalf("保存与编辑器测试应拒绝不安全模板 %q", cmd)
			}
		})
	}
	good := []string{
		`curl {url}`,
		`nmap -p {ports} {target}`,
		`echo hello`,
		`echo "$(printf static)"`, // 无占位符的模板保持兼容。
		`printf '%s' {value}`,
		`printf '%s' {a} {b}`,
		`printf '%s' "static value" {value}`,
		`printf '%s' 'static value' {value}`,
		`printf '%s' "static \"quoted\" value" {value}`,
		`printf '%s' \"static\" {value}`,
		`printf '%s' static\ value {value}`,
		`printf '%s' \\ {value}`,
		`printf '%s' "$HOME" {value}`,
		`printf '%s' $HOME {value}`,
		`printf '%s' '\$(literal) ` + "`literal`" + `' {value}`,
		`printf '%s' \$HOME {value}`,
		"printf '%s' \\`literal\\` {value}",
		"printf '%s' \\\n{value}",
		"printf '%s' {value}\\\n {other}",
		"printf '%s'\t{value}\n",
		`printf '%s' {value}|cat`,
		`printf '%s' {value}; printf '%s' {other}`,
		`printf '%s' {value} && printf '%s' {other}`,
		`cat <{path}`,
		"# 'unclosed quote ignored\nprintf '%s' {value}",
		"printf static # unclosed \" quote\nprintf '%s' {value}",
	}
	for _, cmd := range good {
		t.Run("accept_"+cmd, func(t *testing.T) {
			if err := lintCommandTemplate(cmd); err != nil {
				t.Fatalf("应接受合法模板 %q: %v", cmd, err)
			}
		})
	}
	if err := lintCommandTemplate(`curl "{url}"`); err == nil || !strings.Contains(err.Error(), "占位符必须独立成词") {
		t.Fatalf("校验错误缺少使用指引: %v", err)
	}
	// script/http 的原始参数插值不受 command 校验限制。
	for _, kind := range []string{"script", "http", "shell"} {
		if err := lintCustomToolExec(kind, json.RawMessage(`{"command":"printf \"prefix {value}\""}`)); err != nil {
			t.Fatalf("%s 类型不应进行 command 校验: %v", kind, err)
		}
	}
	if err := lintCustomToolExec("command", nil); err != nil {
		t.Fatalf("空 exec 应保留原行为: %v", err)
	}
	if err := lintCustomToolExec("command", json.RawMessage(`not json`)); err != nil {
		t.Fatalf("格式错误的 exec 应交给执行器处理: %v", err)
	}
}

// 历史数据库记录可能跳过保存期校验，执行器必须在调用 Bash 前拒绝。
func TestCustomToolCommandRejectsUnsafeStoredTemplate(t *testing.T) {
	for _, cmd := range []string{
		`printf '%s' "prefix {value}"`,
		`printf '%s' 'prefix {value}'`,
		`printf '%s' prefix{value}`,
		`printf '%s' {value}suffix`,
	} {
		t.Run(cmd, func(t *testing.T) {
			raw, err := json.Marshal(commandExec{Command: cmd})
			if err != nil {
				t.Fatal(err)
			}
			s := &Server{}
			params := map[string]any{"value": "plain value"}
			res, err := s.runCommandTool(context.Background(), raw, params, nil)
			if err != nil || !res.IsError || !strings.Contains(res.Flatten(), "占位符必须独立成词") {
				t.Fatalf("执行器未拒绝历史不安全模板: result=%+v, err=%v", res, err)
			}
			tool := s.buildCustomTool(&db.Tool{Key: "legacy_command", Kind: "command", Exec: raw})
			res, err = tool.Call(context.Background(), json.RawMessage(`{"value":"plain value"}`), nil)
			if err != nil || !res.IsError || !strings.Contains(res.Flatten(), "占位符必须独立成词") {
				t.Fatalf("历史工具调用未拒绝不安全模板: result=%+v, err=%v", res, err)
			}
		})
	}
}

func TestCustomToolCommandIndependentParams(t *testing.T) {
	cmd := `printf '%s\n' {value} {other}`
	if err := lintCommandTemplate(cmd); err != nil {
		t.Fatalf("独立参数不应被拒绝: %v", err)
	}
	got := renderTemplate(cmd, map[string]any{"value": "a'b\nnext", "other": "two words"}, shellQuote)
	want := "printf '%s\\n' 'a'\\''b\nnext' 'two words'"
	if got != want {
		t.Fatalf("独立参数未安全保留单引号、换行或空格:\n got: %q\nwant: %q", got, want)
	}
}

func TestScalarStr(t *testing.T) {
	cases := []struct {
		v    any
		want string
		ok   bool
	}{
		{"hi", "hi", true},
		{true, "true", true},
		{float64(80), "80", true},   // integer-valued float → no decimal
		{float64(1.5), "1.5", true}, // real float
		{[]any{1, 2}, "", false},    // array → not scalar
		{map[string]any{}, "", false},
	}
	for _, c := range cases {
		got, ok := scalarStr(c.v)
		if ok != c.ok || (ok && got != c.want) {
			t.Fatalf("scalarStr(%v) = (%q,%v), want (%q,%v)", c.v, got, ok, c.want, c.ok)
		}
	}
}

func TestEnsureSchema(t *testing.T) {
	// empty → thin {args:string}
	m := ensureSchema(nil)
	props, _ := m["properties"].(map[string]any)
	if _, ok := props["args"]; !ok {
		t.Fatalf("empty schema should default to args: %v", m)
	}
	// non-empty → passthrough
	raw := json.RawMessage(`{"type":"object","properties":{"target":{"type":"string"}}}`)
	m2 := ensureSchema(raw)
	p2, _ := m2["properties"].(map[string]any)
	if _, ok := p2["target"]; !ok {
		t.Fatalf("non-empty schema should pass through: %v", m2)
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("a'b", "", 0); got != `'a'\''b'` {
		t.Fatalf("shellQuote(a'b) = %q", got)
	}
}

// TestExecPython runs a real Python script end-to-end: it must read params from
// stdin JSON and the mirrored env var, then print — verifying the whole script
// param-passing path. Skips if no python3.
func TestExecPython(t *testing.T) {
	interp, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	code := `import json,sys,os
a = json.load(sys.stdin)
print("stdin_target=" + a["target"])
print("env_target=" + os.environ.get("TOOL_TARGET",""))
print("port=" + str(a["port"]))
`
	out, err := execPython(context.Background(), interp, "test", code,
		map[string]any{"target": "example.com", "port": float64(8080)},
		t.TempDir(), nil, 10*time.Second)
	if err != nil {
		t.Fatalf("execPython error: %v", err)
	}
	for _, want := range []string{"stdin_target=example.com", "env_target=example.com", "port=8080"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

// TestRunHTTPTool functionally exercises the http executor against a local server:
// method/url/header/body templates are rendered from params, the request is sent,
// and the response status+body are returned. No recording proxy → s.m untouched.
func TestRunHTTPTool(t *testing.T) {
	var gotMethod, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	execRaw, _ := json.Marshal(map[string]any{
		"method":  "POST",
		"url":     srv.URL + "/submit?flag={flag}",
		"headers": map[string]string{"Authorization": "Bearer {token}"},
		"body":    `{"flag":"{flag}"}`,
	})
	res, err := (&Server{}).runHTTPTool(context.Background(), execRaw,
		map[string]any{"flag": "CTF{x}", "token": "sekret"}, nil)
	if err != nil {
		t.Fatalf("runHTTPTool: %v", err)
	}
	if res.IsError || len(res.Content) == 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	var out struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	_ = json.Unmarshal([]byte(res.Content[0].Text), &out)

	if gotMethod != "POST" {
		t.Fatalf("method: %q", gotMethod)
	}
	if gotAuth != "Bearer sekret" {
		t.Fatalf("header template not rendered: %q", gotAuth)
	}
	if gotBody != `{"flag":"CTF{x}"}` {
		t.Fatalf("body template not rendered: %q", gotBody)
	}
	if out.Status != 201 || !strings.Contains(out.Body, `"ok":true`) {
		t.Fatalf("response not captured: %+v", out)
	}
}

func TestDetectPython(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	if p := detectPython(); p == "" {
		t.Fatal("detectPython returned empty despite python3 on PATH")
	}
}

// The http tool must truncate an oversized response through norma's Capture, the
// same valve every other tool uses — a session with no OutputDir falls back to a
// head+tail cut, so a body far past the default cap comes back shortened.
func TestHTTPToolTruncatesLargeBody(t *testing.T) {
	big := strings.Repeat("x", 40000) // past Capture's 30000 default
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	execRaw, _ := json.Marshal(map[string]any{"method": "GET", "url": srv.URL})
	res, err := (&Server{}).runHTTPTool(context.Background(), execRaw, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("runHTTPTool: %v", err)
	}
	out := res.Flatten()
	if len(out) >= 40000 {
		t.Fatalf("oversized http body was not truncated: len=%d", len(out))
	}
}
