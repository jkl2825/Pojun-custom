package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFlagSubmitterMapsReceipts 锁住回执翻译，重点是 409 的两种语义必须分开：
// 「已拿过」和「这个值不是答案」是两件事，混成一种会让「诱饵」这条情报丢失，
// 兄弟 worker 会拿同一个假值再提交一遍（上一轮任务实测 16 次诱饵提交）。
func TestFlagSubmitterMapsReceipts(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		body   string
		status string
		flagID string
	}{
		{"计分成功", 200, `{"ok":true,"flag_id":"flag21","layer":3,"score":200,"rotated":true}`, "accepted", "flag21"},
		{"已拿过", 409, `{"error":"already claimed by this agent"}`, "duplicate", ""},
		{"诱饵或过期", 409, `{"error":"stale or unknown flag"}`, "stale", ""},
		{"格式不合法", 400, `{"error":"display_name required"}`, "invalid", ""},
		{"身份不匹配", 403, `{"error":"invalid join code"}`, "denied", ""},
		{"服务端故障", 500, `boom`, "error", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("期望 POST + application/json，实际 %s %s", r.Method, r.Header.Get("Content-Type"))
				}
				w.WriteHeader(c.code)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()

			sub := newFlagSubmitter(map[string]string{"url": srv.URL, "agent": "a", "token": "t"})
			if sub == nil {
				t.Fatal("配置了 url 却拿到 nil submitter")
			}
			r := sub.SubmitFlag(context.Background(), "flag{test}")
			if r.Status != c.status {
				t.Fatalf("状态=%q，期望 %q（body=%s）", r.Status, c.status, c.body)
			}
			if c.flagID != "" && r.FlagID != c.flagID {
				t.Fatalf("flag_id=%q，期望 %q", r.FlagID, c.flagID)
			}
			if c.status == "accepted" && (r.Score != 200 || r.Layer != 3 || !r.Rotated) {
				t.Fatalf("计分字段解析错误：%+v", r)
			}
		})
	}
}

// TestFlagSubmitterAbsentWithoutURL 锁住「未配置 = 工具不注册」的前提：
// 没有 url 就必须返回 nil，否则 submit_flag 会出现在不该有它的任务上。
func TestFlagSubmitterAbsentWithoutURL(t *testing.T) {
	if got := newFlagSubmitter(map[string]string{"agent": "a"}); got != nil {
		t.Fatalf("没有 url 时应返回 nil，实际 %T", got)
	}
}
