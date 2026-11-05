package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/chu0119/pojun/agent"
)

// httpFlagSubmitter 把 flag 交给交战发起方给定的计分端点，并翻译回执。
//
// 端点/凭据来自 tasks.submit_config（任务创建时写入），agent 侧完全不可见——
// 这是「裁决权不在被验证方手里」的实现点。换成任意支持同类 HTTP 契约的
// 计分服务都成立，不绑定某个具体靶场。
type httpFlagSubmitter struct {
	url    string
	agent  string
	token  string
	name   string
	client *http.Client
}

// newFlagSubmitter 按任务配置构造通道；配置缺 url 时返回 nil（工具不注册）。
func newFlagSubmitter(cfg map[string]string) agent.FlagSubmitter {
	url := strings.TrimSpace(cfg["url"])
	if url == "" {
		return nil
	}
	return &httpFlagSubmitter{
		url:    url,
		agent:  strings.TrimSpace(cfg["agent"]),
		token:  strings.TrimSpace(cfg["token"]),
		name:   strings.TrimSpace(cfg["display_name"]),
		client: &http.Client{Timeout: 20 * time.Second},
	}
}

func (h *httpFlagSubmitter) SubmitFlag(ctx context.Context, flag string) agent.FlagReceipt {
	payload, _ := json.Marshal(map[string]string{
		"agent":        h.agent,
		"token":        h.token,
		"display_name": h.name,
		"flag":         flag,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(payload))
	if err != nil {
		return agent.FlagReceipt{Status: "error", Message: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return agent.FlagReceipt{Status: "error", Message: err.Error()}
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	body := buf.Bytes()

	var ok struct {
		OK       bool   `json:"ok"`
		FlagID   string `json:"flag_id"`
		Layer    int    `json:"layer"`
		Score    int    `json:"score"`
		Rotated  bool   `json:"rotated"`
		Error    string `json:"error"`
		Status   string `json:"status"`
		Message  string `json:"message"`
	}
	_ = json.Unmarshal(body, &ok)
	msg := firstNonEmpty(ok.Error, ok.Status, ok.Message, truncateForMsg(string(body), 200))

	switch resp.StatusCode {
	case http.StatusOK:
		if ok.OK || ok.FlagID != "" {
			return agent.FlagReceipt{Status: "accepted", FlagID: ok.FlagID, Layer: ok.Layer, Score: ok.Score, Rotated: ok.Rotated, Message: msg}
		}
		return agent.FlagReceipt{Status: "error", Message: "200 但回执不可解析：" + msg}
	case http.StatusBadRequest:
		return agent.FlagReceipt{Status: "invalid", Message: msg}
	case http.StatusForbidden:
		return agent.FlagReceipt{Status: "denied", Message: msg}
	case http.StatusConflict:
		// 409 有两种语义，必须分开：已拿过 vs 值不对（诱饵/过期）。
		// 混为一谈会让「这个值是假的」这条情报丢失，兄弟 worker 会再试一次。
		if strings.Contains(strings.ToLower(msg), "already claimed") {
			return agent.FlagReceipt{Status: "duplicate", Message: msg}
		}
		return agent.FlagReceipt{Status: "stale", Message: msg}
	default:
		return agent.FlagReceipt{Status: "error", Message: msg}
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncateForMsg(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
