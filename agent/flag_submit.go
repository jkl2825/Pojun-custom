package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/chu0119/pojun/db"
)

// FlagSubmitter 是「把 flag 交给外部计分方并拿回裁决」的通道。
//
// 为什么是接口而不是直接发 HTTP：裁决通道的地址与凭据必须由交战发起方
// （任务创建时写入 tasks.submit_config）持有，agent 只能递 flag。工具入参
// 里刻意不含 url/token——一旦模型能指定地址，它就能指向自己起一个永远返回
// 200 的服务，验收立刻退回自我声明，这正是我们要拆掉的东西。
type FlagSubmitter interface {
	SubmitFlag(ctx context.Context, flag string) FlagReceipt
}

// FlagReceipt 是外部计分方的裁决回执。Status 取值：
//
//	accepted  — 计分成功
//	stale     — 该值已过期或不在答案中（诱饵/已轮换）：**不要重复提交同一个值**
//	duplicate — 本 agent 已提交过该值
//	invalid   — 格式不合法（回去重新读取目标服务）
//	denied    — 身份/token 不匹配
//	error     — 链路错误（超时/连不上/响应不可解析）
type FlagReceipt struct {
	Status  string
	FlagID  string
	Layer   int
	Score   int
	Rotated bool
	Message string
}

// SetFlagSubmitter 注入裁决通道；nil 表示本任务没有提交通道（工具不注册）。
func (t *ToolSet) SetFlagSubmitter(s FlagSubmitter) { t.submitter = s }

// submitFlag 是夺旗类交战的终点动作。
//
// 设计约束（对标 pentest-platform 的 hunt_flag，2026-11-05 评审）：
//  1. 入参只有 flag —— 题号由服务端解析，模型不接触地址与凭据；
//  2. 裁决与记账在同一个调用栈里 —— 记不记由代码保证，不依赖模型自觉；
//  3. 负结果（stale/duplicate）也上图 —— 否则兄弟 worker 会把同一个诱饵
//     再提交一遍（上一轮任务实测 16 次诱饵提交）。
func (t *ToolSet) submitFlag() actool.CoreTool {
	return t.writeExpTool("submit_flag",
		"把从目标读到的【真实 flag】提交给外部计分方并拿回裁决。\n"+
			"纪律：①每次读到真值立即提交；②返回 stale（过期/不在答案中）说明这个值不是真值，**不要重复提交同一个值**，回去重新读取服务；"+
			"③返回 duplicate 表示本 agent 已经拿过该点，直接做下一个；④提交成功后该计分点会轮换，旧值失效。\n"+
			"不要在命令里手写提交请求（curl 等）——那次提交不会进账，也不会有回执留痕。",
		obj(map[string]any{"flag": str("从目标服务读到的真实 flag 原文（不要编造、不要用示例值）")}, "flag"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Flag string `json:"flag"`
			}
			_ = json.Unmarshal(in, &a)
			flag := strings.TrimSpace(a.Flag)
			if flag == "" {
				return actool.Errorf("flag 必填"), nil
			}
			if t.submitter == nil {
				return actool.Errorf("本任务未配置提交通道（submit_config），无法提交"), nil
			}
			r := t.submitter.SubmitFlag(ctx, flag)
			t.recordSubmitReceipt(flag, r)
			switch r.Status {
			case "accepted":
				return actool.Text(fmt.Sprintf("提交成功：flag_id=%s layer=%d score=%d rotated=%v。该点已换新值，做下一个。",
					r.FlagID, r.Layer, r.Score, r.Rotated)), nil
			case "stale":
				return actool.Text("该值被判为过期/不在答案中（stale）。这不是真值，**不要重复提交同一个值**——回到目标服务重新读取当前 flag。"), nil
			case "duplicate":
				return actool.Text("该值本 agent 已提交过（duplicate），无需重提，做下一个目标。"), nil
			case "invalid":
				return actool.Text("flag 格式不合法（invalid），回到目标服务重新读取后再提交。"), nil
			case "denied":
				return actool.Text("提交通道拒绝（denied）：身份或凭据不匹配，提交链路本身有问题，先排查通道配置。"), nil
			default:
				return actool.Text(fmt.Sprintf("提交链路错误：%s（本次未落账，稍后可重试同一值）", r.Message)), nil
			}
		})
}

// recordSubmitReceipt 把回执写到图上：成功计分与「负结果」都留痕。
//
// 只在 accepted/stale/duplicate 三种情况写：invalid/denied/error 是链路或
// 调用方问题，写进图只会污染；而 stale 是**关于世界的结论**（这个值不是答案），
// 必须让兄弟 worker 看到，否则重复踩坑。
func (t *ToolSet) recordSubmitReceipt(flag string, r FlagReceipt) {
	if t.ts == nil {
		return
	}
	var summary, detail string
	switch r.Status {
	case "accepted":
		summary = fmt.Sprintf("[FLAG] 已计分 %s（layer=%d score=%d rotated=%v）", r.FlagID, r.Layer, r.Score, r.Rotated)
		detail = fmt.Sprintf("外部计分方裁决 accepted。flag_id=%s layer=%d score=%d rotated=%v。%s",
			r.FlagID, r.Layer, r.Score, r.Rotated, r.Message)
	case "stale":
		summary = "[FLAG|stale] 该值被判过期/不在答案中——诱饵或已轮换，勿再提交同一值"
		detail = fmt.Sprintf("提交值 %s 被外部计分方判为 stale/unknown。%s", maskFlag(flag), r.Message)
	case "duplicate":
		summary = "[FLAG|duplicate] 该值本 agent 已提交过"
		detail = fmt.Sprintf("提交值 %s 已由本 agent 计分过。%s", maskFlag(flag), r.Message)
	default:
		return
	}
	if _, err := t.ts.AddNode("fact", map[string]any{
		"summary":    summary,
		"detail":     detail,
		"evidence":   "submit_flag 回执（外部计分方）",
		"confidence": "observed",
	}, 0, "confirmed", t.worker, nil); err != nil {
		log.Printf("[submit_flag] task=%d 回执落图失败: %v", t.taskID, err)
	}
}

// maskFlag 只保留首尾各 8 字符，避免把完整答案连同中间段写进图（图会进上下文）。
func maskFlag(flag string) string {
	if len(flag) <= 24 {
		return flag
	}
	return flag[:8] + "…" + flag[len(flag)-8:]
}

// 让 db 包在本文件可用（AddNode 常量 kind 走字符串，但保持显式引用便于阅读）。
var _ = db.KindFact
