package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// recallKnowledge 召回本作用域（同公司，或同任务）历史上反复验证过的手法。
//
// 为什么给规划者而不是 worker：知识是用来决定「往哪打」的，worker 只执行
// 单条意图；把它塞给 worker 会把上下文撑大而决策不变。
//
// 每条都带 boundary（否证边界）——那才是我们最值钱的部分：同类目标上
// 「什么条件下这条打法不成立」，能直接省掉一次整轮试错。
func (t *ToolSet) recallKnowledge() actool.CoreTool {
	return t.readExpTool("recall_knowledge",
		"召回历史知识：同一甲方（无公司则同一任务）此前反复验证过的打法，以及它们成立/不成立的条件。"+
			"开新方向前先看一眼，避免重复踩前人踩过的坑；命中次数=历史上被验证过几次，越高的越可信。",
		obj(map[string]any{
			"limit": intp("返回条数，默认 5，上限 20"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Limit int `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = 5
			}
			if limit > 20 {
				limit = 20
			}
			if t.ts == nil || t.taskID <= 0 {
				return actool.Text("（无知识作用域）"), nil
			}
			entries, err := t.ts.RecallKnowledge(t.taskID, limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(entries) == 0 {
				return actool.Text("（本作用域暂无历史知识——首次打这类目标时属正常）"), nil
			}
			var b strings.Builder
			for i, e := range entries {
				fmt.Fprintf(&b, "%d. [%s] 命中 %d 次\n   手法：%s\n", i+1, e.VulnClass, e.Hits, e.Method)
				if e.Boundary != "" {
					fmt.Fprintf(&b, "   不成立时：%s\n", e.Boundary)
				}
			}
			return actool.Text(b.String()), nil
		})
}
