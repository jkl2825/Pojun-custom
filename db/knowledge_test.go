package db

import (
	"fmt"
	"testing"
	"time"
)

// TestDistillKnowledge 锁住知识沉淀的三条规则：
//  1. 同一漏洞类至少 2 次才沉淀（一次性观察不进知识库）；
//  2. 否证条目（误报/重复/忽略）进 boundary，而不是混进 method；
//  3. 作用域按任务走（无公司时 task:<id>），不跨任务泄漏。
func TestDistillKnowledge(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("knowledge-test", "验证知识沉淀")
	if err != nil {
		t.Fatal(err)
	}
	var taskID int64
	tag := fmt.Sprintf("kt-%d", time.Now().UnixNano())
	if err := d.QueryRow(`INSERT INTO tasks(name, description, goal, exploration_id, status)
VALUES ($1,'','', $2,'created') RETURNING id`, tag, expID).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		d.Exec(`DELETE FROM findings WHERE task_id=$1`, taskID)
		d.Exec(`DELETE FROM knowledge WHERE last_task_id=$1`, taskID)
		d.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)
		d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	}()

	ins := func(class, name, summary, status string) {
		if _, err := d.Exec(`INSERT INTO findings(task_id, vulnclass, name, summary, evidence, status)
VALUES ($1,$2,$3,$4,'ev',$5)`, taskID, class, name, summary, status); err != nil {
			t.Fatal(err)
		}
	}
	// 注入：3 条命中 + 1 条误报（误报应进 boundary）
	ins("注入", "命令注入", "l7-hmi /api/diag 命令注入可读 flag", FindingConfirmed)
	ins("注入", "SQL 注入", "l5 归档接口 order 参数可注入", FindingConfirmed)
	ins("注入", "命令注入", "升级路径 /api/exec 同样可注入", FindingConfirmed)
	ins("注入", "命令注入", "误报：$IFS 被过滤导致 payload 无效", FindingFalsePositive)
	// 另一类只有 1 条 —— 不应沉淀
	ins("XXE", "XXE", "一次性观察，不构成手法", FindingConfirmed)

	es := d.Exploration(expID)
	n, err := es.DistillKnowledge(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("沉淀条数=%d，期望 1（只有「注入」够 2 次门槛）", n)
	}

	var method, boundary string
	var hits int
	if err := d.QueryRow(`SELECT method, boundary, hits FROM knowledge WHERE last_task_id=$1 AND vuln_class='注入'`,
		taskID).Scan(&method, &boundary, &hits); err != nil {
		t.Fatalf("未找到注入知识条: %v", err)
	}
	if hits != 4 {
		t.Fatalf("hits=%d，期望 4（3 命中 + 1 误报都算经历）", hits)
	}
	if method == "" {
		t.Fatal("method 为空：命中的手法没被记下来")
	}
	if boundary == "" {
		t.Fatal("boundary 为空：误报条目没进否证面")
	}

	// 作用域：无 company → task:<id>
	var scope string
	if err := d.QueryRow(`SELECT scope_key FROM knowledge WHERE last_task_id=$1 AND vuln_class='注入'`, taskID).Scan(&scope); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("task:%d", taskID); scope != want {
		t.Fatalf("scope=%q，期望 %q（无公司时退回单任务）", scope, want)
	}

	// 召回：能取回刚沉淀的这条
	entries, err := es.RecallKnowledge(taskID, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].VulnClass != "注入" {
		t.Fatalf("召回结果不符：%+v", entries)
	}
}

// TestTaskSubmitConfigRoundTrip 守住提交通道的存取契约：
// 写入后可读出，清空后读取返回 nil（= submit_flag 不再注册）。
func TestTaskSubmitConfigRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("submit-config-test", "验证提交通道存取")
	if err != nil {
		t.Fatal(err)
	}
	var taskID int64
	if err := d.QueryRow(`INSERT INTO tasks(name, description, goal, exploration_id, status)
VALUES ('sc','','',$1,'created') RETURNING id`, expID).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		d.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)
		d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	}()

	if cfg := d.TaskSubmitConfig(taskID); cfg != nil {
		t.Fatalf("新建任务不应有通道，实际 %+v", cfg)
	}
	want := map[string]string{"url": "http://t.local/api/submit", "agent": "a1", "token": "t1"}
	if err := d.SetTaskSubmitConfig(taskID, want); err != nil {
		t.Fatal(err)
	}
	got := d.TaskSubmitConfig(taskID)
	if got["url"] != want["url"] || got["agent"] != want["agent"] || got["token"] != want["token"] {
		t.Fatalf("回读不符: %+v", got)
	}
	if err := d.SetTaskSubmitConfig(taskID, nil); err != nil {
		t.Fatal(err)
	}
	if cfg := d.TaskSubmitConfig(taskID); cfg != nil {
		t.Fatalf("清空后应返回 nil，实际 %+v", cfg)
	}
}
