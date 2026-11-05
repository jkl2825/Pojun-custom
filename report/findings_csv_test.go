package report

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/chu0119/pojun/db"
)

// 以 =、+、-、@ 等开头的文本字段在 Excel 打开 CSV 时会被当公式执行（公式注入），
// 导出前必须加单引号前缀。
func TestFindingsCSVFormulaInjection(t *testing.T) {
	f := &db.DBFinding{
		ID:              1,
		Name:            "=cmd|'/c calc'!A1",
		VulnClass:       "+1+2",
		Severity:        "high",
		Status:          "pending",
		TaskDescription: "-2+3",
		Summary:         `=HYPERLINK("http://evil.example","click")`,
		CreatedAt:       time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC),
	}
	out := FindingsCSV([]*db.DBFinding{f})
	out = bytes.TrimPrefix(out, []byte("\xEF\xBB\xBF"))

	recs, err := csv.NewReader(bytes.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("解析导出 CSV 失败: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("期望表头+1 行数据, 实际 %d 行", len(recs))
	}
	row := recs[1]

	// 列序: ID, 名称, 类别, 严重等级, 状态, 所属任务, 发现时间, 概述, 流量证据数量, 流量证据ID
	if !strings.HasPrefix(row[1], "'=") {
		t.Fatalf("名称未转义公式注入: %q", row[1])
	}
	if row[2] != "'+1+2" {
		t.Fatalf("类别未转义公式注入: %q", row[2])
	}
	if row[5] != "'-2+3" {
		t.Fatalf("所属任务未转义公式注入: %q", row[5])
	}
	if !strings.HasPrefix(row[7], "'=") {
		t.Fatalf("概述未转义公式注入: %q", row[7])
	}

	// 普通文本与纯数字/时间字段不应被改动。
	if row[0] != "1" {
		t.Fatalf("ID 被意外改动: %q", row[0])
	}
	if row[3] != "high" || row[4] != "pending" {
		t.Fatalf("普通枚举文本被意外改动: %q %q", row[3], row[4])
	}
	if row[6] != "2026-11-04 10:00:00" {
		t.Fatalf("时间字段被意外改动: %q", row[6])
	}
}

// Excel 解析时前导空白不影响公式触发,csvSafe 须按 TrimSpace 后首字符判断,
// 但输出保留原文、只在最前面补单引号。
func TestCSVSafeLeadingWhitespace(t *testing.T) {
	if got := csvSafe("  =1+1"); got != "'  =1+1" {
		t.Fatalf("前导空白的公式未转义: %q", got)
	}
	if got := csvSafe("\t=cmd"); got != "'\t=cmd" {
		t.Fatalf("制表符开头的公式未转义: %q", got)
	}
	if got := csvSafe("正常文本"); got != "正常文本" {
		t.Fatalf("普通文本被意外改动: %q", got)
	}
	if got := csvSafe(""); got != "" {
		t.Fatalf("空串应原样返回: %q", got)
	}
}
