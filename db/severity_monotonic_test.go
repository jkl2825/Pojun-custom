package db

import "testing"

// TestResolveSeverity 锁住「定级默认沿用原值、冲突只报告不改写」。
//
// 背景（2026-11-05，身份包对照分析）：去重路径原实现无条件用本次上报覆盖
// severity，先报 high 后被 medium 复核会静默降级、无留痕。
//
// 但「只升不降」同样是错的：首报 high 定错、二次确认发现应为 medium 时，
// 正当更正会被挡死。定级的真源是报告正文，这里不替人裁决——保留原值，
// 把冲突交给调用方写进证据，由人/planner 显式修改。
func TestResolveSeverity(t *testing.T) {
	cases := []struct {
		name             string
		current, coming  string
		wantSev          string
		wantConflictFlag bool
	}{
		{"降级不自动执行", "high", "medium", "high", true},
		{"升级也不自动执行", "medium", "high", "medium", true},
		{"首次定级直接采用", "", "medium", "medium", false},
		{"本次为空则沿用原值", "high", "", "high", false},
		{"大小写不同视为同级", "HIGH", "high", "HIGH", false},
		{"未知值与正常值冲突", "unknown", "low", "unknown", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sev, conflict := resolveSeverity(c.current, c.coming)
			if sev != c.wantSev || conflict != c.wantConflictFlag {
				t.Fatalf("resolveSeverity(%q, %q) = (%q, %v)，期望 (%q, %v)",
					c.current, c.coming, sev, conflict, c.wantSev, c.wantConflictFlag)
			}
		})
	}
}
