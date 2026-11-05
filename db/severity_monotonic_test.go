package db

import "testing"

// TestHigherSeverity 锁住「严重度只升不降」。
//
// 背景：同一 fingerprint 二次确认时原实现无条件覆盖 severity，先报 high
// 后被 medium 复核就会静默降级，交付物定级随上报顺序漂移，且没有任何留痕。
func TestHigherSeverity(t *testing.T) {
	cases := []struct{ a, b, want string }{
		{"high", "medium", "high"},       // 高不被低覆盖
		{"medium", "high", "high"},       // 低可被高抬升
		{"critical", "high", "critical"}, // 最高档不被降
		{"", "medium", "medium"},         // 原值为空 → 采用新值
		{"high", "", "high"},             // 新值为空 → 保留原值
		{"HIGH", "medium", "HIGH"},       // 大小写不敏感，保留原写法
		{"unknown", "low", "low"},        // 未知值视为最低
	}
	for _, c := range cases {
		if got := higherSeverity(c.a, c.b); got != c.want {
			t.Errorf("higherSeverity(%q, %q) = %q，期望 %q", c.a, c.b, got, c.want)
		}
	}
}
