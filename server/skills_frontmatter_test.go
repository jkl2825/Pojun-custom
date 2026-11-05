package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRepoSkillsHaveFrontmatter 守住 skill 的 YAML 头。
//
// 为什么需要这条用例：上游 v0.4.54 重写 SKILL.md 时删掉了 frontmatter，导致
// 这些 skill 在运行时**静默不加载**——不报错、不告警，只是能力消失
// （仓库里已有 fbdd80e 这个补丁在补它）。每次拉上游都可能重演，所以用测试卡住：
// 缺头、YAML 不合法、缺 name/description、name 与目录名不一致，四种都算失败。
func TestRepoSkillsHaveFrontmatter(t *testing.T) {
	dir := filepath.Join("..", "skills")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("skills 目录不存在（%v）——单包二进制构建时跳过", err)
	}
	checked := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name(), "SKILL.md")
		raw, err := os.ReadFile(p)
		if err != nil {
			continue // 该目录没有 SKILL.md，不是 skill
		}
		head, ok := frontmatterHead(string(raw))
		if !ok {
			t.Errorf("%s：缺少 YAML frontmatter（--- 包裹）——skill 会静默不加载", p)
			continue
		}
		var fm struct {
			Name        string `yaml:"name"`
			Description string `yaml:"description"`
		}
		if err := yaml.Unmarshal([]byte(head), &fm); err != nil {
			t.Errorf("%s：frontmatter 不是合法 YAML: %v", p, err)
			continue
		}
		if strings.TrimSpace(fm.Name) == "" || strings.TrimSpace(fm.Description) == "" {
			t.Errorf("%s：frontmatter 缺 name 或 description（name=%q）", p, fm.Name)
			continue
		}
		// 特意**不**断言 name == 目录名：系统明确支持两者不同。
		// 证据：server/assembly.go:47 按目录名匹配可见性（"match by directory name
		// (Base of Dir), not by skill display Name"）；server/skill_usage.go:61 注释
		// 也写了 "a skill's display Name can differ from its directory"。
		// 实例：skills/scopesentry 的 name 是 scopesentry-mcp，属于设计内形态。
		checked++
	}
	if checked == 0 {
		t.Skip("skills 目录下没有可检查的 skill")
	}
	t.Logf("检查了 %d 个 skill 的 frontmatter", checked)
}

// TestGoallessDoneSummaryDistinguishesBlocked 锁住收尾播报的语义。
//
// 场景：阶梯 L4 把所有在跑意图停放成 blocked 后，HasActiveIntent 转 false，
// engine 的 goalless 分支会直接落 done。此时播报不能说「目标已全部达成」。
func TestGoallessDoneSummaryDistinguishesBlocked(t *testing.T) {
	all := goallessDoneSummary(0)
	if !strings.Contains(all, "全部达成") {
		t.Fatalf("没有 blocked 时应播报达成，实际: %q", all)
	}
	some := goallessDoneSummary(3)
	if strings.Contains(some, "全部达成") {
		t.Fatalf("存在 blocked 时不得播报「全部达成」，实际: %q", some)
	}
	if !strings.Contains(some, "3") || !strings.Contains(some, "blocked") {
		t.Fatalf("应说明有多少条被 blocked，实际: %q", some)
	}
}
