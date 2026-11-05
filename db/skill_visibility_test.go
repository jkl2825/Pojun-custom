package db

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/skill"
)

// 内置 skill 必须能被 norma 的 loader 正确加载。
//
// 为什么要测这个：skill 的 frontmatter 是 YAML，格式写错了（描述里有换行、
// 冒号没引号）会**静默**解析失败——norma 拿不到 name/description，于是
// 这个 skill 既不显示、模型也永远看不到它。而这类问题在页面上完全看不出来
// （页面的 skill 列表是 DB 侧的可见性绑定，跟文件解析是两回事）。
//
// 所以这里用 norma 真实的 LoadDir 加载仓库里的 skills/ 目录，逐个断言
// name/description 都拿到了。
func TestShippedSkillsLoadWithNormaLoader(t *testing.T) {
	skillDir := shippedSkillDir(t)
	reg, err := skill.LoadDir(skillDir)
	if err != nil {
		t.Fatalf("加载 skill 目录失败: %v", err)
	}
	all := reg.List()
	if len(all) == 0 {
		t.Fatal("一个 skill 都没加载到")
	}
	for _, s := range all {
		if strings.TrimSpace(s.Name) == "" {
			t.Errorf("skill 缺少 name（frontmatter 解析失败）")
		}
		if strings.TrimSpace(s.Description) == "" {
			t.Errorf("skill %q 缺少 description——模型靠它判断要不要调用", s.Name)
		}
	}
}

// vuln-hunting 必须能被加载，且描述里说清「什么时候用」——
// 描述是模型决定「要不要点开这个 skill」的唯一依据。
func TestVulnHuntingSkillIsLoadable(t *testing.T) {
	skillDir := shippedSkillDir(t)
	reg, err := skill.LoadDir(skillDir)
	if err != nil {
		t.Fatalf("加载 skill 目录失败: %v", err)
	}
	var found *skill.Skill
	for _, s := range reg.List() {
		if s.Name == "vuln-hunting" {
			cp := s
			found = &cp
			break
		}
	}
	if found == nil {
		t.Fatal("vuln-hunting skill 未被加载——frontmatter 解析失败或目录名不对")
	}
	// 描述必须包含「什么时候用」的触发线索，否则模型不会想到用它。
	for _, want := range []string{"挖掘", "漏洞"} {
		if !strings.Contains(found.Description, want) {
			t.Errorf("vuln-hunting 的描述缺少 %q: %s", want, found.Description)
		}
	}
}

// vuln-hunting 的 reference.md 必须在 skill 目录里——SKILL.md 里引用了它，
// 缺了会让 agent 按需展开时找不到内容。
func TestVulnHuntingHasReferenceFile(t *testing.T) {
	skillDir := shippedSkillDir(t)
	p := filepath.Join(skillDir, "vuln-hunting", "reference.md")
	if _, err := os.Stat(p); err != nil {
		t.Errorf("vuln-hunting/reference.md 缺失: %v", err)
	}
}

// vuln-hunting 必须绑定给 planner 与 worker——
// planner 决定派不派「挖未知漏洞」的意图，worker 执行时需要方法论。
func TestVulnHuntingVisibilityBound(t *testing.T) {
	agents, ok := builtinSkillVisibility["vuln-hunting"]
	if !ok {
		t.Fatal("vuln-hunting 没有可见性绑定——谁都用不到它")
	}
	has := func(k string) bool {
		for _, a := range agents {
			if a == k {
				return true
			}
		}
		return false
	}
	if !has("planner") {
		t.Error("vuln-hunting 未绑给 planner——它没法据此派挖掘类意图")
	}
	if !has("worker") {
		t.Error("vuln-hunting 未绑给 worker——它执行挖掘意图时看不到方法论")
	}
}

// shippedSkillDir 定位仓库里的 skills/ 目录。
//
// 测试在 db 包里跑，而 skills/ 在仓库根——用相对路径往上找。
func shippedSkillDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		cand := filepath.Join(dir, "skills")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("找不到仓库的 skills/ 目录")
	return ""
}

// 新增的内置 skill 必须在升级时自动绑定——不能让用户手动去页面里开。
//
// seedBuiltinSkillVisibility 没有 flag 门控，每次启动都跑，靠 ON CONFLICT
// DO NOTHING 区分两种情况：
//   - 新 skill（无冲突行）→ 插入绑定，升级即生效；
//   - 已有 skill（有冲突行）→ 保留用户的开关状态，不复活用户的「关」。
//
// 这条测试锁住「新增 skill 会进 builtinSkillVisibility 表」这个前提——
// 漏了就意味着新 skill 永远没人用。
func TestNewBuiltinSkillsAreBoundByDefault(t *testing.T) {
	// 每个 skill 至少要绑给一个 agent，否则它不会出现在任何 agent 的工具里。
	for name, agents := range builtinSkillVisibility {
		if len(agents) == 0 {
			t.Errorf("内置 skill %q 没有绑定任何 agent", name)
		}
	}
	// vuln-hunting 必须在内置表里（而不是只存在于文件里）。
	if _, ok := builtinSkillVisibility["vuln-hunting"]; !ok {
		t.Error("vuln-hunting 不在 builtinSkillVisibility 里——升级后不会自动绑定，没人用得了")
	}
	// 反向：表里的 skill 名必须都有对应的目录（否则绑了也没文件可加载）。
	skillDir := shippedSkillDir(t)
	for name := range builtinSkillVisibility {
		p := filepath.Join(skillDir, name, "SKILL.md")
		if _, err := os.Stat(p); err != nil {
			t.Errorf("内置 skill %q 有绑定但没有文件: %v", name, err)
		}
	}
}

// 守门测试（v0.4.56）：仓库里发布的每个 skill 都必须有默认可见性绑定，
// 否则它「存在但没人看得到」——这正是用户在 2026-11-05 反馈的问题：
// redteam-ops / playwright-cli 等写了却从未绑定给任何 agent。
//
// 例外必须显式列在这里并写明原因，新增 skill 忘记绑定会直接红。
func TestEveryShippedSkillIsBoundOrExplicitlyOptOut(t *testing.T) {
	optOut := map[string]string{
		"scopesentry": "依赖外部 ScopeSentry MCP 配置，按需开启",
	}
	dirs, err := os.ReadDir(filepath.Join("..", "skills"))
	if err != nil {
		t.Skip("找不到 skills 目录")
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		name := d.Name()
		if _, ok := optOut[name]; ok {
			continue
		}
		if len(builtinSkillVisibility[name]) == 0 {
			t.Errorf("skill %q 没有默认可见性绑定（也没在 optOut 里说明原因）——写了没人看得到", name)
		}
	}
	// 反向：绑定表里的 key 必须真有这个 skill 目录（防改名后旧 key 悬空）。
	for name := range builtinSkillVisibility {
		if _, err := os.Stat(filepath.Join("..", "skills", name, "SKILL.md")); err != nil {
			t.Errorf("可见性绑定的 skill %q 不存在于 skills/ 目录", name)
		}
	}
}

// src-hunting 是 SRC 场景的知识库入口：references/ 与 rules/ 必须随包完整分发，
// 否则 SKILL.md 里的索引全是死链（模型打开文件失败，方法论就用不起来）。
func TestSrcHuntingSkillShipsKnowledgeBase(t *testing.T) {
	base := filepath.Join("..", "skills", "src-hunting")
	entries, err := os.ReadDir(filepath.Join(base, "references"))
	if err != nil {
		t.Fatalf("src-hunting references 目录缺失: %v", err)
	}
	md := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			md++
			if info, err := e.Info(); err != nil || info.Size() < 100 {
				t.Errorf("references/%s 为空或过小", e.Name())
			}
		}
	}
	if md < 40 {
		t.Fatalf("知识库文件数 %d，少于预期 40+（分发不完整）", md)
	}
	rules, err := os.ReadDir(filepath.Join(base, "rules"))
	if err != nil {
		t.Fatalf("src-hunting rules 目录缺失: %v", err)
	}
	if len(rules) < 10 {
		t.Fatalf("规则文件数 %d，少于预期 10+", len(rules))
	}
	// 入口必读文件
	for _, f := range []string{"打穿短表.md", "recon-methodology.md"} {
		if _, err := os.Stat(filepath.Join(base, "references", f)); err != nil {
			t.Errorf("缺少入口文件 references/%s", f)
		}
	}
}
