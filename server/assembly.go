package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/norma/skill"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/traffic"
)

// wireAgentAugment connects the PG agent_visibility table into the agent runtime:
// an agent's visible skills are loaded from the filesystem and packed into one
// Skill meta-tool; its visible stdio MCP servers are spawned and expanded to
// mcp__server__tool. skillDir is the root directory of all skill subdirectories.
// hostTools, if set, returns runtime host tools (currently the traffic tools when
// capture is on) to add to EVERY agent's base list — the DB tools table then
// filters them per-agent binding. Empty/nil → no host tools this run (capture off).
func wireAgentAugment(pg *db.DB, skillDir string, hostTools func() ([]actool.CoreTool, map[string][]string)) {
	agent.ToolAugment = func(ctx context.Context, agentKey string) ([]actool.CoreTool, agent.DeferredInfo, func()) {
		a, err := pg.GetAgentByKey(agentKey)
		if err != nil || a == nil {
			return nil, agent.DeferredInfo{}, nil
		}
		var extra []actool.CoreTool

		// --- skills: load visible skills into reg (used for the Skill meta-tool
		// and to know which MCP servers are skill-gated). ---
		var reg *skill.Registry
		if names, _ := pg.AgentSkillNames(a.ID); len(names) > 0 {
			nameSet := make(map[string]bool, len(names))
			for _, n := range names {
				nameSet[n] = true
			}
			if allReg, err := skill.LoadDir(skillDir); err == nil && allReg != nil {
				reg = skill.NewRegistry()
				for _, s := range allReg.List() {
					// match by directory name (Base of Dir), not by skill display Name
					if s.Dir != "" && nameSet[filepath.Base(s.Dir)] {
						reg.Add(s)
					}
				}
				if len(reg.List()) == 0 {
					reg = nil
				}
			}
		}
		// A server named by any visible skill's `mcps:` is skill-gated: its tools
		// are deferred + locked (not in the global block) until that skill loads.
		gated := map[string]bool{}
		if reg != nil {
			for _, s := range reg.List() {
				for _, srv := range s.MCPs {
					gated[srv] = true
				}
			}
		}

		// --- mcp: connect enabled servers that are directly visible to this agent
		// OR skill-gated (named in a visible skill's mcps field). Directly-visible
		// and NOT gated → global (unlocked from session start). Skill-gated →
		// deferred until that skill is invoked (regardless of direct visibility).
		var closers []io.Closer
		serverTools := map[string][]string{} // server name → its tool names
		var allNames, globalNames []string
		globalSet := map[string]bool{}
		{
			mcpIDs, _ := pg.AgentVisible(a.ID, "mcp")
			want := idSet(mcpIDs)
			all, _ := pg.ListMCP()
			for _, m := range all {
				if !m.Enabled {
					continue
				}
				directVisible := want[m.ID]
				skillGated := gated[m.Name]
				if !directVisible && !skillGated {
					continue // neither directly visible nor referenced by a visible skill
				}
				// 连接失败短期不重试：wireAgentAugment 每个 agent run 都会走一遍，
				// 一个「本机没装 node」的 MCP（典型：browser 用 npx 启动）会在每个
				// worker 启动时刷一条错误，几十轮下来日志全是它，真正的问题被淹掉。
				// 失败后 10 分钟内直接跳过；期间照常打一条（首次）日志。
				if until, bad := mcpFailedUntil(m.Name); bad && time.Now().Before(until) {
					continue
				}
				cl, err := connectMCP(ctx, m)
				if err != nil {
					log.Printf("[mcp] %s 连接失败: %v（10 分钟内不再重试）", m.Name, err)
					markMCPFailed(m.Name, 10*time.Minute)
					continue
				}
				clearMCPFailure(m.Name) // 连上了：清掉失败记录，下轮照常重连
				closers = append(closers, cl)
				ts, err := cl.Tools(ctx)
				if err != nil {
					log.Printf("[mcp] %s tools/list 失败: %v", m.Name, err)
					continue
				}
				for _, t := range ts {
					extra = append(extra, t)
					allNames = append(allNames, t.Name())
					serverTools[m.Name] = append(serverTools[m.Name], t.Name())
					if directVisible && !skillGated {
						// directly visible and not gated → available from session start
						globalNames = append(globalNames, t.Name())
						globalSet[t.Name()] = true
					}
					// skill-gated tools stay out of globalNames; unlocked via unlockSkill()
				}
			}
		}

		// Shared call-gate: global MCP tools are unlocked from the start; skill-gated
		// ones are unlocked when their skill loads (or replayed from history — C2).
		unlock := actool.NewUnlockSet(globalNames...)
		unlockSkill := func(skillName string) {
			if reg == nil {
				return
			}
			if s, ok := reg.Get(skillName); ok {
				for _, srv := range s.MCPs {
					unlock.Add(serverTools[srv]...)
				}
			}
		}

		// Skill meta-tool: on load, unlock the skill's MCPs and reveal their names
		// (the ones not already in the global block).
		if reg != nil {
			reg.OnInvoke = func(s skill.Skill) string {
				unlockSkill(s.Name)
				var reveal []string
				for _, srv := range s.MCPs {
					for _, n := range serverTools[srv] {
						if !globalSet[n] {
							reveal = append(reveal, n)
						}
					}
				}
				return actool.RenderDeferredToolsBlock(reveal)
			}
			// Attribution for the usage ledger: ToolAugment only gets (ctx, agentKey),
			// so the run's task/session ids ride in on the ctx (agent.RunInfo). Read it
			// once here — this closure is rebuilt per run, so the captured value always
			// belongs to this run.
			extra = append(extra, meterSkillTool(reg.Tool(), pg, reg, a.Key, agent.RunInfoFrom(ctx)))
		}

		// host tools (traffic / orchestration / custom) — added to every agent's base;
		// ToolResolve then keeps them only for agents the tool is bound to. Custom
		// tools flagged deferred contribute their names to the deferred wiring so
		// their schema is withheld (SearchExtraTools/ExecuteExtraTool), same as MCP.
		if hostTools != nil {
			ht, deferredBinds := hostTools()
			extra = append(extra, ht...)
			for name, boundAgents := range deferredBinds {
				if !contains(boundAgents, a.Key) {
					continue // only defer names this agent is actually bound to
				}
				allNames = append(allNames, name)       // schema withheld from the prompt
				globalNames = append(globalNames, name) // advertised in the deferred block
				globalSet[name] = true
				if unlock != nil {
					unlock.Add(name) // global deferred → callable from the start
				}
			}
		}

		cleanup := func() {
			for _, c := range closers {
				_ = c.Close()
			}
		}
		def := agent.DeferredInfo{
			Deferred:    allNames,
			GlobalNames: globalNames,
			Unlock:      unlock,
			UnlockSkill: unlockSkill,
		}
		return extra, def, cleanup
	}
}

func idSet(ids []int64) map[int64]bool {
	m := make(map[int64]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

// seedPrompts writes each built-in agent's code-default prompt body into
// agent_prompts on startup — first-insert only (SeedPromptIfEmpty is a no-op once
// any version exists), so the DB becomes the authoritative editable source while
// user edits survive restarts. Runs after seedBuiltins has created the agent rows.
func seedPrompts(pg *db.DB) {
	for key, tmpl := range agent.BuiltinPromptSeeds() {
		a, err := pg.GetAgentByKey(key)
		if err != nil || a == nil {
			log.Printf("[prompts] seed %s 跳过: agent 不存在 (%v)", key, err)
			continue
		}
		upgraded, err := pg.SeedPromptVersioned(a.ID, tmpl)
		if err != nil {
			log.Printf("[prompts] seed %s 失败: %v", key, err)
			continue
		}
		if upgraded {
			// 内置提示词的改进现在能随版本下发；用户手改过的（updated_by != system）不受影响。
			log.Printf("[prompts] %s 内置提示词已同步到当前版本", key)
		}
	}
}

// wireTools seeds the built-in tool catalog (idempotent, first-insert only so page
// edits survive restart) and wires the DB tools table into the agent runtime: at
// tool-assembly time each built-in tool is filtered by its agent binding / enabled
// flag and, if kept, wrapped so the model sees the DB-overridden description/schema
// and缺省入参 get injected. MCP/skill/host tools have no row and pass through.
func wireTools(pg *db.DB, domainReg map[string]actool.CoreTool) {
	agent.FindingTrafficBindingEnabled = func() bool { return pg.GetBool(settingAgentTrafficBinding, false) }
	// 证据附件列表（v0.4.9）：agent 的 list_artifacts 工具读取本任务已登记附件。
	agent.ListTaskArtifacts = func(taskID string) ([]db.TaskArtifact, error) { return pg.ListTaskArtifacts(taskID) }
	// reporter 的 chat 会话没有任务上下文（v0.4.20）：允许工具按 finding_id
	// 反查所属任务，避免 list_artifacts 永远返回空。
	agent.FindingTaskID = func(findingID int64) (string, error) {
		f, err := pg.GetFinding(findingID)
		if err != nil {
			return "", err
		}
		if f == nil || f.TaskID == nil {
			return "", fmt.Errorf("finding %d 无所属任务", findingID)
		}
		return strconv.FormatInt(*f.TaskID, 10), nil
	}
	// reporter 需要看附件清单来引用截图（worker 由 builtinToolsByAgent 自动绑定）。
	if err := pg.AddAgentToToolBinding("reporter", []string{"list_artifacts"}); err != nil {
		log.Printf("[tools] reporter 绑定 list_artifacts 失败: %v", err)
	}
	// Seed the built-in domain tools (first-insert only; DO NOTHING preserves edits).
	// No startup prune: rows we didn't seed are left alone so future user-defined
	// custom tools (system=false, added via the UI) survive restarts.
	for _, s := range agent.BuiltinToolSeeds() {
		schema, _ := json.Marshal(s.Schema)
		agents, _ := json.Marshal(s.Agents)
		if err := pg.SeedTool(s.Key, s.Desc, schema, agents); err != nil {
			log.Printf("[tools] seed %s 失败: %v", s.Key, err)
		}
	}
	if err := seedWorkerReadOnlyToolsV054(pg); err != nil {
		log.Printf("[tools] worker 只读工具绑定迁移失败: %v", err)
	}
	if err := seedDispatchSchemaV1(pg); err != nil {
		log.Printf("[tools] 协作可选参数迁移失败: %v", err)
	}
	// Seed the traffic host tools so they're bindable per-agent like built-ins.
	// Default binding = worker (preserves prior behavior). Their runtime availability
	// is still gated by the global capture switch (hostTools() returns them only when
	// capture is on), so an off-capture binding simply never surfaces the tool.
	trafficAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range traffic.SeedToolMetas() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := pg.SeedTool(t.Name(), t.Description(), schema, trafficAgents); err != nil {
			log.Printf("[tools] seed %s 失败: %v", t.Name(), err)
		}
	}
	// bashInteractiveShellNote is appended to Bash's description ONLY for agents whose
	// interactive_shell is on, so Bash points at shell_open for interactive programs
	// without ever referencing a tool that isn't injected (§14.1/§14.2).
	const bashInteractiveShellNote = "\n\n需要【交互输入】的程序（msfconsole / ssh 交互登录 / mysql、psql、python 等 REPL / 密码或 yes/no 提示 / nc 反弹 shell）不要用 Bash（它没有 stdin、会卡住），改用 shell_open 开交互会话（用完 shell_close）。一次性、非交互命令仍用 Bash。"
	agent.ToolResolve = func(ctx context.Context, agentKey string, tools []actool.CoreTool) []actool.CoreTool {
		rows, err := pg.ListTools()
		if err != nil {
			log.Printf("[tools] 读取工具表失败，按代码默认放行: %v", err)
			return tools
		}
		byKey := make(map[string]*db.Tool, len(rows))
		for _, t := range rows {
			byKey[t.Key] = t
		}
		runInfo := agent.RunInfoFrom(ctx)
		resolve := func(t actool.CoreTool, row *db.Tool) actool.CoreTool {
			var schema map[string]any
			if len(row.Schema) > 0 {
				_ = json.Unmarshal(row.Schema, &schema)
			}
			return meterTool(agent.DecorateTool(t, row.Description, schema), pg, row.Key, agentKey, runInfo)
		}
		out := tools[:0:0]
		for _, t := range tools {
			row, known := byKey[t.Name()]
			if !known { // MCP/skill/host tool: no row → untouched
				out = append(out, t)
				continue
			}
			if !row.Enabled || !contains(row.Agents, agentKey) {
				continue // disabled globally or not bound to this agent → drop
			}
			out = append(out, resolve(t, row))
		}
		// inject: domain tools bound to this agent in the DB but absent from the
		// incoming list. Covers agents (Auto, custom) whose base only has DefaultTools
		// and therefore never includes ToolSet-backed domain tools. Per-task instances
		// in the base always win: inList is built from the original incoming list so a
		// worker's own upsert_asset is never shadowed by the server-level registry copy.
		if len(domainReg) > 0 {
			inList := make(map[string]bool, len(tools))
			for _, t := range tools {
				inList[t.Name()] = true
			}
			for _, row := range rows {
				if row.Kind == "shell" || !row.Enabled || !contains(row.Agents, agentKey) || inList[row.Key] {
					continue
				}
				inst, ok := domainReg[row.Key]
				if !ok {
					continue // not a domain tool; custom/host tools are injected via hostTools()
				}
				out = append(out, resolve(inst, row))
			}
		}
		// 该 agent 的运行配置：本地执行开关 + 交互式 shell。两者都在这里取一次。
		ag, _ := pg.GetAgentByKey(agentKey)
		// localExec 默认 true：取不到 agent 行时按「不禁」处理，绝不因为一次查询失败就把
		// worker/planner 的 Bash 摘掉（那会让整个任务跑不动）。
		localExec := ag == nil || ag.LocalExec
		// 关掉本地执行 = 摘掉执行类工具。Bash/Write/Edit 这些是 SDK DefaultTools，**没有
		// tools 表行**，ToolResolve 那条「未绑定即丢弃」管不到它们（rows 里查不到 → 直接
		// 放行），所以只能在这里显式摘。摘完剩下只读检查类（Read/LS/Glob/Grep）+ 平台工具，
		// 于是 auto 这类编排 agent 想把事情做成，只剩「派任务」一条路——这正是设计意图：
		// 实测给 Auto 留着 Bash 时，它在对话里直接写 Python 扫描器把网段扫穿了，一个任务
		// 都没建（用户反馈的「他不派发任务、一直自己执行」就是这个）。
		if !localExec {
			out = agent.DropLocalExecTools(out)
		}
		// shell hints: user-defined kind="shell" tools are not callable — they are
		// environment declarations that tell the model which command-line tools are
		// installed. Collect the ones bound to this agent and append to Bash's description.
		var shellHints []string
		for _, row := range rows {
			if row.Kind == "shell" && row.Enabled && contains(row.Agents, agentKey) {
				shellHints = append(shellHints, "- "+row.Key+": "+row.Description)
			}
		}
		// 三段补丁都挂在 Bash 的 description 上：本机网络能力(按 euid/能力位实时判定)、
		// 已装命令行工具、交互式 shell 指引。Bash 已被摘掉的 agent 自然什么都看不到——
		// 否则描述会残留「你可以跑命令」的暗示，与工具集自相矛盾。
		interactive := !actool.InteractiveShellDisabled() && ag != nil && ag.InteractiveShell
		var bashNote string
		if localExec {
			bashNote = agent.EnvCapabilityNote()
			if len(shellHints) > 0 {
				bashNote += "\n\n以下工具已安装在此 bash 环境中，可直接通过 Bash 调用：\n" + strings.Join(shellHints, "\n")
			}
			if interactive {
				bashNote += bashInteractiveShellNote
			}
		}
		if bashNote != "" {
			for i, t := range out {
				if t.Name() == "Bash" {
					out[i] = agent.DecorateTool(t, t.Description()+bashNote, t.InputSchema())
					break
				}
			}
		}
		// interactive shell: gated purely by the agent's interactive_shell flag (like
		// web_search), NOT by tools-table binding. When on, inject the 5 shell_* tools
		// and COUPLE the Bash description addendum so it points at shell_open — and never
		// dangles when off. See docs/交互式shell设计.md §14.2.
		// 本地执行关掉时也一并关掉：PTY 会话等价于给了一条不受管的命令执行通道。
		if localExec && interactive {
			out = append(out, actool.ShellSessionTools()...)
		}
		return out
	}
}

// 仅迁移新增的只读绑定；成功后不再恢复用户主动移除的 worker 绑定。
func seedWorkerReadOnlyToolsV054(pg *db.DB) error {
	const flag = "worker_read_only_tools_v054"
	value, _, err := pg.GetSetting(flag)
	if err != nil {
		return err
	}
	if value == "true" {
		return nil
	}
	keys := []string{"expand_digest", "list_untested_assets", "list_goals"}
	for _, key := range keys {
		tool, err := pg.GetTool(key)
		if err != nil {
			return err
		}
		if tool == nil || !tool.System || tool.Kind != "builtin" {
			return fmt.Errorf("只读工具 %s 不是已登记的系统内置工具", key)
		}
	}
	if err := pg.AddAgentToToolBinding("worker", keys); err != nil {
		return err
	}
	return pg.SetSetting(flag, "true")
}

// Add only optional code-defined fields. Never replace a user's descriptions,
// defaults, required set, bindings or enabled flag on an already-seeded tool.
func seedDispatchSchemaV1(pg *db.DB) error {
	const flag = "downstream_dispatch_schema_v1"
	if value, _, err := pg.GetSetting(flag); err != nil {
		return err
	} else if value == "true" {
		return nil
	}
	var properties map[string]json.RawMessage
	for _, seed := range agent.BuiltinToolSeeds() {
		if seed.Key != "add_intent" {
			continue
		}
		raw, err := json.Marshal(seed.Schema)
		if err != nil {
			return err
		}
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(raw, &schema); err != nil {
			return err
		}
		properties = schema.Properties
	}
	keys := []string{"collaborates_with", "collaboration_angle", "briefing_ids"}
	for _, key := range keys {
		if len(properties[key]) == 0 {
			return fmt.Errorf("missing dispatch property %s", key)
		}
	}
	tx, err := pg.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	if err := tx.QueryRow(`SELECT schema FROM tools WHERE key='add_intent' AND system AND kind='builtin' FOR UPDATE`).Scan(&raw); err != nil {
		return err
	}
	var stored map[string]json.RawMessage
	if err := json.Unmarshal(raw, &stored); err != nil {
		return err
	}
	if len(stored["properties"]) == 0 || string(stored["properties"]) == "null" {
		if _, err := tx.Exec(`UPDATE tools SET schema=jsonb_set(schema,'{properties}','{}'::jsonb,true) WHERE key='add_intent' AND system`); err != nil {
			return err
		}
	} else {
		var existing map[string]json.RawMessage
		if err := json.Unmarshal(stored["properties"], &existing); err != nil {
			return err
		}
	}
	for _, key := range keys {
		if _, err := tx.Exec(`UPDATE tools SET schema=jsonb_set(schema,ARRAY['properties',$1::text],$2::jsonb,true),updated_at=now()
		WHERE key='add_intent' AND system AND NOT(COALESCE(schema->'properties','{}'::jsonb) ? $1)`, key, string(properties[key])); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES($1,'true') ON CONFLICT(key) DO UPDATE SET value='true',updated_at=now()`, flag); err != nil {
		return err
	}
	return tx.Commit()
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

// buildDomainReg builds a name→CoreTool registry from a server-level ToolSet
// (real AssetStore, nil ExplorationStore, taskID=0). Used by ToolResolve to inject
// domain tools into agents (Auto, custom) that don't own a per-task ToolSet.
// nil as → returns nil (no injection, graceful degradation).
//
// The nil ExplorationStore is deliberate — these instances are task-less by
// construction — so every tool here must tolerate it. Asset/company tools do
// (they only need the AssetStore); the exploration-graph tools refuse with a
// clear message via ToolSet.needExploration. Binding one of them to a task-less
// agent in the tools table is therefore a useless tool, not a crash.
func buildDomainReg(as *db.AssetStore) map[string]actool.CoreTool {
	if as == nil {
		return nil
	}
	serverTS := agent.NewToolSet(nil, "")
	serverTS.SetAssetStore(as, as.Companies())
	reg := make(map[string]actool.CoreTool)
	for _, t := range serverTS.AllDomainTools() {
		reg[t.Name()] = t
	}
	return reg
}

func jsonStrSlice(raw json.RawMessage) []string {
	var out []string
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func jsonStrMap(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}
