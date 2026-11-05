// Package db is the PostgreSQL data source for POJUN (取代旧 graph 单文件 SQLite)。
// 它打开连接、应用 schema、并 seed 内置 agent 与变量目录。
package db

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/chu0119/pojun/config"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver ("pgx")
)

//go:embed schema.sql
var schemaSQL string

const schemaMigrationLockKey int64 = 7337741001

// maxOpenConns 是连接池上限，见 Open 里的说明。取值远低于 PostgreSQL 默认的
// max_connections=100，同时远高于应用自身的嵌套取连接深度（启动期的 schema
// advisory lock 会在持有一条连接的同时让 seedBuiltins 另取连接），不会自锁。
const maxOpenConns = 32

var schemaDeadlockRetryDelays = [...]time.Duration{
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
}

type schemaExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func isPostgresDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}

func applySchemaWithRetry(ctx context.Context, execer schemaExecer, sleep func(time.Duration)) error {
	for attempt := 0; ; attempt++ {
		if _, err := execer.ExecContext(ctx, schemaSQL); err != nil {
			if !isPostgresDeadlock(err) || attempt >= len(schemaDeadlockRetryDelays) {
				return err
			}
			sleep(schemaDeadlockRetryDelays[attempt])
			continue
		}
		return nil
	}
}

// withSchemaMigrationLock pins the session-level lock to one checked-out
// connection. Running pg_advisory_lock through *sql.DB is incorrect because a
// later schema or unlock call may use a different pooled PostgreSQL session.
func withSchemaMigrationLock(ctx context.Context, sqlDB *sql.DB, action func(*sql.Conn) error) (err error) {
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	defer func() {
		if _, unlockErr := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, schemaMigrationLockKey); unlockErr != nil && err == nil {
			err = fmt.Errorf("advisory unlock: %w", unlockErr)
		}
	}()
	return action(conn)
}

// coordinateWithSchemaMigration makes long, multi-table archive transactions
// mutually exclusive with startup DDL while allowing ordinary runtime queries
// to continue normally.
func coordinateWithSchemaMigration(tx *sql.Tx) error {
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("coordinate with schema migration: %w", err)
	}
	return nil
}

// DSN resolves the PostgreSQL connection string and reports where it came from.
// Precedence: env POJUN_PG_DSN > config file (config.json). There is no
// built-in default — it errors if neither source is configured.
func DSN() (dsn, source string, err error) {
	return config.PostgresDSN()
}

// DB wraps the shared *sql.DB. PG handles its own connection pool + concurrency
// (MVCC), so unlike the old SQLite store there is no process-wide write mutex.
type DB struct{ *sql.DB }

// ensureDatabase connects to the postgres system database and creates the target
// database if it does not exist. dsn must be a postgres:// URL.
func ensureDatabase(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil // unparseable DSN — let the normal Open fail with a clear error
	}
	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" || dbName == "postgres" {
		return nil
	}
	// connect to the postgres maintenance database instead
	adminDSN := *u
	adminDSN.Path = "/postgres"
	admin, err := sql.Open("pgx", adminDSN.String())
	if err != nil {
		return nil // best-effort; let Open surface the real error
	}
	defer admin.Close()
	if err := admin.Ping(); err != nil {
		return nil
	}
	var exists bool
	_ = admin.QueryRow(`SELECT true FROM pg_database WHERE datname=$1`, dbName).Scan(&exists)
	if !exists {
		if _, err := admin.Exec(`CREATE DATABASE "` + dbName + `"`); err != nil {
			return fmt.Errorf("create database %q: %w", dbName, err)
		}
	}
	return nil
}

// Open connects, applies the schema (idempotent), and seeds builtin rows.
func Open(dsn string) (*DB, error) {
	if err := ensureDatabase(dsn); err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	// database/sql 默认不限制连接数：池里没有空闲连接时会无条件新建，一路顶到
	// PostgreSQL 的 max_connections（默认 100）才被拒，于是高峰期的查询拿到的是
	// `FATAL: sorry, too many clients already` 这种**错误**。封顶之后超额查询改为
	// 排队等待空闲连接——同样的负载下变成变慢而不是报错，调用方不必再去区分
	// "读不到"和"没有"。maxOpenConns 要留出余量给 psql / reset-password.sh 以及
	// 可能并存的其他实例；若 max_connections 调低过，这里也要跟着往下调。
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxOpenConns)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping postgres (%s): %w", config.Redact(dsn), err)
	}
	d := &DB{sqlDB}
	// pgx runs multi-statement Exec via the simple protocol when there are no args.
	// Keep the dedicated lock connection checked out until both DDL and seeding
	// finish so concurrent application instances cannot initialize out of order.
	err = withSchemaMigrationLock(context.Background(), sqlDB, func(conn *sql.Conn) error {
		if err := applySchemaWithRetry(context.Background(), conn, time.Sleep); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
		if err := d.seedBuiltins(); err != nil {
			return fmt.Errorf("seed builtins: %w", err)
		}
		return nil
	})
	if err != nil {
		sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// builtinAgent describes one of the fixed agents and its prompt-variable catalog.
type builtinAgent struct {
	key, name, role, desc string
	vars                  []promptVar
	interactiveShell      bool // 建行时的默认交互式 shell 开关；ON CONFLICT 不覆盖用户后续手动开关
	runSeconds            *int // 建行时的单次 run 墙钟上限(秒)；nil=用种子默认(1200)，0=不限时
}

type promptVar struct{ name, desc, example, source string }

// intp 返回 v 的指针，用于给 builtinAgent 可选字段(如 runSeconds)显式取值。
func intp(v int) *int { return &v }

// builtinAgents mirrors docs §5(a). 内置工具不入库；这里只 seed agent + 变量目录。
// 注：planner/worker/mainagent/auto 的交互式 shell 默认由下方 interactive_shell_default_v1
// 块统一置 true（尊重后续 toggle）；这里的 interactiveShell 只给需要「建行即默认开」的新 agent。
var builtinAgents = []builtinAgent{
	{"goals", "目标拆解", "goals", "把渗透任务目标拆解成若干独立、可验证的子目标。", []promptVar{
		{"EngagementDescription", "任务描述（测试对象/背景）", "测试 example.com 站点", "exploration"},
		// Now 是全局 runtime 变量(见 server.globalPromptVars),不再在各 agent 目录里
		// 重复定义,否则 withGlobalVars 追加时会与全局项撞名。
	}, false, nil},
	{"planner", "规划", "planner", "读取态势、判定目标，只在确有未覆盖的新方向时补充探索意图（每任务一个规划循环）。", []promptVar{
		{"Goal", "任务总目标", "拿下 example.com 的管理员权限", "exploration"},
		{"AssetSummary", "资产计数/类型分布摘要(可选)", "domain:3 ip:5 site:2", "distilled"},
	}, false, nil},
	{"mainagent", "主", "main", "人机接口：观察进展，把人的意图落成 hint 或高优先级意图。", []promptVar{
		{"Goal", "当前任务目标", "拿下 example.com 的管理员权限", "exploration"},
		{"AssetSummary", "开局态势摘要(可选)", "domain:3 ip:5", "distilled"},
		{"FindingsSummary", "已确认漏洞摘要(可选)", "high:1 medium:2", "distilled"},
	}, false, nil},
	{"worker", "执行", "worker", "领取一条意图执行，把发现的事实/漏洞写回知识图谱后停止。", []promptVar{
		{"ProxyAddr", "记录代理地址(驱动 if 双文案)", "127.0.0.1:8080", "runtime"},
		{"WorkerName", "worker 自我标识(可选)", "worker-1", "runtime"},
	}, false, nil},
	// Auto:内置「平台操作」agent。不参与渗透编排循环,经对话页驱动,用工具操作平台。
	{"auto", "Auto", "assistant", "平台操作助手：用工具管理任务(建/看/暂停/给提示)与资产，并可创建/修改 skill、自定义工具、MCP。", nil, false, nil},
	// 渗透测试:内置「独立渗透」agent。经对话页驱动,一人从侦察到收尾走完整条渗透链,自己规划自己执行自己验证。默认开启交互式 shell。
	{"pentest", "渗透测试", "assistant", "独立渗透 agent：一人从侦察→找攻击面→深入利用→验证→收尾走完整条链，自己规划、自己执行、自己对抗式验证。", nil, true, intp(0)},
}

// seedBuiltins inserts the fixed built-in agents and their variable catalog (idempotent).
func (d *DB) seedBuiltins() error {
	for _, a := range builtinAgents {
		var agentID int64
		err := d.QueryRow(`
INSERT INTO agents(key, name, description, role, builtin, enabled, interactive_shell, run_seconds)
VALUES ($1, $2, NULLIF($3,''), $4, true, true, $5, COALESCE($6, 1200))
ON CONFLICT (key) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
RETURNING id`, a.key, a.name, a.desc, a.role, a.interactiveShell, a.runSeconds).Scan(&agentID)
		if err != nil {
			return fmt.Errorf("agent %s: %w", a.key, err)
		}
		for _, v := range a.vars {
			if _, err := d.Exec(`
INSERT INTO agent_prompt_vars(agent_id, var_name, description, example, source)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (agent_id, var_name) DO UPDATE
  SET description = EXCLUDED.description, example = EXCLUDED.example, source = EXCLUDED.source`,
				agentID, v.name, v.desc, v.example, v.source); err != nil {
				return fmt.Errorf("agent %s var %s: %w", a.key, v.name, err)
			}
		}
	}
	// Drop catalog entries for variables that were renamed, so the white-list no
	// longer advertises a name templates can't resolve (EngagementTitle→Description).
	// 'Now' 从各 agent 目录提升为全局 runtime 变量后,旧库里 goals 仍残留一条 'Now'
	// 会与全局项撞名(前端变量列表 key 重复);一并清掉。
	if _, err := d.Exec(`DELETE FROM agent_prompt_vars WHERE var_name IN ('EngagementTitle', 'CoverageGaps', 'Now')`); err != nil {
		return fmt.Errorf("cleanup renamed vars: %w", err)
	}
	// Default-on interactive_shell for the runtime agents (planner/worker/mainagent/auto)
	// ONCE — respects a later user toggle-off (guarded by a settings flag). goals(one-shot
	// decomposer) stays off. Runs after the column exists (schema applied before seed).
	if v, _, _ := d.GetSetting("interactive_shell_default_v1"); v != "true" {
		if _, err := d.Exec(`UPDATE agents SET interactive_shell=true WHERE key IN ('planner','worker','mainagent','auto')`); err != nil {
			return fmt.Errorf("seed interactive_shell defaults: %w", err)
		}
		_ = d.SetSetting("interactive_shell_default_v1", "true")
	}
	// Auto 天生是「平台操作助手」:它该用 spawn_task 把渗透需求派成任务,而不是自己拿
	// Bash/Write 在机器上跑。给它 Bash 时模型几乎必然自己动手(实测:派任务后 Auto 直接
	// 写了个 Python 扫描器扫穿 10.10.0.0/16,一个任务都没建)——所以默认关掉它的本地执行。
	// 一次性 + flag 守卫:用户之后想给它开回来,重启不会再被强制关掉。
	if v, _, _ := d.GetSetting("local_exec_default_v1"); v != "true" {
		if _, err := d.Exec(`UPDATE agents SET local_exec=false WHERE key='auto'`); err != nil {
			return fmt.Errorf("seed local_exec defaults: %w", err)
		}
		_ = d.SetSetting("local_exec_default_v1", "true")
	}
	// Seed the built-in browser (Playwright) MCP once — DISABLED by default (用户
	// 需要时自行启用), no proxy by default. The traffic-capture toggle injects/strips
	// the recording proxy + CA at runtime (server.Manager.syncBrowserMCPProxy).
	// Insert only if absent so we never clobber user edits (args/env/enabled/
	// visibility) on restart.
	if _, err := d.Exec(`
INSERT INTO mcp_servers(name, transport, command, args, env, enabled)
VALUES ('browser', 'stdio', 'npx', $1, '{}', false)
ON CONFLICT (name) DO NOTHING`,
		`["@playwright/mcp","--headless"]`); err != nil {
		return fmt.Errorf("seed browser mcp: %w", err)
	}
	// NOTE: the placeholder ScopeSentry data-source MCP (empty URL + empty X-API-Key,
	// disabled) is seeded directly in schema.sql §F so a raw `psql < schema.sql` init
	// also gets it. schema.sql is Exec'd on every startup, so it stays idempotent.
	if err := d.seedBuiltinSkillVisibility(); err != nil {
		return fmt.Errorf("seed skill visibility: %w", err)
	}
	if err := d.seedDefaultInterceptRules(); err != nil {
		return fmt.Errorf("seed intercept rules: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV2(); err != nil {
		return fmt.Errorf("seed intercept rules v2: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV3(); err != nil {
		return fmt.Errorf("seed intercept rules v3: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV4(); err != nil {
		return fmt.Errorf("seed intercept rules v4: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV5(); err != nil {
		return fmt.Errorf("seed intercept rules v5: %w", err)
	}
	if err := d.migrateListenerRuleTimeout(); err != nil {
		return fmt.Errorf("migrate listener rule timeout: %w", err)
	}
	if err := d.migrateBuiltinRulePatterns(); err != nil {
		return fmt.Errorf("migrate builtin rule patterns: %w", err)
	}
	if err := d.migrateBuiltinRuleActions(); err != nil {
		return fmt.Errorf("migrate builtin rule actions: %w", err)
	}
	if err := d.migrateJudgeTimeoutSeconds(); err != nil {
		return fmt.Errorf("migrate judge timeout: %w", err)
	}
	if err := d.migrateAgentRunSeconds(); err != nil {
		return fmt.Errorf("migrate agent run seconds: %w", err)
	}
	if err := d.migrateContextWindowK(); err != nil {
		return fmt.Errorf("migrate context window k: %w", err)
	}
	if err := d.seedDefaultAssetInterceptRules(); err != nil {
		return fmt.Errorf("seed asset intercept rules: %w", err)
	}
	return nil
}

// seedDefaultAssetInterceptRules inserts the built-in asset blocklist (fuzzy
// domain matches for government / education sites) once on first startup. Gated
// by a settings flag so a user's later disable/delete is never resurrected on
// restart — same policy as the intercept-rule seed.
func (d *DB) seedDefaultAssetInterceptRules() error {
	if v, _, _ := d.GetSetting("asset_intercept_default_rules_v1"); v == "done" {
		return nil
	}
	rules := []struct {
		kind    string
		pattern string
		note    string
	}{
		{"fuzzy_domain", ".gov", "[内置] 政府网站 (.gov)"},
		{"fuzzy_domain", ".gov.cn", "[内置] 政府网站 (.gov.cn)"},
		{"fuzzy_domain", ".edu", "[内置] 教育网站 (.edu)"},
		{"fuzzy_domain", ".edu.cn", "[内置] 教育网站 (.edu.cn)"},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO asset_intercept_rules(enabled, kind, pattern, note, builtin)
VALUES (true, $1, $2, $3, true)
ON CONFLICT DO NOTHING`, r.kind, r.pattern, r.note); err != nil {
			return fmt.Errorf("asset rule %q: %w", r.pattern, err)
		}
	}
	return d.SetSetting("asset_intercept_default_rules_v1", "done")
}

// builtinSkillVisibility maps a shipped skill's directory name → the built-in
// agent keys that should see it by default. The skill FILES themselves live on the
// filesystem (SkillDir, loaded by norma at runtime); DB only carries this visibility
// binding. 绑定策略（v0.4.56 起）：执行类 skill（攻击手法/后渗透/验证/输出）
// 默认绑给 worker 与 pentest；方向类 skill（情报/侦察/0day/代码审计）另绑 planner，
// 因为「要不要往这个方向投入」是规划者的判断。scopesentry（平台集成）保持默认
// 不可见——它依赖外部 MCP 配置，用户按需开启。ON CONFLICT DO NOTHING 保证
// 用户此后的开关不会被重启复活。
var builtinSkillVisibility = map[string][]string{
	// 侦察与接口
	"api-recon":            {"auto", "pentest", "worker"},
	"attack-surface-recon": {"planner", "pentest", "worker"},
	"api-security-testing": {"pentest", "worker"},
	// 方法论与验证
	"vuln-hunting":             {"planner", "worker"},
	"web-attack-methods":       {"pentest", "worker"},
	"component-vuln-intel":     {"planner", "pentest", "worker"},
	"source-code-hunting":      {"planner", "pentest", "worker"},
	"zero-day-research":        {"planner", "pentest", "worker"},
	"pentest-verification":     {"pentest", "worker"},
	"pentest-output-standards": {"pentest", "worker"},
	// 场景专项
	"redteam-ops":              {"pentest", "worker"},
	"redteam-opsec":            {"pentest", "worker"},
	"cloud-attack-methods":     {"pentest", "worker"},
	"active-directory-attack":  {"pentest", "worker"},
	"ai-llm-app-attack":        {"pentest", "worker"},
	"binary-mobile-reversing":  {"pentest", "worker"},
	"smart-contract-audit":     {"pentest", "worker"},
	"wireless-hardware-attack": {"pentest", "worker"},
	// SRC 方法论库（48 篇知识库 + 11 篇规则）：规划者定方向、执行者查细节
	"src-hunting": {"planner", "pentest", "worker"},
	// 浏览器自动化：worker 做 SPA/登录态探测时可用
	"playwright-cli": {"pentest", "worker"},
}

// seedBuiltinSkillVisibility binds the shipped built-in skills to their default
// agents. Insert-if-absent (ON CONFLICT DO NOTHING) so a user's later toggle-off is
// never resurrected on restart — matches the browser-MCP / intercept-rule seed policy.
func (d *DB) seedBuiltinSkillVisibility() error {
	for skillName, agentKeys := range builtinSkillVisibility {
		for _, key := range agentKeys {
			if _, err := d.Exec(`
INSERT INTO agent_skill_visibility(agent_id, skill_name, enabled)
SELECT id, $2, true FROM agents WHERE key=$1
ON CONFLICT (agent_id, skill_name) DO NOTHING`, key, skillName); err != nil {
				return fmt.Errorf("skill %s → agent %s: %w", skillName, key, err)
			}
		}
	}
	return nil
}

// seedBuiltinInterceptRulesBatch 插入一批内置拦截规则。
//
// 规则内容统一来自 builtinInterceptRules（db/intercept_builtin_rules.go）——那是
// 内置规则的单一事实源，分类（明令禁止 / 交 Agent 研判 / 人工确认）也在那里
// 声明并附带理由。这里只负责「插不插」。
//
// 分批是因为历史沿革：内置规则是逐批加上去的，每批有自己的 settings flag
// （intercept_default_rules_v1…v4），已部署实例靠 flag 决定「这批还要不要插」。
// 全新安装时四批依次执行，等价于一次性插全。
//
// flag 已置 done 的实例直接跳过——用户后来的禁用/删除/改动作都不会被复活。
func (d *DB) seedBuiltinInterceptRulesBatch(batch, flag string) error {
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	for _, r := range builtinInterceptRules {
		if r.seedBatch != batch {
			continue
		}
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, true, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT DO NOTHING`,
			r.name, r.priority, r.target, r.typ, r.pattern, r.action, r.message,
			r.timeoutEnabled, r.timeoutSeconds, r.timeoutAction,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting(flag, "done")
}

// seedDefaultInterceptRules inserts built-in safety intercept rules once on
// first startup. The seed is gated by a settings flag so user edits (disable,
// delete, re-order) are never overwritten on subsequent restarts.
func (d *DB) seedDefaultInterceptRules() error {
	return d.seedBuiltinInterceptRulesBatch("v1", "intercept_default_rules_v1")
}

// seedDefaultInterceptRulesV2 migrates the two safety patterns that used to be
// hard-coded in guard.go (destructive shell + data-exfil pipe) into ordinary
// intercept rules. Gated by its own flag so it also lands on DBs that already ran
// v1. Unlike the old guard.go floor, these are plain [内置] rules — the user can
// disable or delete them.
func (d *DB) seedDefaultInterceptRulesV2() error {
	return d.seedBuiltinInterceptRulesBatch("v2", "intercept_default_rules_v2")
}

// seedDefaultInterceptRulesV3 adds the delete-endpoint path rule. The v1 HTTP rules
// only catch the DELETE *method*, so a plain `curl 'http://t/api/user/delete?id=1'`
// (a delete endpoint reached with GET/POST, which is how most web apps expose
// deletion) would otherwise slip through every built-in rule.
//
// deleteEndpointPathPattern 是「删除类接口路径」规则的正则。
//
// 从内置规则表派生（而不是另抄一份）——规则的 pattern 只有一处定义，
// 避免「改了表里的、忘了改常量里的」这种漂移。保留这个名字是为了让
// 单元测试能在没有数据库的情况下直接断言这条正则。
var deleteEndpointPathPattern = builtinRulePattern("[内置] 删除类接口路径")

func (d *DB) seedDefaultInterceptRulesV3() error {
	return d.seedBuiltinInterceptRulesBatch("v3", "intercept_default_rules_v3")
}

// seedDefaultInterceptRulesV4 re-seeds the callback-listener approval boundary
// (v0.3.87: the listener tools got a real implementation, so the ask rule is
// back and the intercept gate needs the tool names again).
//
// ⚠️ 升级路径缺陷的修复（2026-10-30 Kali 实测）：v4 的 flag 在 v0.3.86 已置
// "done"——当时规则被删。直接走 batch 会在 flag 早退处返回，新规则永远落不到
// 已有实例。所以这里在 flag 之外**按规则名补种**：规则行不存在就插入（存在
// 则不动——用户对它的任何编辑保持有效）。
func (d *DB) seedDefaultInterceptRulesV4() error {
	if err := d.seedBuiltinInterceptRulesBatch("v4", "intercept_default_rules_v4_listener"); err != nil {
		return err
	}
	// 按名补种：flag 早退也可能吞掉新规则（v0.3.86 全新装→v0.3.87 升级的实例）。
	for _, r := range builtinInterceptRules {
		if r.name != "[内置] 启停回连接收器" {
			continue
		}
		var exists bool
		if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM intercept_rules WHERE name=$1)`, r.name).Scan(&exists); err != nil {
			return fmt.Errorf("probe listener rule: %w", err)
		}
		if exists {
			continue // 已有（可能是 v0.3.85 种的或用户编辑过的）——不动
		}
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, true, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT DO NOTHING`,
			r.name, r.priority, r.target, r.typ, r.pattern, r.action, r.message,
			r.timeoutEnabled, r.timeoutSeconds, r.timeoutAction,
		); err != nil {
			return fmt.Errorf("reseed listener rule: %w", err)
		}
	}
	// No persisted list means Interceptor uses its code defaults (which already
	// include the listener tools). Existing installations need a one-time append.
	if raw, ok, err := d.GetSetting("intercept_enabled_tools"); err != nil {
		return err
	} else if ok {
		if merged, changed := mergeEnabledInterceptTools(raw, "listener_start", "listener_stop"); changed {
			if err := d.SetSetting("intercept_enabled_tools", merged); err != nil {
				return err
			}
		}
	}
	return nil
}

// mergeEnabledInterceptTools appends newly introduced tools to a persisted
// intercept-enabled list without reordering or removing the user's choices. A
// malformed setting is left untouched instead of silently replacing user data.
func mergeEnabledInterceptTools(raw string, additions ...string) (string, bool) {
	var tools []string
	if err := json.Unmarshal([]byte(raw), &tools); err != nil {
		return raw, false
	}
	seen := make(map[string]struct{}, len(tools)+len(additions))
	for _, name := range tools {
		seen[name] = struct{}{}
	}
	changed := false
	for _, name := range additions {
		if _, ok := seen[name]; ok {
			continue
		}
		tools = append(tools, name)
		seen[name] = struct{}{}
		changed = true
	}
	if !changed {
		return raw, false
	}
	encoded, err := json.Marshal(tools)
	if err != nil {
		return raw, false
	}
	return string(encoded), true
}

// migrateBuiltinRulePatterns 把两条实测误报的内置规则换成收窄后的正则。
//
// 误报（全部来自生产环境的拦截历史，都是合法的渗透探测命令）：
//
//	rm -f /tmp_out.$$                     → 命中「删除系统关键目录」（裸 / 分支）
//	rm -f /usr/share/nmap/scripts/_t.nse  → 同上
//	for p in /api/.../reboot ...          → 命中「关机 / 重启」（路径里的 reboot）
//
// 规则是 first-insert only 的 seed，改代码对已部署实例无效，所以用一次性迁移
// 同步 pattern。**只改 pattern，不改 action/enabled/priority**——用户自己把
// 规则改成 judge 或停用的实例，行为保持。
func (d *DB) migrateBuiltinRulePatterns() error {
	const flag = "intercept_builtin_rule_patterns_v2"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	updates := []struct{ name, pattern string }{
		{
			"[内置] 删除系统关键目录",
			`\brm\b[^"'\n]{0,60}["'\s](/(?:etc|bin|usr|boot|var|lib|sys|proc|dev|sbin|root)(?:["'\s]|$|/(?:["'\s]|$)))`,
		},
		{
			"[内置] 关机 / 重启",
			`(?:^|[;&|]\s*|\b(?:sudo|doas)\s+)(?:shutdown|reboot|halt|poweroff)\b|\binit\s+[06]\b`,
		},
	}
	for _, u := range updates {
		if _, err := d.Exec(`UPDATE intercept_rules SET pattern=$2 WHERE name=$1`, u.name, u.pattern); err != nil {
			return fmt.Errorf("rule %q: %w", u.name, err)
		}
	}
	// 新增「清空系统关键目录」这条（rm -rf /var/lib/* 整棵清空）。
	// 旧的「删除系统关键目录」收窄后不再覆盖这个形态，需要单独一条。
	const clearName = "[内置] 清空系统关键目录"
	if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
SELECT $1, true, 100, 'tool_input', 'regex', $2, 'deny', $3, false, 60, 'allow'
WHERE NOT EXISTS (SELECT 1 FROM intercept_rules WHERE name = $1)`,
		clearName,
		`\brm\b[^"'\n]{0,120}["'\s][^"'\n]{0,80}/(?:etc|bin|usr|boot|var|lib|sys|proc|dev|sbin|root)/\*`,
		"禁止清空系统关键目录下的内容",
	); err != nil {
		return fmt.Errorf("rule %q: %w", clearName, err)
	}
	return d.SetSetting(flag, "done")
}

// migrateContextWindowK 把 LLM 配置的上下文窗口从「未设置(按 200K 算)」改成
// 显式的 1000K(1M)。
//
// 起因：本平台常用的 minimax-m3.1-flash-free 原生上下文是 1M(模型自报
// 1000000)，而 profile 的 context_window_k 留空时代码按 200K(Claude 默认)
// 算压缩阈值。于是压缩在远未到上限时就触发——压缩本身要额外调一次 LLM
// (还要 32768 预算)，白白吃掉预算、拖慢流程。
//
// 只改仍为 0(未设置)的行:用户自己填过窗口大小的实例保持不变。
func (d *DB) migrateContextWindowK() error {
	const flag = "llm_profiles_context_window_1000k_v1"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	if _, err := d.Exec(`UPDATE llm_profiles SET context_window_k=1000 WHERE COALESCE(context_window_k,0)=0`); err != nil {
		return fmt.Errorf("context window k: %w", err)
	}
	return d.SetSetting(flag, "done")
}

// migrateAgentRunSeconds 把各 agent 的单次 run 墙钟预算从 3600s 调回 1200s。
//
// 背景：2026-10-20 的迁移（agents_run_seconds_3600_v1）把 1200s 提到 3600s，
// 当时的判断是「给太紧」——实测生产环境里 89 个意图 exhausted vs 8 个 done。
//
// 那个归因是错的。exhausted 不是失败信号，是「这一小步没做完」的信号：上游
// (POJUN-upstream) 的种子默认就是 1200s，靠「短 run → exhausted → 规划者看
// trace 判进度 → 续派或换打法」形成小步快跑的闭环，从来不需要长 run。
//
// 拉长到 3600s 反而把这个闭环拆了：run 拖到 1 小时，撞的几乎都是硬上限，
// 规划者看到的一律是「运行超时」→ 续派同一条链 → 2026-10-21 实测 26 个意图
// 里 4 个跑满 3600s 后 exhausted，合计 4.1 小时机时且零事实产出。
//
// 另一个当时的干扰因素已被单独修掉：上下文窗口从 200K 提到 1M。压缩过早
// 触发会烧掉一整轮 LLM 预算，间接让意图显得「做不完」——那是上下文的问题，
// 不是墙钟的问题。两个一起调，等于把两个变量混在一起归因到一个。
//
// 只改仍是 3600 的行：用户自己调过的实例保持不变。
func (d *DB) migrateAgentRunSeconds() error {
	const flag = "agents_run_seconds_1200_v2"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	if err := d.applyAgentRunSeconds(3600, 1200); err != nil {
		return err
	}
	return d.SetSetting(flag, "done")
}

// applyAgentRunSeconds 把 run_seconds=from 的行改成 to。
//
// 单独抽出来是为了能直接测「迁移方向」这个不变量：之前那个 1200→3600 的迁移
// 就是走弯路的根源，而它是【一次性迁移】——跑过就没了，事后无从验证方向对错。
// 保持它是可测的纯逻辑（而不是藏在一次性 flag 后面），才能用单测锁住。
func (d *DB) applyAgentRunSeconds(from, to int) error {
	if _, err := d.Exec(`UPDATE agents SET run_seconds=$2 WHERE run_seconds=$1`, from, to); err != nil {
		return fmt.Errorf("agent run seconds %d->%d: %w", from, to, err)
	}
	return nil
}

// migrateJudgeTimeoutSeconds 把模型裁决的墙钟上限从 90s 提到 180s。
//
// 起因：思考型模型(MiniMax-M3.1 等强制 adaptive thinking 的)的裁决耗时随
// 命令长度而变——实测短命令 4~26 秒，长命令(几百到上千字符的 shell 脚本)
// 明显更久；而且正文为空时会升预算重试(32768 → 65536)，重试要挤在同一个
// 超时窗口内。90s 会把「模型其实能裁决」误判成超时失败(实测生产环境里
// 已有 24 条这种超时记录)。
//
// 只改仍是默认值 90 的实例：用户自己调过的值保持不变。
func (d *DB) migrateJudgeTimeoutSeconds() error {
	const flag = "intercept_judge_timeout_180_v1"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	if _, err := d.Exec(`
UPDATE settings SET value='180', updated_at=now()
WHERE key='llm_judge_timeout_seconds' AND value IN ('90','90.0',' 90 ')`); err != nil {
		return fmt.Errorf("judge timeout: %w", err)
	}
	return d.SetSetting(flag, "done")
}

// seedDefaultInterceptRulesV5 brings goal_met into the intercept system
// (v0.3.88 体检 S3)：新增 judge 规则 + 把 goal_met 合进已保存的 enabled 工具集
// （未保存的实例走代码默认 defaultEnabledTools，那里也已加入）。
func (d *DB) seedDefaultInterceptRulesV5() error {
	if err := d.seedBuiltinInterceptRulesBatch("v5", "intercept_default_rules_v5_goalmet"); err != nil {
		return err
	}
	// 按名补种：flag 早退也可能吞掉新规则（V4 教训：v0.3.86 全新装→0.3.87 升级
	// 的实例 listener 规则缺失——flag 在规则入目录前已置 done）。
	for _, r := range builtinInterceptRules {
		if r.seedBatch != "v5" {
			continue
		}
		var exists bool
		if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM intercept_rules WHERE name=$1)`, r.name).Scan(&exists); err != nil {
			return fmt.Errorf("probe v5 rule %q: %w", r.name, err)
		}
		if exists {
			continue // 用户编辑过或已插入——不动
		}
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, true, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT DO NOTHING`,
			r.name, r.priority, r.target, r.typ, r.pattern, r.action, r.message,
			r.timeoutEnabled, r.timeoutSeconds, r.timeoutAction,
		); err != nil {
			return fmt.Errorf("reseed v5 rule %q: %w", r.name, err)
		}
	}
	// 已保存过 enabled 工具集的实例补 goal_met（V4 同款一次性 append）。
	if raw, ok, err := d.GetSetting("intercept_enabled_tools"); err != nil {
		return err
	} else if ok {
		if merged, changed := mergeEnabledInterceptTools(raw, "goal_met"); changed {
			if err := d.SetSetting("intercept_enabled_tools", merged); err != nil {
				return err
			}
		}
	}
	return nil
}

// migrateListenerRuleTimeout 把「启停回连接收器」这条 ask 规则的超时策略从
// deny 改成 allow、时长从 300s 改成 180s。
//
// 起因：ask 会【同步阻塞】worker 等人批。操作员不在电脑前时 deny 等于把整条
// 渗透链卡死在这条命令上。放行只影响这一条命令，事后仍可在「拦截审批」页看到
// 记录并追认。
//
// seed 是 first-insert only（ON CONFLICT DO NOTHING），改 seed 对已部署实例
// 无效，所以这里用一次性迁移补上。只改 timeout 字段，不碰 action——用户自己
// 把规则改成 judge 的不受影响。
func (d *DB) migrateListenerRuleTimeout() error {
	const flag = "intercept_listener_rule_timeout_allow_v1"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	if _, err := d.Exec(`
UPDATE intercept_rules
   SET timeout_enabled = true,
       timeout_seconds = 180,
       timeout_action = 'allow'
 WHERE name = '[内置] 启停回连接收器'
   AND timeout_action <> 'allow'`); err != nil {
		return err
	}
	return d.SetSetting(flag, "done")
}
