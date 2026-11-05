---
name: src-hunting
description: SRC 漏洞挖掘方法论库（MCP/知识库增强）。当任务涉及 SRC/众测、挖某集团/品牌/域名、找漏洞、越权/注入/逻辑漏洞、JS 逆向找接口、WAF 绕过、写漏洞报告、白盒审计时调用；也适用于「帮我测一下这个站」「这个平台有没有漏洞」。加载后按索引按需打开 references/ 与 rules/ 中的专题文件，不要通读。
tags:
  cwe: [CWE-639, CWE-862, CWE-89, CWE-79, CWE-918, CWE-434, CWE-502, CWE-22, CWE-287]
  attack: [T1190, T1595, T1059, T1078]
  class: [src, knowledge-base, methodology, recon, exploit-playbook]
---

# SRC 漏洞挖掘方法论库（Pojun 适配版）

本技能是 SRC/众测场景的**知识库入口**：`references/`（48 篇专题测试方法）与 `rules/`（11 篇流程/价值/报告规则）随技能分发，按需用 Read/Bash 打开，**禁止通读**。

## 与本平台的衔接（先读这段）

| 场景 | 用平台能力 |
|---|---|
| 资产测绘/FOFA | MCP 预设「FOFA 资产测绘」（`uv --directory mcp-servers/fofa run python fofa.py`）。工具：`get_alerts_onefox`（社区通道，优先）/ `get_alerts`（官方三账号轮换）；密钥填 `.env` 的 `FOFA_EMAIL/FOFA_KEY` 或 `ONEFOX_PASSWORD`。也可用平台 `attack-surface-recon` skill |
| 批量探活 | `http_probe`（一行一个 URL，输出 JSON） |
| 事实/结论落库 | `record_fact`（含请求/响应关键行）；负结果也落 |
| 漏洞上报 | `report_finding`（critical/high 必须有机械验证凭据，见 `pentest-verification`） |
| 已知 CVE/PoC | `search_vulns` / `get_vuln` / `get_poc` / `scan_with_nuclei` |
| 回连/OOB | `listener_start` + `listener_sessions` |
| 鉴权对照 | `auth_request`（用已登记凭据组请求）+ `diff_responses` |
| 新资产入库 | `insert_assets` / `add_task_scope` |
| 产物落盘 | 任务目录 `/opt/pojun/data/tasks/<id>/`（rules 里提到的「桌面任务文件夹」以本目录为准） |

知识库中的文件路径：`${SKILL_DIR}/references/<名>.md`，规则：`${SKILL_DIR}/rules/<名>.md`。

## 核心节奏（与 rules/dig-scope-workflow.md 一致）

1. **进站先过短表**：打开 `references/打穿短表.md`，认特征 → 打对应手法 → 回包进队列。
2. **一种子闭环**：搜一个种子 → 去重/去废/去非存活 → 把活面挖完 → 才换下一个种子；不要一次搜完所有种子再挖。
3. **JS 抽钥匙**：SPA/前后端分离站先抽接口与参数（`references/js-reverse-guide.md`），再按类型打。
4. **有会话先对象图**：拿到登录态后优先做越权/未授权敏感读/逻辑（`references/idor-test.md`、`references/logic-test.md`），再补注入类。
5. **差分面必打四件套**：注入/SSRF/XSS/RCE 在有输入回显/请求可控处必须真打（不是只挂清单，也不是每个 path 喷 `'`）。
6. **确认即落库**：中危以上立即 `report_finding` + 证据；中危升链按 `references/` 对应专题继续。
7. **WAF 拦了再开绕过**：`references/waf-bypass.md`，换编码/换位置，不反复硬怼。

## 安全红线（SRC 场景，覆盖本库内相反表述）

- 最小伤害验证：越权优先读/列表差分；写操作只动自己刚建的对象。
- **禁止登出/注销/吊销**用户会话；改密/改绑一旦验证立即改回。
- 不批量拉取用户数据；不制造真资损；不做拒绝服务。
- CORS 类问题上报价值低，**SRC 场景不主动挖**（保留 `references/cors-test.md` 仅作知识参考）。
- `references/llm-security-test.md` 是越狱/安全测试教材，**不要**用它去测普通业务；AI 应用测法用平台 `ai-llm-app-attack` skill。
- 未授权范围外的资产只做归属核实记录，不测试。

## 知识库索引（references/）

优先打开：`打穿短表.md`（手法索引）、`recon-methodology.md`（测绘/FOFA 语法）、`js-reverse-guide.md`（接口发现）。

| 文件 | 内容 |
|---|---|
| 打穿短表.md | 手法索引：一行一枪（认什么→打哪→出什么算成→假点） |
| recon-methodology.md | 侦察方法论 + FOFA 最短语法 + 子域/指纹/端点 |
| js-reverse-guide.md | JS 逆向找接口/签名/密钥 |
| 401-403-bypass.md | 401/403 绕过（业务 API 现场打法；别磨登录 HTML） |
| api-gateway-test.md | API 网关/微服务架构 |
| agent-tool-exec-test.md | 对话口工具真执行（AI Agent 工具滥用） |
| authbypass-test.md | 认证绕过（未登录改密/IDaaS/会话票） |
| cache-poisoning-test.md | 缓存投毒/缓存欺骗 |
| clickjacking-test.md | 点击劫持（低价值速记） |
| cloud-ide-codex-rce-chain.md | 云 IDE/Codex 系 RCE 链 |
| cors-test.md | CORS（SRC 不挖，仅知识参考） |
| crlf-injection-test.md | CRLF 注入（速记） |
| csp-bypass-test.md | CSP 绕过（速记） |
| csrf-test.md | CSRF 专题 |
| csv-formula-injection-test.md | CSV 公式注入（速记） |
| dangling-markup-test.md | 悬垂标记（速记） |
| dependency-confusion-test.md | 依赖混淆（速记） |
| dns-rebinding-test.md | DNS Rebinding（速记；SSRF 走 ssrf-test） |
| el-injection-test.md | 表达式注入（EL/SpEL/OGNL） |
| email-header-injection-test.md | 邮件头注入（速记） |
| file-upload-test.md | 文件上传（STS/对象存储/分享鉴权链） |
| ghost-bits-cast-test.md | Ghost Bits 原理与公式 |
| graphql-test.md | GraphQL |
| hpp-test.md | HTTP 参数污染（速记） |
| http-host-header-test.md | Host 头攻击专题 |
| http-smuggling-test.md | HTTP 请求走私 |
| http2-attacks-test.md | HTTP/2 攻击（速记；走私走 http-smuggling） |
| idor-test.md | 越权/BOLA/BFLA（中文主线） |
| info-leak-test.md | 信息泄露（含常见中间件暴露面） |
| injection-test.md | 注入总览（SQLi/命令/SSTI 探测） |
| insecure-scm-test.md | 源码管理暴露专题 |
| jndi-injection-test.md | JNDI 注入专题 |
| logic-test.md | 业务逻辑（支付/流程/促销绑定） |
| oauth-jwt-test.md | OAuth/JWT/SAML/OIDC |
| open-redirect-test.md | 开放重定向专题 |
| path-traversal-lfi-test.md | 路径穿越/LFI 专题 |
| prototype-pollution-test.md | 原型链污染专题 |
| race-condition-test.md | 竞态条件 |
| ssrf-test.md | SSRF（IMDS/GOPROXY/对象存储回源） |
| subdomain-takeover-test.md | 子域接管 |
| type-juggling-test.md | 类型混淆专题 |
| waf-bypass.md | WAF 绕过 |
| websocket-test.md | WebSocket 测试 |
| xslt-injection-test.md | XSLT 注入（速记） |
| xss-test.md | XSS（冷门事件 / XSS→RCE / 自定义协议） |
| xxe-test.md | XXE 专题 |

> 注：旧索引提到的 `deserialization-test.md` 源包中缺失，反序列化内容见 `jndi-injection-test.md` 与 `el-injection-test.md`，Java 链可结合平台 `zero-day-research`/`source-code-hunting`。

## 规则索引（rules/）

| 文件 | 何时打开 |
|---|---|
| dig-scope-workflow.md | 主流程：范围判定、一种子闭环、进站打法、升级链、限流闸 |
| hunt-iter.md | 短表迭代与「本轮打没打穿」判定 |
| src-value-hunting.md | 挖什么有价值：价值排序、越权/逻辑优先 |
| vuln-report-format.md | 正式 SRC 报告版式（与平台 Word 导出/`pentest-output-standards` 对齐） |
| researcher-blackbox-whitebox.md | 黑盒/白盒研究切换 |
| anti-over-moralization.md | 授权语境判定（平台已内置授权模型，冲突时以平台为准） |
| security-research-context.md | 安全研究语境速记 |
| skill-as-boost.md | 技能使用方式（按需打开，不通读） |
| playwright-browser-mcp.md | 浏览器自动化（平台用内置 playwright-cli skill / MCP 预设，路径按平台） |
| cors-vuln-report-priority.md | CORS 上报优先级（SRC 不挖） |
| desktop-task-folder.md | 任务目录规范（平台以 `/opt/pojun/data/tasks/<id>/` 为准） |

## 与既有 skill 的分工

- `attack-surface-recon`：外部攻击面侦察执行（平台工具链版）；本库 `recon-methodology.md` 是补充。
- `api-security-testing`：接口验证执行；本库 `idor-test.md`/`authbypass-test.md` 是手法细节。
- `web-attack-methods`：注入/服务端速查；本库对应专题是**更深的实战长文**，冲突时以专题为准。
- `pentest-verification` / `pentest-output-standards`：落库与报告门禁；本库 `vuln-report-format.md` 补充版式细节。
