# 15 - 身份包对 Pojun 的落地判定

> 对象：A 面 `Grok换机移交/AGENTS.md` + `rules/` 11 篇（机制层提炼见 `14`，本篇不重复）；B 面本仓库 `downstream/custom`。
> 判定口径：**A** = 已有等价实现（必须给 file:line，并说明语义是否完全等价）；**B** = 该加（指明提示词/代码/数据模型哪一层）；**C** = 不该加（指明冲突对象）；**D** = 改造后加（指明冲突点与改法）。
> 一条判定要成立，必须落到可核对的代码行。指不出行号的，只能判 B 或 C，不许判 A。

## 0. 总判断

13 条候选机制：**A 7 条、C 4 条、D 2 条、B 0 条**。

净增量接近零。身份包是一份**外部执行器的自律补丁**——约束对象是「一个会自己乱跑的模型」，手段是提示词里反复念。Pojun 把其中能编码的部分全下沉成代码强制（Frontier 的 SQL 排序、idlestop 的 PreToolUse 阻断、auto_finish 的计数判据、finding 的证据闸门）。自律换成硬闸，条文就没有移植价值了。

但它有一样别的东西：**它逼着人把「谁说了算」写死**。拿这条去照，照出两个真缺陷，都在报告真源上（第 9、10 行）。这两个缺陷不是身份包教出来的，是拿身份包对照时才暴露的。

## 1. 主表

| # | 机制 | 判定 | Pojun 证据 | 理由 |
|---|------|------|-----------|------|
| 1 | 禁止问「要不要继续」、不以提问结尾 | **A** | `agent/planner.go:330`（硬底线）；无 ask 类工具（`agent/tools.go` 全量注册表）；`server/auto_finish.go:110` | 「问」在结构上做不到：工具集里没有任何通向用户的通道，比提示词禁令硬。等价风险是「0 意图空等」，由硬底线 + 3 轮 idle 收尾兜住（详见 §2①）。 |
| 2 | 自由跳「用户未叫停就一直挖」 | **C** | `server/auto_finish.go:94-114`（四判据收尾） | Pojun 的收尾是**产品功能**（goal met / coverage / idle 3 轮 / 80 轮上限），不是待修缺陷。「永不收工」搬进来会与 `settleTaskWithReason` 对立，让交付永远出不来。两者是相反的产品姿态，不是同一件事的两种写法。 |
| 3 | 一种子闭环（搜一个→挖完→才搜下一个） | **A**（形不可搬） | `agent/planner.go:371-372`、`:374`；`db/exploration.go:1557-1562` | 内核是「扩面不算进度」，已由三层表达：深度优先于覆盖度（371）、二轮无增量才恢复铺广（372）、数据面扩展族先取干净（374）。**串行形式不能搬**：4 意图并发 + 强串行会把 Frontier 退化成单队列。aging 解的是饥饿（78 条意图 3 小时没被领），与广度优先无关，别混。 |
| 4 | 深挖优先五闸（A–E） | **A** | `agent/planner.go:355-379`；`server/escalation.go:31-35` | 五闸合起来一句话：别拿扩面冒充进度。371/372/374/378 已覆盖；「时间军规」那档由阶梯 L1/L2/L4 代码执行，比提示词更可靠。 |
| 5 | 空转判定（15–20 分钟、肥瘦分层） | **A**（口径有差） | `agent/idlestop.go:84,91,96,207-215`；`server/escalation.go:55-73` | 两层都在：worker 级 idlestop（连续 10 轮无写回 **且**[超 12 分钟 或 满 30 轮] → 阻断），意图级阶梯（15/25/45）。口径差在判据：原文按「有没有苗头」分肥瘦，Pojun 按「有没有写回」，肥面抽 JS 不落资产会被判空转——正是 11-05 把阈值从 3 抬到 10 修的误杀。不必再加会开假口子的「肥面豁免」。 |
| 6 | 种子队列落盘 + 回合结束闸 | **A** | `db/exploration.go:1538-1569`（只取 state='open'）；`:1576-1581`；`server/auto_finish.go:166-172` | 队列 = Frontier（图节点即队列，原子 claim，比 markdown 表强）；回合闸 = 「frontier 不空则不收尾」。落盘、跳过已 done、续跑读旧队列，在 PG 里天然成立。 |
| 7 | 锁面 / 自由跳模式判定 | **A**（更强） | `agent/constraints.go:13-47`；`db/task_scope.go:12-30` | Pojun 不判模式，直接落表：task_scope 当覆盖度分母兼授权边界，task_constraints 渲染成「凌驾于一切探索启发式」的提示词块，并写明「约束外的新主机不等于获得授权」。靠表 + 注入比靠读入口自判稳。 |
| 8 | 同族迁移 + 中危同一对象先升链 | **A** | `agent/planner.go:378`（variant hunting）；`:371-372`（升链） | variant 那条还多了越界闸（必须锚定 task_scope），比原规则严。升链由「两轮无增量才恢复铺广」实现，语义覆盖。 |
| 9 | **报告唯一真源** | **D** | `server/server.go:4236-4258`（图渲染，无状态过滤）vs `server/report_export.go:20-23,111`（表渲染，排除误报） | **现在有两个真源、三条交付路径。** `/api/report` 从探索节点渲染（`server.go:4241` → `report/report.go:49`），**不看 findings.status**，已标 `false_positive` 的照样进报告；`/api/report/export` 走 findings 表并剔除误报。同一交付物，两个入口两种内容。改法：`getReport` 改读 `ListFindingsForExport`，删掉 `report.Markdown` 的图输入。 |
| 10 | **冲突裁决链（含 severity 变更）** | **D** | `db/finding_traffic.go:417`（`severity=$3` 无条件覆盖）；`agent/tools.go:1183-1196`（`compactFinding` 用 `n.State`）；A 面对照 `vuln-report-format.md:18`、`hunt-iter.md:18` | 去重合并时 severity **无条件取最后一次上报值**，先报 high、后报 medium，已确认的高危被静默降级且无留痕。A 面条文可作正向依据，但不是「只升不降」：`format:18` 禁「比上一份多一个字段就跳档」（防上抬），`hunt-iter:18` 要求「不以标题或已写的高危二字为准，读磁盘现稿」（防沿用）——合起来的语义是**等级每次由正文重裁**。故改法收敛为「默认沿用，变更须对正文并写 fact 留痕」。另一头 `compactFinding` 读节点 `n.State`（插入即写死 `'confirmed'`），人 triage 成误报后 planner 仍看到 confirmed——与上引 `hunt-iter:18`、`format:36` 匿名闸（有 Cookie 才不写「匿名」）同构：A 面的通用律是**标签须由当前事实推导，不得继承写死值**。 |
| 11 | 报告格式纪律（一包一步、不贴回包、认钥闸前置） | **C** | `report/findings.go:37`；`agent/finding_recorder.go:15-115`；`agent/tools.go:1723-1760` | Pojun 的报告是**程序渲染**，不是模型写散文，「步骤里不贴回包」没有执行面。能编码的（证据字数、机械凭据、逐字回验、流量绑定）已在代码里，且更硬：证据不足直接打回重报。 |
| 12 | 三问 / 门槛 / 假点（短表准入） | **C** | 无对应产物 | **跨任务知识沉淀**的准入规则，服务对象是「下次还挖同一个 SRC」的人。Pojun 是单任务执行器，没有「短表」，硬塞进 planner 只会变成一段无产出的自我审查。要沉淀该做 `vulnintel`/`skills`。 |
| 13 | 反说教 / 反误拒 | **C** | `agent/worker.go:243`（授权系统声明）、`:257`（操作约束红线） | 原文防的是外部 CLI 模型动不动拒答。Pojun 是专用系统提示词 + 工具白名单 + 授权语境，拒答面本来就窄；再加一层「不要拒绝」只会削弱第 5 条的操作约束。 |

## 2. 四条必查的正面回答

**① 禁止问「要不要继续」——不需要这条硬约束，因为 planner 根本没有嘴。**
全仓 grep 无 `ask_user` / `ask_human`；planner 与 worker 的产物只有 intents / facts / findings，没有提问通道。唯一形似是 `intent_intervention.go` 的**人→worker** 单向消息，方向相反。planner 也不鼓励等待：`planner.go:330` 把「无 open/running 时必须派单」列为最高优先硬底线。结论 **A**，且是结构性成立，不是提示词成立。

**② 一种子闭环 vs Frontier + aging——串行形式适用不了，内核已经在了。**
Pojun 一轮最多 4 条意图、多 worker 同时 claim、Frontier 按 `priority + aging` 排序。「搜一个挖完再下一个」翻译过来就是「同一时刻只许一条意图在跑」，会把 worker 池和 aging 一起废掉。该保留的是「同族未收口不新开同族意图」，`planner.go:374` 已是这个意思，只是软约束。**不必为它造种子队列**——Frontier 就是队列，多造一层是重复建模。

**③ 报告唯一真源——Pojun 目前有两个，这是本篇唯一确认的真缺陷。**
`server.go:4241` 图取数、无状态过滤；`report_export.go:111` 表取数、剔除误报。更麻烦的是合并只 append `findings.evidence`（`finding_traffic.go:415-420`）而不回写节点 payload，图那条路径的证据停在第一次上报的样子。同一任务，「报告页」和「导出 Word」可以是两份不同结论。判 **D**。

**④ 反空转/深挖优先 vs escalation 阶梯——互补，不重复。**
三层各管一段：idlestop 管 **worker 连续无写回**（工具级阻断）；escalation 管 **意图整体停摆**（15/25/45，含 goallessDoneSummary 的诚实播报）；auto_finish 管 **任务级收尾**。身份包的「空转就跳」是**人的策略切换**，对应 planner 的「两轮无增量恢复铺广」。判据都锚在「产出」而非「活动」，同源不同层，没有一条冗余。

## 3. 现在就该做（3 条，按性价比排序）

1. **`/api/report` 改读 findings 表**（`server/server.go:4236-4258`）。
   `ListByKind(KindFinding,1000)` 换成 `ListFindingsForExport(FindingFilter{TaskID, ExcludeStatuses: exportExcludeStatuses})`，与导出共用同一份过滤。改一层（一个 handler），不动 schema、不动前端；影响面 = 报告页数据，会少掉几条已标误报的条目（这正是目的）。
2. **severity 变更须重新裁决 + 留痕**（`db/finding_traffic.go:415-420`）。
   现在 `severity=$3` 无条件覆盖，等于 last-write-wins。改成「默认沿用原值；要改必须带一句对 `vuln-report-format` 等级法的重新比对，并写 fact 留痕」。注意不要写成「只升不降」——A 面条文（`format:18` 反跳档 / `hunt-iter:18` 反沿用）说的是**每次由正文重裁**，一刀切禁降会挡住真正报错后改对的情况。改一层（合并分支一条条件）；影响面 = 重复上报路径，`auto_finish` 的 findings 计数不看 severity，不会连带。
3. **`compactFinding` 改读 findings.status**（`agent/tools.go:1183-1196`）。
   否则人标了误报，planner 的 `list_findings` 仍报 confirmed，会继续往那条已否证的方向派意图。改一层（一个 helper 加一次 join）；影响面 = planner 上下文，可能减少少量无效派单。

以上三条都在「报告真源」这一个面上，加起来是一次半天的改动。身份包其余 10 条，建议一条都不动。
