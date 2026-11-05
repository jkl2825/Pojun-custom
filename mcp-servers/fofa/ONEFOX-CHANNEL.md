# ONE-FOX FOFA 代理通道实现说明

> 2026-09-20 接入。本文记录 `fofa.one-fox.cn` 代理接口的抓取分析结论，以及
> `fofa.py` 中 `get_alerts_onefox` 工具的实现思路，供日后维护或复用。

## 一、目标站是什么

`https://fofa.one-fox.cn/`（ONE-FOX 安全团队星球会员查询工具）**不是 FOFA 镜像站**，
是一个纯前端壳 + PHP 服务端代理：

- 页面只有 4 个静态资源，核心逻辑全在 `js.js`（不到 5KB）；
- 真实的 FOFA API key 存在**站方服务器**（PHP 环境变量），浏览器流量里永远看不到；
- 前端 `getApiKey()` 返回的是写死的常量 `"onefox"`——那是**站点令牌**，不是 FOFA key
  （注释还一本正经写着"获取服务器生成的API密钥"，实际是个幌子）。

## 二、代理接口规格

```
POST https://fofa.one-fox.cn/function.php
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Referer: https://fofa.one-fox.cn/

action=fofa_cx&fofa_yf=<URL编码的fofa语法>&fofa_ts=<条数>&api_key=onefox
```

- 返回 **FOFA 官方 API v1 的原生 JSON**（`error / consumed_fpoint / required_fpoints /
  size / page / mode / results` 与 `fofa.info/api/v1/search/all` 完全同构），
  `mode:"extended"` 说明站方挂的是注册用户 API；
- `results` 行格式固定 `[host, ip, title, port]`（字段在站方服务端写死，无法自选）；
- 站点令牌 `api_key=onefox` 公开在 `js.js` 里，人人可见。

## 三、会话机制（调用链三步）

```bash
# 1. GET 首页，拿 WAF 质询 cookie（server_session_* / X_CACHE_KEY / md5名cookie）
#    缺这一步直接提密码会 403
curl -c jar.txt https://fofa.one-fox.cn/

# 2. POST 密码建 PHP 会话（表单回提交到首页本身）
curl -b jar.txt -c jar.txt -d "pagepwd=<星球密码>" https://fofa.one-fox.cn/

# 3. 带会话查询
curl -b jar.txt -X POST https://fofa.one-fox.cn/function.php \
  -H "X-Requested-With: XMLHttpRequest" -e "https://fofa.one-fox.cn/" \
  --data 'action=fofa_cx&fofa_yf=header%3D%22ThinkPHP%22&fofa_ts=10&api_key=onefox'
```

实测细节：

- 密码 POST 首次常被 WAF 403，**退避几秒重试即过**（纯 cookie 质询，无 JS 挑战）；
- 会话 cookie 里 `PHPSESSID=onefox` 是写死的固定值，但服务端 session 状态仍需真实登录，
  带无效会话查 function.php 回 `{"error":true,"errmsg":"session is exists."}`
  （js.js 里另有 `session is not exists.` 分支，站点两种都可能出现，处理上同等对待）；
- 密码校验成功后另发 `mk_encrypt_*` cookie。

## 四、站点侧限制

| 信号 | 含义 | 处置 |
|------|------|------|
| `Too frequent access. Please wait a moment.` | 60s 频控 | 客户端节流 65s |
| HTTP 500 | 超过试用条数（站方限制，非官方 API 报错） | 改小 `fofa_ts` |
| `FOFA coin is not enough!` | **站方 FOFA 账号 F 点耗尽** | 停手，等站方充值 |
| `Query invalid!` | 语法为空 | 检查入参 |

**红线：这通道耗的是站方账号的 F 点。2026-09-20 起定为独立查询主用通道（用户指定），
但主用 ≠ 滥用：全量导出、批量扫描等重活仍走官方通道，站方 F 点打光了本通道就废。**

## 五、fofa.py 集成实现

新增工具 `get_alerts_onefox(query, size=10)`，与官方通道 `get_alerts`（三账号轮换）
并列，互不干扰。实现要点：

1. **配置**：`ONEFOX_PASSWORD` 在 `fofa_MCP/.env`（禁写对话/报告）；`ONEFOX_BASE_URL`
   可覆盖，默认 `https://fofa.one-fox.cn`；站点令牌 `ONEFOX_SITE_TOKEN="onefox"` 硬编码。
2. **请求客户端**：`httpx.AsyncClient(trust_env=False)` —— 绕开本机可能残留的失效代理
   （127.0.0.1:59112 坑）；UA 用浏览器串，防 UA 指纹拦截。
3. **会话管理**：cookie 持久化到 `.onefox_session.json`（已进 `.gitignore`），跨 MCP
   重启复用，省掉每次登录。查询回 `session is*` 或 403 时自动走一遍登录链再重试一次。
4. **频控**：状态文件里记 `last_query` 时间戳，每次查询前算差值不足 65s 就
   `asyncio.sleep` 补齐——同一 MCP 进程内靠 `asyncio.Lock` 串行，跨进程靠文件。
5. **size 档位**：只认 10/100/1000/10000，其它值自动吸附最近档。
6. **错误映射**：站点错误翻译成中文提示后原样返回，返回结构与 `get_alerts` 同构
   （`query/size/page/mode/count/data/raw_results/account_used`），
   `account_used="onefox-proxy"` 标记来源。
7. **登录成功判定**：密码 POST 回 200 且 HTML 含 `function.php` 或 `搜索小工具`
   （即查询页特征），否则退避重试至多 3 次。

## 六、部署位置

| 位置 | 内容 |
|------|------|
| `src-6k/mcp-servers/fofa_MCP/fofa.py` | 工具实现（本目录） |
| `src-6k/mcp-servers/fofa_MCP/.env` | `ONEFOX_PASSWORD` + FOFA 三账号 key |
| `src-6k/mcp-servers/fofa_MCP/.onefox_session.json` | 会话 cookie + last_query（运行时生成） |
| Claude Code：`~/.claude.json` mcpServers.fofa | 原有注册，env 内联 FOFA_KEY |
| ZCode：`~/.zcode/cli/config.json` mcp.servers.fofa | 2026-09-20 新增注册，不内联 key，靠 .env |
| `src-6k/SKILL.md` 第 53 行 | 2026-09-20 起主用通道（用户指定）；官方三账号退为兜底 |

**改动生效需重启对应 harness 会话**（MCP 服务器随会话启动）。

## 七、实测记录（2026-09-20）

- `header="ThinkPHP"`：`size=427293`，返回 10 行 host/ip/title/port ✓
- 首查无会话 → 自动 GET + 提密码（WAF 403 一次 → 退避重试通过）→ 重查成功 ✓
- cookie 落盘 ✓；纯 curl 三步链路复现 ✓

## 八、局限

- 返回字段写死 host,ip,title,port，要 body/icon_hash 等字段走官方通道；
- 每分钟最多 1 次查询，且吃站方额度，跑大批量测绘不现实；
- 站点是社区公益性质，接口无契约保障，随时可能改版——改版后从
  `js.js` 重新看 `run_form()` 的 data 模板即可（本文第二节的规格就是从那里扒的）。
