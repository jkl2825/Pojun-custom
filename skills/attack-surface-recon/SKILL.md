---
name: attack-surface-recon
description: 任务开局或进入新资产域时做外部攻击面侦察时调用——备案/证书/whois/ASN 归属核实、子域与端口枚举、指纹与敏感文件发现、资产入库与覆盖规划。当意图涉及「侦察/资产发现/子域/指纹/扫端口」时使用。
tags:
  cwe: [CWE-200]
  attack: [T1595, T1590, T1592, T1596]
  class: [recon, asset-discovery, fingerprint, attack-surface]
---

# 攻击面侦察方法论

## 目标产物（每次侦察都要交）

1. 归属清楚的新资产（域名/IP/服务/端点）——经备案/证书/whois/ASN 证据链确认，再 `insert_assets`；
2. 每个资产的指纹（状态码/标题/Server/技术栈/CDN/WAF）；
3. 未测资产清单（`list_untested_assets` 的输入）；
4. 一条 fact 说明覆盖范围与结论（含失败项，防重复扫）。

## 1. 归属核实（先证归属，再谈测试）

- ICP 备案：工信部备案查询确认主办单位；
- 证书透明度：`crt.sh` / `certspotter` 查证书 SAN（子域最稳来源之一）；
- whois / ASN：`whois <ip>`、`whois -h whois.radb.net <ip>`，确认 IP 归属与网段；
- 反向 DNS、favicon hash（`mmh3`/`whatweb`）、页面版权/备案号；
- **仅同 IP 不构成归属依据**：同 IP 第三方业务不得纳入范围（写 fact 标注「同 IP 非本主体」）。

## 2. 子域与域名面

- 被动：crt.sh、`subfinder -d domain -all`、`amass enum -passive -d domain`；
- 主动：`dnsx`/`naabu` 校验存活，`ffuf -w <字典> -u https://FUZZ.domain` 虚拟主机枚举；
- 泛解析判定：随机子域是否解析（防假阳性）；
- 通配符证书可能掩盖真实子域，注意 SAN 列表里的**其他域名**（常是旧域名/别名域名）。

## 3. 端口与服务

- 全端口快扫：`nmap -p- --min-rate 2000 -T4 <ip>`；服务识别 `nmap -sV -sC -p<ports> <ip>`；
- masscan 大网段收敛：先确认授权网段，`masscan -p80,443,8080,8443 <cidr> --rate 1000`；
- 非标端口重点：`8080/8443/8888/7001(WebLogic)/9200(ES)/6379(Redis)/27017(Mongo)/2375(Docker)/9090`；
- 服务直连证据：Redis 未授权 `redis-cli -h ip info`、ES `curl ip:9200/_cat/indices`。

## 4. HTTP 指纹（批量、留证）

- 平台工具：`http_probe` 一次探活批量 URL，返回每行 JSON（status/bytes/ms/title/server/ct/redirect）；
- 补充：`whatweb -a3 <url>`、`httpx -title -tech-detect -status-code -web-server`；
- 关注：框架（Spring/Vue/React/ThinkPHP/若依）、中间件（Tomcat/Nginx/IIS）、
  WAF/CDN（响应头/拦截页特征）、调试端点（`/actuator`、`/druid`、`/swagger-ui`）；
- favicon hash 与 Shodan/FOFA 反查可作为同源指纹（需要时用对应工具/API）。

## 5. 敏感文件与信息泄露

- 常规：`/robots.txt`、`/sitemap.xml`、`/.git/config`、`/.svn/entries`、`/.env`、
  `/backup.zip`、`/www.zip`、`/db.sql`、`/.DS_Store`、`/phpinfo.php`；
- Swagger/OpenAPI：`/swagger-ui.html`、`/v2/api-docs`、`/openapi.json`（拿到即接口全景）；
- Spring：`/actuator`、`/actuator/env`、`/actuator/heapdump`（含密钥，属高危证据）；
- 前端打包：`.js` 里的接口前缀、AK/SK、测试环境域名、sourcemap（`.map` 可直接还原源码）。

## 6. 覆盖与入库

- 新资产入库：`insert_assets`（类型/名称/归属公司）；范围外只记录不测试；
- 用 `list_untested_assets` 找漏测资产，按「同前缀聚簇 + 静态沉底」选择下一批；
- 覆盖度看 `graph_overview` 的 coverage；不要为凑 100% 重复扫已测资产；
- 任务约束（`set_constraints` 里登记的）优先于任何扫描计划：只扫允许的端口/网段。

## 纪律

- 先被动后主动，先轻后重（避免一上来全端口+大字典触发封禁）；
- 每个探测失败也落 fact（「子域 X 无解析」「端口 Y 滤包」），减少重复；
- 识别到第三方资产/云托管边界时立即停手并记录。
