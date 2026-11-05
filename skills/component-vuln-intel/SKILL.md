---
name: component-vuln-intel
description: 拿到组件指纹或版本号、要判断是否存在已知 CVE、找 PoC 或决定是否值得打时调用——平台内置漏洞情报（search_vulns/get_vuln/get_poc/scan_with_nuclei）的标准用法与版本区间判定、误报规避。当意图涉及「已知漏洞/CVE/版本匹配/PoC」时使用。
tags:
  cwe: [CWE-1104, CWE-1395, CWE-1035]
  attack: [T1190, T1203]
  class: [vuln-intel, cve, fingerprint, exploit-selection]
---

# 组件漏洞情报（用平台内置能力，不要靠记忆报 CVE）

## 为什么用工具而不用脑子

模型记忆里的 CVE 版本区间经常记错、记旧。平台情报库（NVD + CISA KEV + GHSA + PoC 聚合）
是唯一可信来源：**先 `search_vulns`，再决定打不打**。

## 标准流程

1. **拿准指纹**：组件名 + 精确版本（`Server: nginx/1.18.0`、`X-Powered-By`、
   `/actuator/info`、favicon、静态资源 hash、错误页版本号）。版本拿不准就先想办法拿准；
2. `search_vulns` 查询：返回 CVE、CVSS、KEV（在野利用）、`version_in_range` 三态；
3. `get_vuln` 看详情与受影响范围说明；`get_poc` 找公开 PoC / 利用链接；
4. 命中后**必须行为验证**：`scan_with_nuclei` 或手工构造请求，拿到响应特征才算漏洞；
5. `report_finding` 时写明：组件+版本、CVE 编号、验证方式、真实响应证据。

## 版本区间判定的三个坑

- **发行版 backport**：RedHat/Debian 把补丁回移到旧版本号，版本匹配 ≠ 有漏洞；
  证据里必须体现「行为验证」，纯版本号会被平台机械验证闸门打回；
- **版本号不可信**：很多产品改版本号/隐藏版本（`Server: nginx` 无版本、`X-Powered-By: PHP`）；
  此时只能按行为测（端点是否存在、错误特征）；
- `version_in_range` 返回「可能受影响」时：写 fact 标注「版本可能受影响，行为未验证」，
  再决定是否投入验证；不要直接报漏洞。

## nuclei 的正确用法

- 先确认模板覆盖：`nuclei -t <匹配的模板/标签> -u <url> -severity high,critical -stats`；
- 平台工具 `scan_with_nuclei` 会组好命令并留流量；自己跑时结果落文件后 `save_evidence`；
- 模板命中 ≠ 漏洞：核对请求/响应是否真的触发（有些模板只匹配版本 banner）；
- 高危模板（如 RCE）先确认目标有授权且不影响业务，再执行。

## PoC 使用纪律

- 公开 PoC 常带反连/写文件行为：先读代码，确认不会破坏目标（无 rm/无加密/无批量）；
- 需要 OOB 时用平台回连器（`listener_start` 或 interactsh）留证；
- 利用失败也落 fact（哪一步失败、错误特征），避免换人再打一遍。

## 高频组件优先表（先看这些）

- Web 容器/框架：Tomcat、WebLogic、Spring(Boot)、Struts2、ThinkPHP、若依(RuoYi)、JeecgBoot；
- 中间件/反代：Nginx、Apache、IIS、Kong、Nacos、Consul；
- 运维面：Jenkins、GitLab、Zabbix、Grafana、Kibana、Druid、Actuator；
- 组件：Fastjson、Log4j2、Shiro、XXL-JOB、RabbitMQ、Redis、Elasticsearch、MinIO；
- 办公/OA：致远、泛微、通达、蓝凌（国内 SRC 高频）。

## 报告口径

- 标题写清「组件+版本+CVE+影响」；证据含请求/响应或 nuclei 输出；
- KEV 命中要特别标注「在野利用」；
- 无法拿到真实影响的版本匹配：medium + 「版本匹配，行为未验证」，并给出复测步骤。
