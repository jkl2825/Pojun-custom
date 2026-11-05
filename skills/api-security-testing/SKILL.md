---
name: api-security-testing
description: 已有接口清单/流量/前端 JS 里的 API 时做接口安全测试调用——契约提取(api_contract)、双身份对照(auth_request)、响应差分(diff_responses)、越权/未授权/参数污染的验证路径。当意图涉及「测接口/越权/未授权访问/API」时使用。
tags:
  cwe: [CWE-639, CWE-862, CWE-306, CWE-284, CWE-915]
  attack: [T1190, T1078]
  class: [api-security, idor, broken-authz, contract, differential]
---

# API 安全测试（围绕平台三个接口工具）

## 平台工具怎么配合

| 工具 | 用途 |
|---|---|
| `api_contract` | 从前端 JS / 流量里提取接口契约（路径/方法/参数/是否带鉴权） |
| `auth_request` | 用**资产上已登记的凭据**组装带认证请求命令（只组命令，Bash 执行） |
| `diff_responses` | 对比两个响应的结构/字段差异（越权与信息泄露的判据） |

## 流程

1. **建契约清单**：`api_contract` 提取接口；没有前端时从流量/JS 里手工补；
2. **分类打标**：公开 / 需登录 / 需特权 / 内部（看响应特征与 JS 调用上下文）；
3. **双身份对照**：
   - 身份 A（低权/无凭据）→ 身份 B（另一账号或已登记凭据）；
   - 同一资源分别请求，`diff_responses` 看数据是否相同/字段是否泄露；
4. **验证四类缺陷**：
   - 未授权访问：无 token 直接 200 + 业务数据；
   - 水平越权（IDOR）：A 的 token 读 B 的对象；
   - 垂直越权：低权账号打高权接口（返回 200 或仅前端隐藏）；
   - 参数污染/批量赋值：多传 `role/isAdmin/tenantId/userId` 看是否被采纳。

## 判定标准（写报告用）

- **L3 证据**：不同身份的响应体差异（含他人数据字段）、或未授权拿到业务数据；
- 仅返回 200 但无业务数据 → 不算越权，最多记为「接口存在」；
- 前端隐藏 ≠ 后端校验：必须直接调用接口确认；
- `diff_responses` 结果里指出具体差异字段（时间戳/ID/姓名等），不要只说「有差异」。

## 常见绕过

- 路径：`/api/v1/user/1` vs `/api/v1/user/1/`（尾斜杠）、大小写、`//`、`%2e`；
- 方法：GET↔POST 互换、`X-HTTP-Method-Override`、OPTIONS 探 Allow；
- 参数位置：query↔body↔header 三处都试（很多后端只校验一处）；
- 批量/分页：`size=1000`、`page=0`、`fields=*`、`expand=all` 拿全量；
- 签名/时间戳：参数排序、空值、时间窗重放（看服务端是否只查非空）。

## 流量与证据

- 每个验证请求确认被 MITM 代理记录（HTTP 请求都会留流量 ID）；
- `report_finding` 绑定 baseline（正常请求）/proof（越权请求）两类流量；
- 敏感数据只取最小样本（一条记录），不批量拉取。

## 与侦察的分工

- 接口**发现**归 `api-recon`（前端路由/JS/参数）；本 skill 负责拿到清单后的**验证**；
- 发现新接口/新参数顺手 `record_fact`，供后续意图复用。
