---
name: source-code-hunting
description: 拿到目标源码/仓库（白盒或泄露源码）做代码审计时调用——危险 sink 定位、框架模式识别、git 历史挖掘、依赖 CVE、semgrep/gitleaks 用法与从代码到可利用性的验证路径。
tags:
  cwe: [CWE-89, CWE-78, CWE-502, CWE-22, CWE-798, CWE-287]
  attack: [T1552.001, T1213]
  class: [whitebox, code-audit, sast, secrets]
---

# 源码审计方法论

## 先做三件事（比逐行读快 10 倍）

1. **看仓库全貌**：语言/框架/入口文件/路由表/依赖清单（pom.xml/package.json/go.mod/requirements.txt）；
2. **找秘密**：`gitleaks detect --source . -v`、`semgrep --config p/secrets`；`.env`/配置/硬编码 AK；
3. **git 历史**：`git log --oneline --all | head -50`、`git log -p -- .env`（删除过又提交的密钥仍在历史里）。

## sink 驱动审计（从危险函数反向找输入）

| 类型 | 语言 | sink 关键词 |
|---|---|---|
| SQLi | Java/PHP/Py/Go | `Statement.execute*`、`${}`拼接、`db.Raw`、`cursor.execute(f"` |
| 命令注入 | 全部 | `Runtime.exec`、`ProcessBuilder`、`os.system`、`subprocess(...,shell=True)`、`exec.Command("sh","-c"` |
| 反序列化 | Java | `ObjectInputStream`、`readObject`、Fastjson `JSON.parse*`、XStream |
| SSRF | 全部 | `http.Get(req.Param`、`requests.get(`、`urllib`、`new URL(input)` |
| 文件 | 全部 | `../`拼接、`os.path.join(base, user)`、`FileInputStream(user)`、`sendFile` |
| 模板注入 | Java/Py | `Template.process`、`render_template_string`、`new Template(input)` |
| 越权 | 全部 | 直接用请求 id 查库（无 owner 校验）、`findById(param)` 后不比对当前用户 |

## 框架模式（国内常见）

- 若依 RuoYi：`@PreAuthorize` 缺失、`/common/download?fileName=`（路径穿越）、`gen` 模块 SQL 注入；
- Spring Boot：`@RequestMapping` 通配、Actuator 暴露、SpEL 注入点（`#{...}`）；
- ThinkPHP：`input()` 直接进 `whereRaw`、`invokeFunction`、多语言 `lang` 参数 LFI；
- JeecgBoot：`/jmreport/*`、Freemarker 模板注入、`queryTableData` SQL；
- Laravel：`unserialize`、`.env` 暴露、`Debugbar`；
- Django：`raw()`/`extra()`、`mark_safe`、`DEBUG=True`。

## 从代码到可利用性

1. 确认入口可达（路由/鉴权过滤器是否拦）；
2. 确认参数可控（谁传进来、有没有校验）；
3. 本地起服务验证或构造与线上一致的请求（用 `http_probe`/curl 打真实目标）；
4. 代码级证据 + 实际回显 = 高可信；只有代码推断 → 最多 medium 且注明「代码审计，未验证」。

## semgrep / 依赖

- `semgrep --config auto .` 快速起量，重点看 high confidence 项；
- 依赖：`mvn dependency:tree`/`npm audit`/`gosum` + `search_vulns` 匹配版本；
- 依赖命中同样要行为验证（版本匹配 ≠ 漏洞）。

## 输出

- 每个候选点写 fact：文件:行号、sink、输入来源、是否可达、验证状态；
- 确认后 report_finding 的 evidence 附代码片段 + 实际请求响应；
- 修复建议具体到函数级（参数化/白名单/编码）。
