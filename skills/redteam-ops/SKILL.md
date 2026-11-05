# 红队后渗透方法论

## 边界与禁止

- 仅在授权范围内操作，遵守【操作约束】；
- 不得破坏目标系统可用性，不得删除/篡改业务数据；
- 敏感数据点到为止（证明可获取即可），不批量导出、不留存、不外传；
- 所有操作必须留证（截图/命令输出/流量 ID）。

## 阶段 0：落地稳定化

拿到初始访问后先稳定立足点，避免掉线后重复工作：

1. 确认当前身份（whoami / id / hostname）与权限等级；
2. 确认网络位置（ip addr / ifconfig / ipconfig），标注内网段与可达网段；
3. 检查现有持久化（计划任务、服务、启动项），如需添加按任务约束执行；
4. 把获取的凭据/令牌/密钥**全文**（不缩写、不掩码）写入 fact（凭据是后续横向的弹药）。

## 阶段 1：信息收集与提权

### Linux
- `sudo -l` 检查 sudo 权限（GTFOBins 查利用方式）；
- SUID/SGID 文件：`find / -perm -4000 -type f 2>/dev/null`；
- 定时任务：`cat /etc/crontab` + `ls -la /etc/cron.d/` + 用户 crontab；
- 内核版本：`uname -a` → search_vulns 查已知提权 CVE；
- 环境变量：`env | grep -i pass\|token\|key\|secret`；
- SSH 密钥：`find / -name "id_rsa" 2>/dev/null`、`cat ~/.ssh/authorized_keys`；
- 历史命令：`cat ~/.bash_history`（往往包含其他凭据或内网信息）。

### Windows
- 当前用户权限：`whoami /priv`（关注 SeImpersonate/SeDebug/SeBackup）；
- 域信息：`whoami /groups`（是否 Domain Admins/Enterprise Admins）；
- 存储的凭据：`cmdkey /list`、PowerShell `Get-StoredCredential`；
- 计划任务：`schtasks /query /fo LIST`；
- 服务：`wmic service get name,pathname,startmode`（查找 unquoted path）;
- 始终用 `winPEAS` 或 `PowerUp.ps1` 做全面检查（宿主工具已装）。

## 阶段 2：横向移动

1. **凭据复用优先**：拿到凭据后先试 SSH/SMB/RDP/WinRM 到已知内网 IP；
2. **pass-the-hash/pass-the-ticket**：impacket 工具族（psexec.py/wmiexec.py/secretsdump.py）；
3. **端口转发/隧道**：ligolo-ng（TUN 方式）或 socat（端口转发）；
4. **扫描内网**：已知网段内 `nmap -sV --top-ports 100` 或 `crackmapexec smb <网段>/24`；
5. **凭据喷射**：对发现的服务用收集到的凭据逐个尝试（限制并发避免锁号）。

## 阶段 3：数据获取

- 数据库凭据：从配置文件（.env/config.php/web.config/application.yml）提取；
- 数据库交互：mysql/psql/mssql 客户端连接，**只做 SELECT**（读证明数据即可）；
- 文件下载：目标系统的导出/下载接口（Excel/PDF/JSON）；
- 关键标识：用户表含身份证号/手机号、财务表含金额/交易记录、配置文件含 API 密钥。

## 阶段 4：Windows 域环境专项

- **信息枚举**：`Get-ADUser`/`Get-ADComputer`/`Get-ADGroup`（PowerShell ActiveDirectory 模块）；
- **Kerberoasting**：`GetUserSPNs.py domain/user:pass -dc-ip <DC>` → hashcat 破解；
- **AS-REP Roasting**：`GetNPUsers.py domain/ -usersfile users.txt -no-pass`；
- **DCSync**：`secretsdump.py domain/admin:pass@dc-ip`（需域管理员权限）；
- **BloodHound**：SharpHound.exe 采集 → BloodHound 分析攻击路径（宿主需安装）；
- **GPP 密码**：`gpp-decrypt` 解析 SYSVOL 中的组策略 XML。

## 阶段 5：权限维持与清理

- 测试环境的权限维持仅限 demonstration（写一条 fact 证明"可以做到"即可，不实际部署）；
- 清理测试痕迹：删除上传的脚本/工具文件、还原修改过的配置、关闭创建的监听器。

## 证据纪律

- **每个阶段都要 save_evidence**（截图或命令输出）；
- **凭据全文写进 fact**（不缩写不掩码）；
- **每步标注 confidence**：observed（直接看到）vs inferred（推断）；
- **流量 ID 引用**：HTTP 操作用 traffic_search 查 ID 并绑定到 finding。
