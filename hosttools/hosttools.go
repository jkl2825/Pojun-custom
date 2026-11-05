// Package hosttools:宿主工具体检 + 安装配方。
//
// 二进制部署形态下,POJUN 直接跑在操作系统里——宿主装了什么渗透工具,
// worker 就能通过 Bash 工具直接调用什么。这里用 exec.LookPath 探测一份
// 常用工具清单(可用/缺失+安装提示),注入 graph_overview 让模型派意图时
// 知道家底,并通过 /api/tools/inventory 暴露给前端展示。
//
// 同一份清单同时驱动「一键安装」:每条工具带一个 Kind + 配方(apt 包名 /
// GitHub Release 资产模板 / pip 包 / 仅手工),由特权助手 pojun-hostd 按
// 配方执行。**体检清单和安装器共用这一个 catalog**,不存在"页面上列了、
// 安装器却不会装"的漂移。
//
// LookPath 只扫 PATH,单次微秒级,无需缓存。
package hosttools

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// Kind 安装方式。manual = 官方只提供交互式安装器,不做一键。
type Kind string

const (
	KindApt    Kind = "apt"    // 系统包管理器(apt/dnf)
	KindGitHub Kind = "github" // GitHub Release 单文件
	KindPip    Kind = "pip"    // pip / pipx
	KindManual Kind = "manual" // 不提供一键安装
)

// Category 攻击面分类。Kind 说「怎么装」,Category 说「干什么用在哪」——
// 目录里有 39 个工具,平铺成一张表没法看:用户要回答的是「Web 侧我有哪些家伙」,
// 而不是「一共有 39 行」。页面上按 Category 分组,模型侧的清单不受影响。
type Category string

const (
	CatNetwork  Category = "network"  // 端口扫描/连通性/基础网络
	CatWeb      Category = "web"      // Web 侧的探测、爆破、扫描
	CatDNS      Category = "dns"      // 资产测绘与域名枚举
	CatCred     Category = "cred"     // 在线爆破、离线破解、横向移动
	CatCode     Category = "code"     // 源码/密钥泄露、代码审计
	CatPivot    Category = "pivot"    // 内网穿透、代理转发
	CatOOB      Category = "oob"      // 带外通道、通知
	CatExploit  Category = "exploit"  // 框架与二进制利用
	CatMaterial Category = "material" // 字典、语料
	CatRuntime  Category = "runtime"  // 脚本、证书、HTTP 等基础能力
	// CatMiddleware 是中间件协议专项工具。
	//
	// 为什么单列一类（2026-10-22 调研）：近 30 天 NVD 上 CVSS≥9.0 的高危
	// 漏洞，中间件占了很大一块——apache/http_server、apache/cxf（SOAP）、
	// mariadb、rabbitmq_server、moquette(MQTT)、gitlab、splunk、f5/big-ip、
	// fortinet/fortimail…而通用扫描器（nmap/nuclei）对这类**协议型**中间件
	// 要么不认、要么只做通用探测。
	//
	// 这里的工具是**协议客户端库**——不是「一键打洞」的漏洞利用器，而是让
	// Agent 能直接跟中间件说话：枚举配置、读队列、订阅主题、调管理 API。
	// 「怎么打」仍由 Agent 结合漏洞情报决定。
	CatMiddleware Category = "middleware" // 中间件协议专项（MQTT/AMQP/DB/SOAP/设备等）
)

// categoryOrder 决定页面上的分组顺序——按攻击流程排：先摸清面(网络/DNS)→
// 再打(Web/凭据)→ 深入(代码/利用)→ 辅助(隧道/外带/资料/通用)。
var categoryOrder = []Category{
	CatNetwork, CatDNS, CatWeb, CatCred, CatCode,
	CatExploit, CatMiddleware, CatPivot, CatOOB, CatMaterial, CatRuntime,
}

// CategoryLabel 分类的中文标签(页面展示)。
func CategoryLabel(c Category) string {
	switch c {
	case CatNetwork:
		return "网络与主机"
	case CatWeb:
		return "Web 应用"
	case CatDNS:
		return "子域名与 DNS"
	case CatCred:
		return "凭据与口令"
	case CatCode:
		return "代码与密钥"
	case CatPivot:
		return "内网与隧道"
	case CatOOB:
		return "外带与回连"
	case CatExploit:
		return "漏洞利用"
	case CatMiddleware:
		return "中间件协议"
	case CatMaterial:
		return "资料与字典"
	case CatRuntime:
		return "通用与运行时"
	default:
		return "其他"
	}
}

// Tool 一条体检结果 + 安装配方。
type Tool struct {
	ID   string `json:"id"`   // 稳定标识(与 Bin 相同)
	Name string `json:"name"` // 工具名(展示用)
	Bin  string `json:"bin"`  // PATH 里探测的二进制名

	Available   bool     `json:"available"`
	Installable bool     `json:"installable"`       // 能否一键安装
	Purpose     string   `json:"purpose"`           // 干什么用(给模型看)
	Install     string   `json:"install,omitempty"` // 缺失时展示的安装提示
	Kind        Kind     `json:"kind"`
	Category    Category `json:"category"` // 攻击面分类(页面分组用)

	// kind=apt: 各包管理器下的包名
	Apt string `json:"-"`
	Dnf string `json:"-"`

	// kind=github: owner/repo + 资产名模板({ver} 不带 v,{arch} = amd64|arm64)
	// + 压缩包内二进制名(空 = 与 Bin 同名)
	Repo      string `json:"-"`
	AssetTmpl string `json:"-"`
	BinInZip  string `json:"-"`

	// kind=pip
	Pip string `json:"-"`

	// PipLibrary 标记这个 pip 包是**纯库**（没有命令行入口）。
	//
	// 为什么需要这个区分（2026-10-22 实测）：pipx 只能装「带 CLI 入口的应用」，
	// 装纯库会直接失败并报：
	//
	//	No apps associated with package gmqtt or its dependencies. If you are
	//	attempting to install a library, pipx should not be used.
	//
	// 中间件协议工具（gmqtt/pika/pymongo/zeep…）全是纯库——它们是给 Agent
	// 在脚本里 import 的，不是命令行工具。装它们必须走 pip。
	//
	// 现有那些有 CLI 的（wafw00f/netexec/semgrep/pwntools）继续走 pipx：
	// 隔离环境不会污染系统 Python，正是我们想要的。
	PipLibrary bool `json:"-"`
}

// catalog 常用渗透工具目录。安装方式优先选「自包含」的:能用 GitHub Release
// 单文件就不依赖 go install(宿主未必有 Go 工具链)。
var catalog = []Tool{
	{Name: "nmap", Purpose: "端口扫描/服务指纹", Kind: KindApt, Category: CatNetwork, Apt: "nmap", Dnf: "nmap"},
	{Name: "masscan", Purpose: "大规模端口快扫", Kind: KindApt, Category: CatNetwork, Apt: "masscan", Dnf: "masscan"},
	{Name: "sqlmap", Purpose: "SQL 注入检测与利用", Kind: KindApt, Category: CatWeb, Apt: "sqlmap", Dnf: "sqlmap"},
	{Name: "imagemagick", Purpose: "证据图片处理：拼图/水印/脱敏（报告照片证据必需）", Kind: KindApt, Category: CatRuntime, Apt: "imagemagick", Dnf: "ImageMagick"},
	{Name: "libreoffice", Purpose: "文档证据预览：Word/Excel/PPT→PDF（附件缩略图与报告预览）", Kind: KindApt, Category: CatRuntime, Apt: "libreoffice-writer libreoffice-calc libreoffice-impress", Dnf: "libreoffice-writer libreoffice-calc libreoffice-impress"},
	{Name: "poppler", Bin: "pdftoppm", Purpose: "PDF 转图片（文档证据预览必需）", Kind: KindApt, Category: CatRuntime, Apt: "poppler-utils", Dnf: "poppler-utils"},
	{Name: "ffuf", Purpose: "目录/参数模糊枚举", Kind: KindApt, Category: CatWeb, Apt: "ffuf", Dnf: "ffuf"},
	{Name: "gobuster", Purpose: "目录/DNS/vhost 爆破", Kind: KindApt, Category: CatWeb, Apt: "gobuster", Dnf: "gobuster"},
	{Name: "nikto", Purpose: "Web 服务器常见问题扫描", Kind: KindApt, Category: CatWeb, Apt: "nikto", Dnf: "nikto"},
	{Name: "whatweb", Purpose: "Web 指纹识别", Kind: KindApt, Category: CatWeb, Apt: "whatweb", Dnf: "whatweb"},
	{Name: "hydra", Purpose: "在线口令爆破(ssh/登录表单等)", Kind: KindApt, Category: CatCred, Apt: "hydra", Dnf: "hydra"},
	{Name: "john", Purpose: "离线口令破解", Kind: KindApt, Category: CatCred, Apt: "john", Dnf: "john"},
	{Name: "hashcat", Purpose: "GPU 口令破解", Kind: KindApt, Category: CatCred, Apt: "hashcat", Dnf: "hashcat"},
	{Name: "curl", Purpose: "HTTP 请求与调试", Kind: KindApt, Category: CatRuntime, Apt: "curl", Dnf: "curl"},
	{Name: "openssl", Purpose: "TLS 证书检查/加解密", Kind: KindApt, Category: CatNetwork, Apt: "openssl", Dnf: "openssl"},
	{Name: "python3", Purpose: "脚本执行/自定义 PoC", Kind: KindApt, Category: CatRuntime, Apt: "python3", Dnf: "python3"},
	{Name: "nc", Purpose: "TCP/UDP 连接与监听(反连交互)", Kind: KindApt, Category: CatNetwork, Apt: "netcat-openbsd", Dnf: "nmap-ncat"},
	{Name: "dig", Purpose: "DNS 查询", Kind: KindApt, Category: CatDNS, Apt: "dnsutils", Dnf: "bind-utils"},
	{Name: "ssh", Purpose: "登录验证/隧道", Kind: KindApt, Category: CatNetwork, Apt: "openssh-client", Dnf: "openssh-clients"},
	{Name: "testssl.sh", Bin: "testssl", Purpose: "TLS 配置弱项扫描", Kind: KindApt, Category: CatNetwork, Apt: "testssl.sh", Dnf: "testssl"},
	// nodejs 连 npx 一起装：MCP 里用 `npx @playwright/mcp` 启动 browser 服务器，
	// 机器上没有 node 时那个 MCP 永远连不上（实测每次 worker 启动都报
	// "npx: executable file not found in $PATH"）。
	{Name: "nodejs", Bin: "node", Purpose: "Node 运行时(npx 随装,供 MCP 服务器用)", Kind: KindApt, Category: CatRuntime, Apt: "nodejs", Dnf: "nodejs"},

	{Name: "nuclei", Purpose: "基于模板的漏洞扫描(漏洞情报联动)", Kind: KindGitHub, Category: CatWeb,
		Repo: "projectdiscovery/nuclei", AssetTmpl: "nuclei_{ver}_linux_{arch}.zip"},
	{Name: "httpx", Purpose: "Web 存活/指纹批量探测(projectdiscovery 版)", Kind: KindGitHub, Category: CatWeb,
		Repo: "projectdiscovery/httpx", AssetTmpl: "httpx_{ver}_linux_{arch}.zip"},
	{Name: "subfinder", Purpose: "子域名枚举", Kind: KindGitHub, Category: CatDNS,
		Repo: "projectdiscovery/subfinder", AssetTmpl: "subfinder_{ver}_linux_{arch}.zip"},
	// ProjectDiscovery 系另外三个：naabu(端口扫)、dnsx(DNS 解析/爆破)、
	// katana(爬虫)、tlsx(TLS 证书探测)。资产命名与上面三个同构
	// （{tool}_{ver}_linux_{arch}.zip），所以一个 AssetTmpl 模板就够。
	{Name: "naabu", Purpose: "快速端口扫描(与 httpx 联动筛存活)", Kind: KindGitHub, Category: CatNetwork,
		Repo: "projectdiscovery/naabu", AssetTmpl: "naabu_{ver}_linux_{arch}.zip"},
	{Name: "dnsx", Purpose: "DNS 解析/爆破/记录提取", Kind: KindGitHub, Category: CatDNS,
		Repo: "projectdiscovery/dnsx", AssetTmpl: "dnsx_{ver}_linux_{arch}.zip"},
	{Name: "katana", Purpose: "Web 爬虫(爬深层路径与参数)", Kind: KindGitHub, Category: CatWeb,
		Repo: "projectdiscovery/katana", AssetTmpl: "katana_{ver}_linux_{arch}.zip"},
	// waybackurls / gau：历史 URL 收集。katana 只爬当前站点，挖不到早已下线但
	// 仍可访问的老接口/老参数，这两个走第三方存档(wayback/otx/commoncrawl)补这块。
	// 资产命名：waybackurls 是 `名称-linux-架构-版本.tgz`（架构在中间、无 v 前缀），
	// gau 是标准 `gau_版本_linux_架构.tar.gz`——两者不同构，模板不能复用。
	{Name: "waybackurls", Purpose: "历史 URL 收集(Wayback Machine, 挖已下线接口)", Kind: KindGitHub, Category: CatWeb,
		Repo: "tomnomnom/waybackurls", AssetTmpl: "waybackurls-linux-{arch}-{ver}.tgz"},
	{Name: "gau", Purpose: "历史 URL 收集(wayback/otx/commoncrawl 多源聚合)", Kind: KindGitHub, Category: CatWeb,
		Repo: "lc/gau", AssetTmpl: "gau_{ver}_linux_{arch}.tar.gz"},
	{Name: "tlsx", Purpose: "TLS 证书信息提取(证书/ SAN / 过期)", Kind: KindGitHub, Category: CatNetwork,
		Repo: "projectdiscovery/tlsx", AssetTmpl: "tlsx_{ver}_linux_{arch}.zip"},

	{Name: "wafw00f", Purpose: "WAF 识别", Kind: KindPip, Category: CatWeb, Pip: "wafw00f"},
	// arjun / commix：ffuf 能爆破已知参数位，但发现不了"字段名未知"的隐藏参数
	// （arjun 干这个）；命令注入手工试 payload 效率低（commix 干这个）。
	// 两者都是带 CLI 入口的 pip 应用，走 pipx 也能装，这里用 pip 与现网一致。
	{Name: "arjun", Purpose: "HTTP 隐藏参数发现(GET/POST 字段枚举)", Kind: KindPip, Category: CatWeb, Pip: "arjun"},
	{Name: "commix", Purpose: "命令注入检测与利用", Kind: KindPip, Category: CatWeb, Pip: "commix"},
	// impacket 是 SMB/NTLM/票据的 Python 库(提供 msmfmap、ntlmrelay、secretsdump
	// 等脚本)。apt 源里的包名是 python3-impacket,Debian/Ubuntu 都有。
	{Name: "impacket", Purpose: "SMB/NTLM 协议工具集(secretsdump/ntlmrelay 等)", Kind: KindApt, Category: CatCred,
		Apt: "python3-impacket", Dnf: "python3-impacket"},
	// SecLists 是最大的通用字典集(目录爆破/参数 fuzz 的语料)。apt 源里没有
	// 稳定包名,只能从 GitHub 克隆——但它是目录而非单文件,GitHub 配方装不了,
	// 所以走 KindManual 并在 install.sh 里单独克隆。
	{Name: "seclists", Purpose: "通用字典集(目录/参数/用户名爆破语料)", Kind: KindManual, Category: CatMaterial,
		Install: "git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists"},

	// ── 资产命名与上面不同的项目 ──
	// 各项目的 release 资产名规范很不统一（架构在前/后、版本带不带 v、
	// 扩展名 .zip/.tar.gz/.gz），所以模板必须逐个按实测资产名写。
	// 这些资产名都是 2026-10 实测 GitHub API 得到的，不是猜的。

	// gitleaks：资产名用 x64（不是 x86_64），且是 .tar.gz。
	{Name: "gitleaks", Purpose: "代码/配置里的密钥扫描(检测硬编码凭据)", Kind: KindGitHub, Category: CatCode,
		Repo: "gitleaks/gitleaks", AssetTmpl: "gitleaks_{ver}_linux_{arch4}.tar.gz"},
	// chisel：内网穿透/隧道工具（SOCKS 隧道、反向隧道都靠它）。
	{Name: "chisel", Purpose: "内网穿透与隧道(TCP/UDP/SOCKS 隧道)", Kind: KindGitHub, Category: CatPivot,
		Repo: "jpillora/chisel", AssetTmpl: "chisel_{ver}_linux_{arch}.gz"},
	// amass：子域名枚举（OWASP）。资产名里**没有版本号**，所以模板不带 {ver}。
	{Name: "amass", Purpose: "子域名枚举(OWASP,主动+被动解析)", Kind: KindGitHub, Category: CatDNS,
		Repo: "OWASP/Amass", AssetTmpl: "amass_linux_{arch}.tar.gz"},
	// dalfox：XSS 扫描与利用。资产名带 v 前缀、架构用 x86_64/aarch64。
	{Name: "dalfox", Purpose: "XSS 扫描与利用(反射型/存储型/DOM)", Kind: KindGitHub, Category: CatWeb,
		Repo: "hahwul/dalfox", AssetTmpl: "dalfox-{verv}-linux-{arch2}.tar.gz"},
	// feroxbuster：目录/文件爆破（Rust 版 gobuster 替代）。
	// 注意它的资产名**架构在前**，且 amd64 用 x86_64、arm64 用 aarch64。
	{Name: "feroxbuster", Purpose: "目录/文件爆破(Rust 版,支持多线程与递归)", Kind: KindGitHub, Category: CatWeb,
		Repo: "epi052/feroxbuster", AssetTmpl: "{arch2}-linux-feroxbuster.tar.gz"},
	// ── 红队后渗透补齐（2026-10-30）：权限保持/横向/隧道/凭据 ──
	// socat：nc 的全能替代（双向管道、TLS、转发），反弹 shell 稳定化的标配。
	{Name: "socat", Purpose: "多用途网络中继(反弹 shell 稳定化/端口转发)", Kind: KindApt, Category: CatPivot,
		Apt: "socat", Dnf: "socat"},
	// proxychains4：让任意 TCP 工具走 SOCKS 隧道（配 chisel/ligolo 的隧道口）。
	{Name: "proxychains4", Bin: "proxychains4", Purpose: "任意 TCP 工具走 SOCKS 代理(隧道出口)", Kind: KindApt, Category: CatPivot,
		Apt: "proxychains4", Dnf: "proxychains-ng"},
	// evil-winrm：Windows 目标 WinRM 落地 shell（横向移动的标配落点）。
	// GitHub release 只有源码（无二进制），Kali/Debian 走 apt 包。
	{Name: "evil-winrm", Purpose: "WinRM 落地 shell(Windows 横向落地)", Kind: KindApt, Category: CatPivot,
		Apt: "evil-winrm"},
	// ligolo-ng：TUN 式反向代理（比 SOCKS 更顺手的内网直达）。
	// 资产名 2026-10-30 实测：ligolo-ng_proxy_<ver>_linux_amd64.tar.gz（官方
	// 仓库是 nicocha30/ligolo-ng——猜 fork 名会 404）。
	{Name: "ligolo-ng", Purpose: "TUN 反向代理(内网直达/双 bind)", Kind: KindGitHub, Category: CatPivot,
		Repo: "nicocha30/ligolo-ng", AssetTmpl: "ligolo-ng_proxy_{ver}_linux_{arch}.tar.gz"},
	// responder：LLMNR/NBT-NS 毒化（Windows 内网凭据捕获）。GitHub 无 release，
	// Kali/Debian 有 apt 包（上游源码形态是目录，GitHub 配方装不了）。
	{Name: "responder", Purpose: "LLMNR/NBT-NS 毒化(内网凭据捕获)", Kind: KindApt, Category: CatCred,
		Apt: "responder"},
	// tcpdump：内网抓包（流量取证/凭据嗅探的证据面）。
	{Name: "tcpdump", Purpose: "网络抓包(流量取证)", Kind: KindApt, Category: CatNetwork,
		Apt: "tcpdump", Dnf: "tcpdump"},
	// pspy：无特权进程监视（发现 cron/服务类权限保持点）。资产名固定
	// pspy64/pspy32（2026-10-30 实测，无版本号、repo 已归档=最后版本不变）。
	{Name: "pspy", Bin: "pspy64", Purpose: "无特权进程监视(发现权限保持点)", Kind: KindGitHub, Category: CatExploit,
		Repo: "DominicBreuker/pspy", AssetTmpl: "pspy64"},
	// linpeas：Linux 提权枚举（后渗透第一脚本的行业标准）。资产实测
	// linpeas_linux_amd64（无扩展名，arch 模板对齐）。
	{Name: "linpeas", Bin: "linpeas", Purpose: "Linux 提权枚举(PEASS 系列)", Kind: KindGitHub, Category: CatExploit,
		Repo: "peass-ng/PEASS-ng", AssetTmpl: "linpeas_linux_{arch}"},
	// sshuttle：SSH 翻越（把远端网段拉进本机路由表）。
	{Name: "sshuttle", Purpose: "SSH 隧道直连远端网段(路由级 pivot)", Kind: KindApt, Category: CatPivot,
		Apt: "sshuttle", Dnf: "sshuttle"},

	// notify：外带/回连数据接收（DNS/HTTP/TLS 多种通道）。
	{Name: "notify", Purpose: "外带数据接收(DNS/HTTP/TLS 多通道)", Kind: KindGitHub, Category: CatOOB,
		Repo: "projectdiscovery/notify", AssetTmpl: "notify_{ver}_linux_{arch}.zip"},
	// interactsh-client：OOB 交互式探测的客户端（配合 nuclei 的 oob 模板）。
	{Name: "interactsh-client", Bin: "interactsh-client", Purpose: "OOB 回连客户端(配合 nuclei 的 oob 模板)", Kind: KindGitHub, Category: CatOOB,
		Repo: "projectdiscovery/interactsh", AssetTmpl: "interactsh-client_{ver}_linux_{arch}.zip"},
	// netexec：SMB/Windows 协议横移（CrackMapExec 的现代替代）。
	// 注意（2026-11 实测）：NetExec 商业化后把 PyPI 上的发行文件全部撤下
	// （/simple/netexec 404），pip 配方必失败——体检会如实显示缺失；
	// 需要时从 https://github.com/Pennyw0rth/NetExec 源码安装（uv/pipx + git）。
	{Name: "netexec", Bin: "netexec", Purpose: "SMB/WinRM 横移与凭据喷洒(现代版 CrackMapExec；PyPI 已撤包，需源码安装)", Kind: KindPip, Category: CatCred,
		Pip: "netexec"},
	// semgrep：SAST 规则扫描（对下载到的源码做规则匹配）。
	{Name: "semgrep", Purpose: "源码静态规则扫描(SAST)", Kind: KindPip, Category: CatCode, Pip: "semgrep"},
	// pwntools：漏洞利用脚本框架（agent 写 exploit 时用）。
	{Name: "pwntools", Bin: "pwntools", Purpose: "漏洞利用脚本框架(写 exploit 用)", Kind: KindPip, Category: CatExploit, Pip: "pwntools"},

	// ── 中间件协议专项 (2026-10-22 调研新增) ──────────────────────────
	//
	// 依据：近 30 天 NVD 上 CVSS≥9.0 的高危漏洞，中间件占比很大
	// （apache/http_server、apache/cxf、mariadb、rabbitmq_server、
	// moquette(MQTT)、gitlab、splunk、f5/big-ip、fortinet/fortimail…），
	// 而通用扫描器（nmap/nuclei）对这类协议型中间件要么不认、要么只做通用探测。
	//
	// 这些是**协议客户端库**，不是「一键打洞」的利用器：让 Agent 能直接跟中间件
	// 说话——枚举配置、读队列、订阅主题、调管理 API。「怎么打」由 Agent 结合
	// 漏洞情报（search_vulns / search_recent_critical）决定。
	//
	// 包名全部经 PyPI API 核实存在（2026-10-22）。两个易踩的坑：
	//   - MQTT 的包名是 **paho-mqtt**（不是 paho——后者在 PyPI 上不存在，
	//     同名近似包是供应链投毒的常见入口）；
	//   - PostgreSQL 驱动要用 **psycopg2-binary**（psycopg2 是纯 sdist，
	//     一键安装会退化成源码编译，很多机器上直接失败）。

	// MQTT：broker 枚举、主题订阅/发布。
	{Name: "gmqtt", Purpose: "MQTT 协议客户端(枚举/订阅/发布 broker)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "gmqtt"},
	{Name: "paho-mqtt", Purpose: "MQTT 协议客户端(脚本用,支持 v3.1.1/v5)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "paho-mqtt"},
	// 消息队列：AMQP / Kafka / 多协议。
	{Name: "pika", Purpose: "RabbitMQ AMQP 协议客户端(读队列/投递)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "pika"},
	{Name: "amqpstorm", Purpose: "RabbitMQ 管理 API + AMQP 客户端", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "amqpstorm"},
	{Name: "confluent-kafka", Purpose: "Kafka 协议客户端(读 topic/消费组)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "confluent-kafka"},
	{Name: "kombu", Purpose: "多协议消息队列客户端(AMQP/Redis/SQS 等)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "kombu"},
	// 数据库协议：直连枚举与数据读取。
	{Name: "pymongo", Purpose: "MongoDB 协议客户端(枚举库/读集合)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "pymongo"},
	{Name: "pymysql", Purpose: "MySQL 协议客户端(枚举库/读表)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "pymysql"},
	{Name: "psycopg2-binary", Purpose: "PostgreSQL 协议客户端(枚举库/读表)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "psycopg2-binary"},
	{Name: "redis-py", Bin: "redis", Purpose: "Redis 协议客户端(枚举键/读配置)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "redis"},
	// SOAP/XML 中间件：Apache CXF 之类 SOAP 服务的协议客户端。
	{Name: "zeep", Purpose: "SOAP 客户端(枚举 WSDL/调用接口,适用 CXF 等)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "zeep"},
	// 代码托管平台：GitLab 的 REST/GraphQL API。
	{Name: "python-gitlab", Purpose: "GitLab API 客户端(枚举项目/用户/流水线)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "python-gitlab"},
	// 网络设备：交换机/路由器的 CLI 交互与自动化。
	{Name: "netmiko", Purpose: "网络设备 CLI 交互(多厂商 SSH)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "netmiko"},
	{Name: "napalm", Purpose: "多厂商网络设备自动化(取配置/路由表)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "napalm"},
	// 日志/SIEM：Splunk 的 REST API。
	{Name: "splunk-sdk", Purpose: "Splunk API 客户端(检索/枚举)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "splunk-sdk"},

	{Name: "msfconsole", Purpose: "Metasploit 框架(exploit/encoder)", Kind: KindManual, Category: CatExploit,
		Install: "官方安装包(需交互): https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/"},
}

// normalize 补齐派生字段并做路径探测。
func normalize(t Tool) Tool {
	if t.Bin == "" {
		t.Bin = t.Name
	}
	t.ID = t.Bin
	if t.BinInZip == "" {
		t.BinInZip = t.Bin
	}
	t.Installable = t.Kind != KindManual
	return t
}

// humanInstall 给缺失项生成人类可读的安装提示(没有配方时回落到系统包名)。
func humanInstall(t Tool) string {
	switch t.Kind {
	case KindApt:
		return "apt install " + t.Apt
	case KindGitHub:
		return "GitHub Release: https://github.com/" + t.Repo + "/releases"
	case KindPip:
		return "pip install " + t.Pip
	}
	if t.Install != "" {
		return t.Install
	}
	return ""
}

// Catalog 返回目录的副本(含派生字段,未探测可用性)。
func Catalog() []Tool {
	out := make([]Tool, len(catalog))
	for i, t := range catalog {
		out[i] = normalize(t)
	}
	return out
}

// Lookup 按 id 取配方;ok=false 表示不在白名单内——这是特权助手唯一的
// 输入校验依据:凡是这里查不到的 id 一律拒绝执行。
func Lookup(id string) (Tool, bool) {
	for _, t := range catalog {
		n := normalize(t)
		if n.ID == id {
			return n, true
		}
	}
	return Tool{}, false
}

// AvailableInPath 该工具当前是否已在 PATH 内。
func (t Tool) AvailableInPath() bool {
	_, err := exec.LookPath(t.Bin)
	return err == nil
}

// Inventory 探测全部目录项(顺序与 catalog 一致)。
func Inventory() []Tool {
	out := make([]Tool, len(catalog))
	for i, t := range catalog {
		n := normalize(t)
		n.Available = false
		if _, err := exec.LookPath(n.Bin); err == nil {
			n.Available = true
			n.Install = ""
		} else {
			n.Install = humanInstall(n)
		}
		out[i] = n
	}
	return out
}

// Summary 注入 graph_overview / API 的紧凑形态:
// available 是可直接调用的二进制名清单;missing 带安装提示;
// hint 给模型一句话用法约定。
//
// available 里每项都带**用途**（"name: 用途"），不只给名字。
// 理由很实际：目录里现在有 30+ 个工具，模型只看到名字（chisel / dalfox /
// feroxbuster…）根本判断不出该在什么场景调哪一个，只能瞎试或者干脆不用。
// 带上用途后"派意图选手段以家底为准"才真正成立。
func Summary() map[string]any {
	inv := Inventory()
	avail := make([]string, 0, len(inv))
	missing := make([]string, 0, len(inv))
	for _, t := range inv {
		if t.Available {
			if t.Purpose != "" {
				avail = append(avail, t.Bin+": "+t.Purpose)
			} else {
				avail = append(avail, t.Bin)
			}
		} else {
			// 缺失项只给名字——安装提示是给人看的（宿主环境页），模型既不能装
			// 也不需要知道怎么装，给它 27 条安装命令只是每轮都在烧上下文。
			missing = append(missing, t.Name)
		}
	}
	return map[string]any{
		"available": avail,
		"missing":   missing,
		"hint":      "available 是本机 PATH 里可直接经 Bash 调用的工具，格式为「命令名: 用途」——派意图选手段时按用途挑，别只认得名字；missing 是本机没有的工具，不要臆测它们的存在。需要缺失工具时在意图/小结里向用户提示安装命令，不要自行安装。",
	}
}

// SummaryText 纯文本形态（提示词注入用）：一行一个可用工具，带用途。
//
// 只列【可用】的：缺失的工具模型既不能调，也不该在提示里占位置（一次
// worker 运行的 system prompt 里放几十条「未安装」纯属浪费上下文）。
// 用途必须带上——只给名字的话模型判断不出该在什么场景调哪个
// （chisel / dalfox / feroxbuster 这类尤其明显）。
//
// 曾经这个函数定义了却没有调用方：工具清单只进了 planner 的唤醒提示，
// 而真正动手的 worker 看不到它——于是新装的一批工具一次都没被用起来。
func SummaryText() string {
	var b strings.Builder
	avail := 0
	for _, t := range Inventory() {
		if !t.Available {
			continue
		}
		avail++
		if t.Purpose != "" {
			b.WriteString("✓ " + t.Bin + " —— " + t.Purpose + "\n")
		} else {
			b.WriteString("✓ " + t.Bin + "\n")
		}
	}
	if avail == 0 {
		return ""
	}
	return "可用工具 " + strconv.Itoa(avail) + " 个（都是本机 PATH 里可直接经 Bash 调用的命令）：\n" + b.String() +
		"\n动手前先想一下这些工具能不能直接解决问题——别用 python3 从头造轮子，" +
		"也别因为不认得某个工具的名字就忽略它。确实需要本机没有的工具时，" +
		"在意图/小结里写清楚要装什么，不要自行安装。"
}

// Arch 归一化为 Release 资产里用的架构名。
func Arch() string {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return runtime.GOARCH
	default:
		return runtime.GOARCH
	}
}

// ArchAlt 返回另一种架构命名：amd64→x86_64、arm64→aarch64。
//
// GitHub 上各项目的资产命名不统一：ProjectDiscovery 系用 amd64/arm64，
// gitleaks/amass 用 x86_64/aarch64，chisel 的部分资产用 x86/arm。
// 模板里用 {arch}/{arch2}/{arch3} 分别对应这三套。
func ArchAlt() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH
	}
}

// ArchShort 返回更短的架构命名：amd64→x86、arm64→arm。
func ArchShort() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86"
	case "arm64":
		return "arm"
	default:
		return runtime.GOARCH
	}
}

// ArchX64 返回 gitleaks 用的命名：amd64→x64、arm64→arm64。
//
// 这是第四套命名——实测 gitleaks 的资产是 gitleaks_8.30.1_linux_x64.tar.gz
// 与 ..._linux_arm64.tar.gz，即 amd64 叫 x64、arm64 叫 arm64。
func ArchX64() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	default:
		return runtime.GOARCH
	}
}
