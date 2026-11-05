#!/usr/bin/env bash
# Docker 镜像内置工具安装（构建期执行，docker/install-tools.sh）。
#
# 与二进制形态 install.sh --with-tools 的工具集对齐——Docker 形态没有
# pojun-hostd 一键安装（特权助手只服务 systemd 部署），所以宿主环境
# 「体检」页看到的工具必须在镜像里就带全，否则永远显示缺失。
#
# 差异说明（相对 --with-tools）：
#   - nuclei 不在这里装：Dockerfile 单独装（带版本验证）
#   - SecLists 装到 /opt/SecLists（与 hosttools.go 目录引用一致）
#   - 公文字体由 Dockerfile 直接 COPY 仓库内 report/fonts（构建期不下载）
set -euo pipefail

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }

# fetch：下载重试——GitHub release blob 当天抖动是常态（2026-11-05 实测
# CI 上同 URL 一轮全通、下一轮全断），三轮间隔 8s 能跨过大多数抖动窗口。
fetch(){
  local url="$1" out="$2" i
  for i in 1 2 3; do
    curl -fsSL --retry 2 --connect-timeout 15 --max-time 300 "$url" -o "$out" && return 0
    sleep 8
  done
  return 1
}

arch="$(dpkg --print-architecture)"
case "$arch" in
  amd64) pa="amd64"  p2="x86_64"  p3="x86" p4="x64" lin="x86_64" ;;
  arm64) pa="arm64"  p2="aarch64" p3="arm" p4="arm64" lin="arm64" ;;
  *) echo "unsupported arch: $arch"; exit 1 ;;
esac

# ── apt 渗透组已在 Dockerfile 基础层逐包容错装好 ──
# （masscan/sqlmap/hydra/whatweb/nikto/ffuf/john/impacket/socat/proxychains4；
#   bookworm 源缺的包（如 nikto）构建日志有 [warn]，体检页如实显示缺失）

# ── GitHub Release 单文件 ────────────────────────────
# 表：repo|资产模板|二进制名。占位符 {ver}(不带v) {verv}(带v)
# {arch}(amd64/arm64) {arch2}(x86_64/aarch64) {arch3}(x86/arm) {arch4}(x64/arm64)。
# 与 install.sh 同表（nuclei/gitleaks 已由 Dockerfile/apt 覆盖的除外）。
specs="
projectdiscovery/httpx|httpx_{ver}_linux_{arch}.zip|httpx
projectdiscovery/subfinder|subfinder_{ver}_linux_{arch}.zip|subfinder
projectdiscovery/naabu|naabu_{ver}_linux_{arch}.zip|naabu
projectdiscovery/dnsx|dnsx_{ver}_linux_{arch}.zip|dnsx
projectdiscovery/katana|katana_{ver}_linux_{arch}.zip|katana
projectdiscovery/tlsx|tlsx_{ver}_linux_{arch}.zip|tlsx
projectdiscovery/notify|notify_{ver}_linux_{arch}.zip|notify
projectdiscovery/interactsh|interactsh-client_{ver}_linux_{arch}.zip|interactsh-client
gitleaks/gitleaks|gitleaks_{ver}_linux_{arch4}.tar.gz|gitleaks
jpillora/chisel|chisel_{ver}_linux_{arch}.gz|chisel
OWASP/Amass|amass_linux_{arch}.tar.gz|amass
hahwul/dalfox|dalfox-{verv}-linux-{arch2}.tar.gz|dalfox
epi052/feroxbuster|{arch2}-linux-feroxbuster.tar.gz|feroxbuster
OJ/gobuster|gobuster_Linux_{lin}.tar.gz|gobuster
"

tmpd="$(mktemp -d)"
trap 'rm -rf "$tmpd"' EXIT
for spec in $specs; do
  repo="$(printf '%s' "$spec" | cut -d'|' -f1)"
  tmpl="$(printf '%s' "$spec" | cut -d'|' -f2)"
  bin="$(printf '%s' "$spec" | cut -d'|' -f3)"
  if command -v "$bin" >/dev/null 2>&1; then ok "  $bin 已存在"; continue; fi
  # 版本解析双通道：API 限流时走 releases/latest 302 重定向（不吃 API 配额）
  tag="$(curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 "https://api.github.com/repos/$repo/releases/latest" \
    | grep -oE '"tag_name": *"[^"]+"' | head -1 | cut -d'"' -f4)" || tag=""
  if [ -z "$tag" ]; then
    tag="$(curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 -o /dev/null -w '%{url_effective}' \
      "https://github.com/$repo/releases/latest" | sed 's|.*/tag/||')" || tag=""
  fi
  if [ -z "$tag" ]; then warn "  $bin 无法解析版本，跳过"; continue; fi
  ver="${tag#v}"
  asset="$tmpl"
  asset="${asset//\{ver\}/$ver}"; asset="${asset//\{verv\}/$tag}"
  asset="${asset//\{arch\}/$pa}";  asset="${asset//\{arch2\}/$p2}"
  asset="${asset//\{arch3\}/$p3}"; asset="${asset//\{arch4\}/$p4}"; asset="${asset//\{lin\}/$lin}"
  url="https://github.com/$repo/releases/download/${tag}/${asset}"
  file="$tmpd/$(basename "$asset")"
  if ! fetch "$url" "$file"; then warn "  $bin 下载失败，跳过"; continue; fi
  xdir="$tmpd/x"; rm -rf "$xdir"; mkdir -p "$xdir"
  case "$asset" in
    *.zip) unzip -oq "$file" -d "$xdir" 2>/dev/null || true ;;
    *.tar.gz|*.tgz) tar -xzf "$file" -C "$xdir" 2>/dev/null || true ;;
    *.gz)  gzip -dc "$file" > "$xdir/$bin" 2>/dev/null || true ;;
  esac
  found="$(find "$xdir" -type f -name "$bin" 2>/dev/null | head -1)"
  if [ -n "$found" ] && [ -s "$found" ]; then
    install -m 0755 "$found" "/usr/local/bin/$bin"
    ok "  $bin $tag"
  else
    warn "  $bin 解压后找不到二进制（$url）"
  fi
done

# ── pip 组（python 基础镜像自带 pip，无 PEP668 限制）──
# 包名|可执行名。逐个 || true：单个包装不上不阻断整个构建，
# 但构建日志里能看到 warn，宿主环境体检页也会如实显示缺失。
info "pip 安装 wafw00f / semgrep / pwntools..."
# impacket 必须走 pip：Debian 的 python3-impacket deb 只带库，不带
# impacket-smbexec 等命令脚本；pip 版会装全套 /usr/local/bin/impacket-*。
# netexec（nxc）不装：NetExec 2026 起商业化，PyPI 上的发行文件已全部
# 撤下（/simple/netexec 404），pip 装不到。需要时从 GitHub 源码安装
# （hosttools 目录 netexec 条目留有说明），运行期体检会如实显示缺失。
for pkg in wafw00f semgrep pwntools; do
  if python3 -m pip install --no-cache-dir --root-user-action=ignore "$pkg" >/dev/null 2>&1; then
    ok "  $pkg"
  else
    warn "  $pkg pip 安装失败"
  fi
done

# ── impacket 专用安装 ─────────────────────────────
# 必须从 GitHub 源码装：PyPI wheel 只带库+少数示例，且 0.12 起不注册命令；
# 源码 setup.py 会把 examples 全部注册成 impacket-smbexec/wmiexec/getST 等
# 命令——渗透作业按这些命令名调用。源码装失败再退 wheel+wrapper 兜底。
imp_ok=0
rm -rf /tmp/impacket-src; mkdir -p /tmp/impacket-src
for i in 1 2 3; do
  # 不用 pip git+：那要构建机有 git；codeload tarball 走 release 同款 CDN，fetch 自带重试
  if fetch "https://github.com/fortra/impacket/archive/refs/heads/master.tar.gz" /tmp/impacket-src/imp.tar.gz; then
    tar -xzf /tmp/impacket-src/imp.tar.gz -C /tmp/impacket-src 2>/dev/null || true
    d="$(find /tmp/impacket-src -maxdepth 1 -type d -name 'impacket-*' | head -1)"
    [ -n "$d" ] || break
    python3 -m pip install --no-cache-dir --root-user-action=ignore "$d" >/dev/null 2>&1 \
      && command -v impacket-smbexec >/dev/null 2>&1 && { imp_ok=1; break; }
  fi
  sleep 8
done
if [ "$imp_ok" = "1" ]; then
  ok "  impacket（源码，含全套示例命令）"
else
  warn "  impacket 源码安装失败，退 PyPI wheel + wrapper"
  python3 -m pip install --no-cache-dir --root-user-action=ignore impacket >/dev/null 2>&1 || true
  exdir="$(python3 -c 'import impacket, os; print(os.path.join(os.path.dirname(impacket.__file__), "examples"))')" 2>/dev/null || exdir=""
  if [ -n "$exdir" ] && [ -d "$exdir" ]; then
    for s in secretsdump smbclient mssqlshell ldap_shell; do
      [ -f "$exdir/$s.py" ] || continue
      printf '#!/bin/sh\nexec python3 "%s/%s.py" "$@"\n' "$exdir" "$s" > "/usr/local/bin/impacket-$s"
      chmod +x "/usr/local/bin/impacket-$s"
    done
  fi
fi

# ── SecLists 字典集 ──────────────────────────────────
# 路径必须是 /opt/SecLists——hosttools.go 的 seclists 条目与 worker 提示词
# 引用的都是这个目录。浅克隆 + 去掉 .git 减体积。
if [ ! -d /opt/SecLists/Discovery ]; then
  info "克隆 SecLists 字典集（浅克隆）..."
  sec_ok=0
  for i in 1 2 3; do
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists >/dev/null 2>&1 \
      && { sec_ok=1; break; }
    rm -rf /opt/SecLists; sleep 8
  done
  [ "$sec_ok" = "1" ] \
    && { rm -rf /opt/SecLists/.git; ok "  SecLists → /opt/SecLists"; } \
    || warn "  SecLists 克隆失败（构建机网络问题；运行时可按 hosttools 目录条目手动克隆）"
fi

# ── 汇总体检 ─────────────────────────────────────────
info "内置工具清单："
for b in nmap masscan sqlmap hydra whatweb nikto ffuf john impacket-smbexec socat proxychains4 \
         nuclei httpx subfinder naabu dnsx katana tlsx notify interactsh-client gitleaks \
         chisel amass dalfox feroxbuster gobuster wafw00f semgrep pwn; do
  if command -v "$b" >/dev/null 2>&1; then ok "  $b"; else warn "  $b 缺失"; fi
done
