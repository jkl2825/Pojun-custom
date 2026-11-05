#!/usr/bin/env python3
"""Pojun 宿主工具补齐脚本（Docker 形态专用，在容器内以 root 运行）。

背景：Docker 部署下 /api/hostenv/install 不可用（依赖特权助手 pojun-hostd）。
本脚本直接从容器内完成 apt / pip / GitHub Release 三类安装，绕过 hostd。

用法：
    docker cp install_hosttools.py pojun-pojun-1:/tmp/
    docker exec -u 0 pojun-pojun-1 python3 /tmp/install_hosttools.py
"""

import gzip
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

UA = {"User-Agent": "Mozilla/5.0 (pojun-installer)"}
BIN = "/usr/local/bin"
FAIL = []


def sh(cmd, timeout=2400):
    p = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=timeout)
    ok = p.returncode == 0
    print(("[ ok ] " if ok else "[ !! ] ") + cmd, flush=True)
    if not ok:
        FAIL.append(cmd)
        tail = (p.stdout + p.stderr).strip().splitlines()[-2:]
        print("        " + " | ".join(tail), flush=True)
    return ok


def fetch(url, dest, timeout=900):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def latest_tag(repo):
    """用 releases/latest 的 302 跳转拿 tag，避开 api.github.com 的 60/h 限流。"""
    req = urllib.request.Request(f"https://github.com/{repo}/releases/latest", headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.geturl().rsplit("/tag/", 1)[-1]


def asset_paths(repo, tag):
    url = f"https://github.com/{repo}/releases/expanded_assets/{tag}"
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        html = r.read().decode("utf-8", "ignore")
    return re.findall(r'href="(/%s/releases/download/[^"]+)"' % re.escape(repo), html)


def pick(paths, pattern):
    for p in paths:
        if re.search(pattern, p.rsplit("/", 1)[-1]):
            return p
    return None


def unpack(archive, workdir):
    low = archive.lower()
    if low.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            z.extractall(workdir)
    elif low.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive) as t:
            t.extractall(workdir)
    elif low.endswith(".gz"):
        out = os.path.join(workdir, os.path.basename(archive)[:-3])
        with gzip.open(archive, "rb") as s, open(out, "wb") as d:
            shutil.copyfileobj(s, d)
    else:
        shutil.copy(archive, os.path.join(workdir, os.path.basename(archive)))


def install_bin(repo, asset_re, bin_re, name=None, extra=None):
    """下载 release 资产 → 解包 → 把匹配 bin_re 的可执行文件装到 /usr/local/bin。"""
    name = name or repo.rsplit("/", 1)[-1]
    try:
        tag = latest_tag(repo)
        rel = pick(asset_paths(repo, tag), asset_re)
        if not rel:
            print(f"[ !! ] {repo}: 找不到匹配 {asset_re} 的资产", flush=True)
            FAIL.append(repo)
            return False
        with tempfile.TemporaryDirectory() as td:
            arc = os.path.join(td, rel.rsplit("/", 1)[-1])
            fetch("https://github.com" + rel, arc)
            ex = os.path.join(td, "x")
            os.makedirs(ex, exist_ok=True)
            unpack(arc, ex)
            cand = None
            for root, _, files in os.walk(ex):
                for f in files:
                    if re.match(bin_re, f):
                        cand = os.path.join(root, f)
                        break
                if cand:
                    break
            if not cand:
                print(f"[ !! ] {repo}: 解包后未见 {bin_re}", flush=True)
                FAIL.append(repo)
                return False
            dst = os.path.join(BIN, name)
            shutil.copy(cand, dst)
            os.chmod(dst, 0o755)
            # 附带的第二个二进制（ligolo-ng 的 proxy / PEASS 的其他脚本）
            if extra:
                for pat, alias in extra:
                    for root, _, files in os.walk(ex):
                        hit = [f for f in files if re.match(pat, f)]
                        if hit:
                            shutil.copy(os.path.join(root, hit[0]), os.path.join(BIN, alias))
                            os.chmod(os.path.join(BIN, alias), 0o755)
                            break
        print(f"[ ok ] {name} ({tag})", flush=True)
        return True
    except Exception as e:  # noqa: BLE001
        print(f"[ !! ] {repo}: {e}", flush=True)
        FAIL.append(repo)
        return False


def main():
    os.makedirs(BIN, exist_ok=True)
    os.environ["DEBIAN_FRONTEND"] = "noninteractive"

    print("=== 1/5 apt ===", flush=True)
    sh("apt-get update -qq")
    apt = [
        "sqlmap masscan hydra hashcat john socat openssh-client tcpdump",
        "proxychains4 ffuf gobuster nikto whatweb testssl.sh imagemagick",
        "libimage-magick-perl libnet-ssleay-perl default-jre-headless",
    ]
    for group in apt:
        for pkg in group.split():
            if sh(f"apt-get install -y -qq --no-install-recommends {pkg}", timeout=1200):
                continue

    print("=== 2/5 pip ===", flush=True)
    sh("pip3 install --no-cache-dir -q --break-system-packages "
       "impacket wafw00f semgrep pwntools netifaces "
       "paho-mqtt gmqtt pika amqpstorm confluent-kafka kombu "
       "pymongo pymysql psycopg2-binary redis zeep python-gitlab "
       "netmiko napalm splunk-sdk", timeout=2400)
    # netexec：PyPI 上没有适配 Python 3.12 的分发（报 "from versions: none"），只能从 git 装。
    # evil-winrm：PyPI 上不存在，是 Ruby gem（见 make_shims.py）。
    sh("pip3 install --no-cache-dir -q --break-system-packages "
       "git+https://github.com/Pennyw0rth/NetExec", timeout=1800)

    print("=== 3/5 GitHub Release ===", flush=True)
    # projectdiscovery 全家桶：资产名形如 httpx_1.7.1_linux_amd64.zip
    for tool in ["httpx", "subfinder", "naabu", "dnsx", "katana", "tlsx", "notify"]:
        install_bin(f"projectdiscovery/{tool}", r"linux_amd64\.zip$", rf"^{tool}$", tool)
    install_bin("projectdiscovery/interactsh", r"interactsh-client_.*linux_amd64\.zip$",
                r"^interactsh-client$", "interactsh-client")
    install_bin("gitleaks/gitleaks", r"linux_x64\.tar\.gz$", r"^gitleaks$", "gitleaks")
    install_bin("jpillora/chisel", r"linux_amd64\.gz$", r"^chisel$", "chisel")
    install_bin("owasp-amass/amass", r"amass_linux_amd64\.zip$", r"^amass$", "amass")
    install_bin("hahwul/dalfox", r"linux_amd64\.tar\.gz$", r"^dalfox$", "dalfox")
    install_bin("epi052/feroxbuster", r"x86_64-linux\.tar\.gz$", r"^feroxbuster$", "feroxbuster")
    install_bin("nicocha30/ligolo-ng", r"agent_.*linux_amd64\.tar\.gz$", r"^agent$", "ligolo-agent",
                extra=[(r"^proxy$", "ligolo-proxy")])
    install_bin("DominicBreuker/pspy", r"^pspy64$", r"^pspy64$", "pspy64")
    install_bin("peass-ng/PEASS-ng", r"linpeas\.sh$", r"^linpeas\.sh$", "linpeas")

    print("=== 4/5 SecLists ===", flush=True)
    if not os.path.isdir("/opt/SecLists"):
        sh("git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists")
    else:
        print("[ ok ] /opt/SecLists 已存在", flush=True)

    print("=== 5/5 兼容 shim ===", flush=True)
    # 工具目录里 imagemagick 的 bin 名写的是 imagemagick，Debian 里实际叫 magick
    for alias, target in [("imagemagick", "magick"), ("proxychains", "proxychains4")]:
        path = os.path.join(BIN, alias)
        if not os.path.exists(path) and shutil.which(target):
            with open(path, "w") as f:
                f.write(f'#!/bin/sh\nexec {shutil.which(target)} "$@"\n')
            os.chmod(path, 0o755)
            print(f"[ ok ] shim {alias} -> {target}", flush=True)

    print("\n=== 结果 ===", flush=True)
    for t in ["nmap", "masscan", "sqlmap", "httpx", "subfinder", "naabu", "dnsx", "katana",
              "tlsx", "notify", "interactsh-client", "gitleaks", "chisel", "amass", "dalfox",
              "feroxbuster", "ligolo-agent", "pspy64", "linpeas", "ffuf", "gobuster", "nikto",
              "whatweb", "testssl.sh", "hydra", "hashcat", "john", "socat", "ssh", "tcpdump",
              "proxychains4", "imagemagick", "impacket-GetNPUsers", "evil-winrm", "wafw00f",
              "netexec", "semgrep", "nuclei"]:
        print(f"  {'OK ' if shutil.which(t) else '-- '} {t}", flush=True)
    print(f"\n失败项 {len(FAIL)}：", flush=True)
    for f in FAIL:
        print("  " + f, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
