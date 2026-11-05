#!/usr/bin/env python3
"""补装 install_hosttools.py 首轮失败的几件工具（chisel/amass/dalfox/feroxbuster/nikto + shim）。"""
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


def fetch(url, dest, timeout=900):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def latest_tag(repo):
    req = urllib.request.Request(f"https://github.com/{repo}/releases/latest", headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.geturl().rsplit("/tag/", 1)[-1]


def assets(repo, tag):
    url = f"https://github.com/{repo}/releases/expanded_assets/{tag}"
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        html = r.read().decode("utf-8", "ignore")
    return re.findall(r'href="(/%s/releases/download/[^"]+)"' % re.escape(repo), html)


def take(repo, asset_re, bin_re, name):
    try:
        tag = latest_tag(repo)
        hit = None
        for p in assets(repo, tag):
            if re.search(asset_re, p.rsplit("/", 1)[-1]):
                hit = p
                break
        if not hit:
            print(f"[ !! ] {repo}: 无匹配资产 {asset_re}", flush=True)
            return False
        with tempfile.TemporaryDirectory() as td:
            arc = os.path.join(td, hit.rsplit("/", 1)[-1])
            fetch("https://github.com" + hit, arc)
            ex = os.path.join(td, "x")
            os.makedirs(ex)
            low = arc.lower()
            if low.endswith(".zip"):
                zipfile.ZipFile(arc).extractall(ex)
            elif low.endswith((".tar.gz", ".tgz")):
                tarfile.open(arc).extractall(ex)
            else:  # 单文件（.gz 已由 tarfile 排除，这里处理裸二进制/脚本）
                out = os.path.join(ex, os.path.basename(arc))
                if low.endswith(".gz"):
                    import gzip
                    with gzip.open(arc, "rb") as s, open(out[:-3], "wb") as d:
                        shutil.copyfileobj(s, d)
                else:
                    shutil.copy(arc, out)
            cand = None
            for root, _, files in os.walk(ex):
                for f in files:
                    if re.match(bin_re, f):
                        cand = os.path.join(root, f)
                        break
                if cand:
                    break
            if not cand:
                print(f"[ !! ] {repo}: 解包无 {bin_re}", flush=True)
                return False
            shutil.copy(cand, os.path.join(BIN, name))
            os.chmod(os.path.join(BIN, name), 0o755)
        print(f"[ ok ] {name} ({tag})", flush=True)
        return True
    except Exception as e:  # noqa: BLE001
        print(f"[ !! ] {repo}: {e}", flush=True)
        return False


def main():
    take("jpillora/chisel", r"chisel_.*linux_amd64\.gz$", r"^chisel.*amd64$", "chisel")
    take("owasp-amass/amass", r"amass_linux_amd64\.tar\.gz$", r"^amass$", "amass")
    take("hahwul/dalfox", r"linux-x86_64\.tar\.gz$", r"^dalfox$", "dalfox")
    take("epi052/feroxbuster", r"x86_64-linux-feroxbuster\.tar\.gz$", r"^feroxbuster$", "feroxbuster")

    # nikto：Debian 源里没有，官方仓库直接跑（perl 脚本）
    if not shutil.which("nikto"):
        if not os.path.isdir("/opt/nikto"):
            subprocess.run("git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto",
                           shell=True, capture_output=True)
        prog = "/opt/nikto/program/nikto.pl"
        if os.path.exists(prog):
            with open(os.path.join(BIN, "nikto"), "w") as f:
                f.write(f'#!/bin/sh\nexec perl {prog} "$@"\n')
            os.chmod(os.path.join(BIN, "nikto"), 0o755)
            print("[ ok ] nikto (perl, /opt/nikto)", flush=True)
        else:
            print("[ !! ] nikto 克隆失败", flush=True)

    # impacket 脚本名带 .py，给几个常用口令做无后缀软链
    for name in ["GetNPUsers", "GetUserSPNs", "secretsdump", "psexec", "wmiexec", "smbexec",
                 "ntlmrelayx", "smbclient", "lookupsid", "GetADUsers", "goldenPac"]:
        src = shutil.which(name + ".py") or (
            f"/usr/local/bin/{name}.py" if os.path.exists(f"/usr/local/bin/{name}.py") else None)
        if src and not os.path.exists(os.path.join(BIN, name)):
            os.symlink(src, os.path.join(BIN, name))
            print(f"[ ok ] 软链 {name} -> {src}", flush=True)

    # imagemagick / proxychains 兼容 shim（工具目录里的 bin 名与 Debian 包名不一致）
    for alias, target in [("imagemagick", "magick"), ("proxychains", "proxychains4")]:
        p = os.path.join(BIN, alias)
        t = shutil.which(target)
        if not os.path.exists(p) and t:
            with open(p, "w") as f:
                f.write(f'#!/bin/sh\nexec {t} "$@"\n')
            os.chmod(p, 0o755)
            print(f"[ ok ] shim {alias} -> {target}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
