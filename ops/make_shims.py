#!/usr/bin/env python3
"""为「库形态」工具生成可执行 shim。

Pojun 的工具体检（hosttools.AvailableInPath）纯靠 exec.LookPath(Bin)，
而 pip 库类工具（paho-mqtt / pymongo / pwntools…）本身没有同名可执行文件，
于是即使装好了也会被判定为缺失。这里按工具 ID 造一个同名 shim：
调用时做一次真实 import 自检并打印版本，既让 LookPath 命中，也能被 agent 直接调用来确认可用性。
"""

import os
import shutil
import subprocess

BIN = "/usr/local/bin"

# 工具 ID -> 要 import 的模块
LIBS = {
    "gmqtt": "gmqtt",
    "paho-mqtt": "paho.mqtt.client",
    "pika": "pika",
    "amqpstorm": "amqpstorm",
    "confluent-kafka": "confluent_kafka",
    "kombu": "kombu",
    "pymongo": "pymongo",
    "pymysql": "pymysql",
    "psycopg2-binary": "psycopg2",
    "redis": "redis",
    "zeep": "zeep",
    "python-gitlab": "gitlab",
    "netmiko": "netmiko",
    "napalm": "napalm",
    "splunk-sdk": "splunklib",
    "pwntools": "pwn",
    "impacket": "impacket",
}

TEMPLATE = """#!/bin/sh
# {name} — pip 库的可用性自检 shim（由 ops/make_shims.py 生成）
exec python3 -c 'import importlib, sys
m = importlib.import_module("{mod}")
print("{name} ok", getattr(m, "__version__", "installed"))'
"""


def write(name, content, mode=0o755):
    path = os.path.join(BIN, name)
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, mode)
    print(f"[ ok ] shim {name}")


def main():
    for name, mod in LIBS.items():
        try:
            ok = subprocess.run(["python3", "-c", f"import {mod}"],
                                capture_output=True).returncode == 0
        except Exception:  # noqa: BLE001
            ok = False
        if ok:
            write(name, TEMPLATE.format(name=name, mod=mod))
        else:
            print(f"[ !! ] {name}: 模块 {mod} 未安装，跳过")

    # 目录型工具：SecLists
    if os.path.isdir("/opt/SecLists"):
        write("seclists", '#!/bin/sh\necho /opt/SecLists\nls /opt/SecLists | head -20\n')

    # 目录型工具：Responder（源码形态，直接跑入口脚本）
    if os.path.exists("/opt/Responder/Responder.py"):
        write("responder", '#!/bin/sh\ncd /opt/Responder && exec python3 Responder.py "$@"\n')

    # ligolo-ng：目录里的 Bin 名是 ligolo-ng，实际装的是 ligolo-proxy/ligolo-agent
    if not os.path.exists(os.path.join(BIN, "ligolo-ng")) and shutil.which("ligolo-proxy"):
        os.symlink(shutil.which("ligolo-proxy"), os.path.join(BIN, "ligolo-ng"))
        print("[ ok ] symlink ligolo-ng -> ligolo-proxy")

    # netexec：PyPI 无可用分发（要求 Python <3.12），从 git 装的入口叫 netexec/nxc
    if not shutil.which("netexec") and shutil.which("nxc"):
        os.symlink(shutil.which("nxc"), os.path.join(BIN, "netexec"))
        print("[ ok ] symlink netexec -> nxc")

    # evil-winrm：Ruby gem 形态
    if not shutil.which("evil-winrm") and shutil.which("gem"):
        r = subprocess.run("gem install evil-winrm --no-document", shell=True,
                           capture_output=True, text=True, timeout=600)
        print("[ ok ] gem evil-winrm" if r.returncode == 0 else
              "[ !! ] gem evil-winrm 失败: " + (r.stderr or r.stdout).strip()[-200:])
    for cand in ["/usr/local/bin/evil-winrm", "/var/lib/gems/3.1.0/bin/evil-winrm"]:
        if os.path.exists(cand) and not os.path.exists(os.path.join(BIN, "evil-winrm")):
            os.symlink(cand, os.path.join(BIN, "evil-winrm"))
            print(f"[ ok ] symlink evil-winrm -> {cand}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
