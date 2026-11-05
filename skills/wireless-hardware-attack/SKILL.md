---
name: wireless-hardware-attack
description: 目标含 WiFi/蓝牙/无线设备、IoT 或物理硬件时调用——无线侦察、WPA 攻击路径、蓝牙/BLE、固件提取与硬件接口测试的基本路径。
tags:
  cwe: [CWE-321, CWE-798, CWE-1188]
  attack: [T1465, T1557]
  class: [wireless, hardware, iot, firmware]
---

# 无线与硬件速查

## WiFi

- 侦察：`iw dev`、`airodump-ng <iface>`（看 AP/客户端/加密类型）；
- WPA/WPA2：抓 4 次握手 → `aircrack-ng -w rockyou.txt cap`；WPS：`reaver`（先授权！）；
- 企业级 (802.1X)：EAP 降级/evil twin 属高风险测试，仅演练授权时做；
- 结论：能拿到明文口令/接入内网才算 L3。

## 蓝牙 / BLE

- `bluetoothctl scan on`、`hcitool lescan`；
- BLE 特征读写：`gatttool -b <mac> --char-read`，未授权可写特征 → 设备控制；
- 配对模式/默认 PIN（0000/1234）验证。

## IoT / 固件

- 固件提取：官网下载 / 升级接口抓包 / Flash 读取（`binwalk -e firmware.bin`）；
- 解包后找：`/etc/shadow`、硬编码密钥、调试接口（telnet/uart）、`squashfs-root/www`；
- 模拟：`firmadyne`/`qemu` 起固件（慎用，隔离网络）；
- 硬件：UART/JTAG 引脚识别（`picocom -b 115200 /dev/ttyUSB0`），先只读。

## 边界

- 无线攻击会干扰他人，仅在明确授权的演练/测试窗口做；
- 不干扰生产无线、不做 deauth 泛洪；
- 固件/硬件测试在隔离环境，不接生产网络。
