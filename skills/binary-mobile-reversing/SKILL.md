---
name: binary-mobile-reversing
description: 目标有 APP(APK/IPA)、桌面客户端或需要逆向二进制找接口/密钥/漏洞时调用——静态分析、Jadx/apktool、移动端常见漏洞（硬编码密钥、导出组件、证书校验绕过、WebView），以及从逆向结果回到服务端测试的路径。
tags:
  cwe: [CWE-798, CWE-312, CWE-926, CWE-295]
  attack: [T1409, T1552.001]
  class: [mobile, reverse, apk, ipa, binary]
---

# 移动端 / 二进制逆向速查

## APK 静态分析

1. `apktool d app.apk -o out/`：资源、`AndroidManifest.xml`（导出组件/权限/deep-link）；
2. `jadx -d src/ app.apk`：Java 源码还原；
3. 找秘密（全文写 fact）：
   ```bash
   grep -rnE "https?://|api[_-]?key|secret|token|password|AKID|accessKey" src/ | head -50
   gitleaks detect --source src/ 2>/dev/null
   ```
4. 抓接口：`okhttp`/`retrofit` 注解、`/api/` 常量、加密参数构造逻辑（签名算法）；
5. 导出组件：`adb shell dumpsys package <pkg> | grep -A2 exported`，`activity`/`service`/`receiver` 可导出 → 启动参数注入。

## IPA / 桌面端

- IPA 解包 `unzip app.ipa`，Mach-O 用 `strings`/`otool`；Flutter 用 `flutter_engine` 特征；
- Electron：`app.asar` 解包（`npx asar extract`）→ 找 preload 与 IPC 面；
- 二进制：`strings -n8` 找 URL/密钥；`radare2/Cutter`、`ghidra` 反编译（宿主工具按需装）。

## 移动端常见漏洞验证

| 漏洞 | 验证方式 |
|---|---|
| 硬编码密钥 | 从包内提取 AK/SK/token→直接调 API 验证（能列数据/调接口即 L3） |
| 未授权/越权 API | 从逆向得到接口→无 token 调→返回业务数据 |
| 导出组件 | `adb shell am start -n pkg/.Activity --es key value` 验证能否拉起并携带参数 |
| 证书校验绕过 | 仅对自有测试包做（Frida/objection），不用于第三方生产；证明可中间人即可 |
| WebView 注入 | deep-link 参数进入 `loadUrl`/`addJavascriptInterface` → 构造 URL 验证 |
| 备份/调试 | `android:allowBackup=true` → `adb backup` 导出数据；`debuggable=true` |

## 从客户端回到服务端

- 逆向得到的接口/参数/签名算法是**测试服务端的钥匙**：
  用脚本还原签名 → 直接打 API 做越权/注入（比在 APP 里点快得多）；
- 客户端校验（签名/加密）通常服务端不校验——重点验证服务端是否真的校验；
- 接口清单落 fact，交给 `api-security-testing` 继续。

## 工具与边界

- 工具：jadx/apktool/frida/objection/radare2/ghidra（宿主环境页按需装）；
- 只逆授权目标的包；不破解付费/版权保护用于非测试目的；
- 证书校验绕过只对自有测试环境做，生产目标只做「能读到流量」的最小证明。
