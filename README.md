# TraeCN

> 本地离线提取 Trae SOLO CN 凭证与 Token 续期工具
> Offline local credential extractor & Token refresher for Trae SOLO CN

## 致谢 / Credits

本仓库的工具参考并致敬原作者 **ethgan** 的项目
[TraeCN-cloudflare-](https://github.com/ethgan/TraeCN-cloudflare-)（Trae Work 每日签到 ·
Cloudflare Worker，基于 GPL-3.0 开源）。

We sincerely thank **ethgan** for the original project
[TraeCN-cloudflare-](https://github.com/ethgan/TraeCN-cloudflare-) (Trae Work daily
check-in · Cloudflare Worker, released under GPL-3.0). This repository is an independent,
offline local toolkit built around the same Trae credential ecosystem, and reuses the
GPL-3.0 license to respect the upstream license.

> 说明：上游项目通过抓包（Reqable）获取 TOKEN 与 x-device-id 并部署到 Cloudflare 实现每日自动签到。
> 本仓库不依赖抓包，改为**离线解密本机 Trae SOLO CN 的 Electron 加密存储**来提取同样的凭证，
> 并提供 Token 续期与多账号运维能力。
>
> Note: the upstream project obtains TOKEN/x-device-id via packet capture and runs a
> Cloudflare Worker for daily check-in. This repo instead **decrypts the local Trae SOLO CN
> Electron encrypted storage offline** to extract the same credentials, and adds Token refresh
> and multi-account tooling.

## 功能特性 / Features

- 离线提取 TOKEN 与 x-device-id，无需抓包、无需代理（纯本地解密）。
  Offline extraction of TOKEN and x-device-id — no packet capture, no proxy required.
- 解密 Trae SOLO CN 的 storage.json（byteCrypto：SHA512 + AES-128-CBC，密钥自包含于头部）。
  Decrypts Trae SOLO CN storage.json (byteCrypto: SHA512 + AES-128-CBC, key embedded in header).
- 凭证有效期检查（--check 可联网验证 checked_in 状态）。
  Credential expiry check (--check verifies the checked_in status online).
- Token 续期（--refresh：调用 ExchangeToken 接口，本地 ECDSA 签名）。
  Token refresh (--refresh: calls ExchangeToken with local ECDSA signing).
- 多账号启动器（trae-launch-account.js，一号一用户数据目录）。
  Multi-account launcher (trae-launch-account.js, one user-data-dir per account).
- 续期错误诊断（trae-exchange-probe.js，定位 20403 / 20101 / 20405 等）。
  Refresh diagnostics (trae-exchange-probe.js for 20403 / 20101 / 20405, etc.).
- 全中文 --h 帮助。
  Full Chinese --h help built-in.

## 文件说明 / Files

| 文件 / File | 说明 / Description |
|---|---|
| get-trae-credentials.js | 主工具：提取 + 续期一体化，含中文 --h 帮助（推荐入口）。Main tool: extract + refresh, with --h help. |
| trae-refresh.js | 独立续期入口（保留，方便单独调用）。Standalone refresh entry. |
| trae-launch-account.js | 多账号启动器，按 --dir 指定独立的 user-data-dir。Multi-account launcher. |
| trae-exchange-probe.js | ExchangeToken 单变量探测 / 矩阵测试，用于诊断续期失败。Diagnostics probe. |

## 安装 / Install

仅需 Node.js 18+，无任何第三方依赖（全部使用 Node 标准库）。

Requires Node.js 18+ only; zero third-party dependencies (pure Node stdlib).

```bash
node --version   # 确认 >= 18
git clone https://github.com/nanningjyd/TraeCN.git
cd TraeCN
```

## 使用 / Usage

### 1. 列出本机所有 Trae 账号凭证（离线解密）

List all local Trae credentials (offline decrypt):

```bash
node get-trae-credentials.js --list
node get-trae-credentials.js --scan
```

输出格式：TOKEN#x-device-id#备注，可直接用于上游签到项目的管理面板。
Output format: TOKEN#x-device-id#remark, ready to paste into the upstream check-in admin panel.

### 2. 查看某个凭证的详细信息与有效期

Show details and expiry:

```bash
node get-trae-credentials.js --all
node get-trae-credentials.js --check          # 联网验证 checked_in 状态
```

### 3. 续期（刷新 Token）

Refresh the token:

```bash
node get-trae-credentials.js --refresh        # 等价于 --live --write-back
```

> 重要提醒 / Important: 续期接口在部分账号 / 服务端状态下会返回 20403 Token device not match，
> 该错误与请求内容无关，属服务端设备绑定限制，脚本路径当前不稳定。此时请按
> node get-trae-credentials.js --h 中【重要提醒】处理（通常为重新登录或等待客户端自刷）。
> The ExchangeToken endpoint may return 20403 Token device not match under some server-side
> device-binding states; this is unrelated to the request payload. See --h for handling.

### 4. 中文帮助

Full Chinese help:

```bash
node get-trae-credentials.js --h
```

## 工作原理 / How it works

### 数据位置 / Data location

    %APPDATA%\TRAE SOLO CN\User\globalStorage\storage.json

关键键 / Key entries:

- iCubeAuthInfo://icube.cloudide — 加密的认证凭证（含 TOKEN / RefreshToken）。
- iCubeAuthInfo://icube-dc:<deviceId> — 本地 EC P-256 密钥对（用于续期签名）。
- aha/TinyStorage 中的 aha.device.device_id — 设备 ID。

### 解密算法 / Decryption

    magic   = 74 63 05 10 00 00
    header  = magic(6) + key(32 random) + ciphertext(AES-128-CBC)
    derived = SHA512( SHA512(key) || pad64 )      # pad64[i] = SM4_SBOX[i] ^ SM4_SBOX2[i]
    plain   = AES-128-CBC(dec, derived[0:16], derived[16:32])
            = [ 64B SHA512(body) ][ body ]

### 续期签名 / Refresh signing

    POST {host}/trae/api/v3/oauth/ExchangeToken
    DeviceProof = base64( ECDSA-SHA256( "POST <path> <ClientID> <RefreshToken> <ts> <nonce>", 本地私钥 ) )
    Header: x-cloudide-token: <access token>

## 重要提醒 / Important notes

1. 凭证等同于账号密码：请勿将真实的 TOKEN 截图、粘贴到聊天或提交到公开仓库。
   Credentials equal your account password — never screenshot, paste in chat, or commit real tokens.
2. 本工具仅用于个人本机运维，请遵守所在地法律法规与 Trae 服务条款。
   For personal local maintenance only; comply with local laws and Trae Terms of Service.
3. 续期失败时优先查看 --h 的【重要提醒】与 trae-exchange-probe.js 的诊断输出。
   On refresh failure, consult --h and trae-exchange-probe.js.
4. 多账号需一号一用户数据目录（--user-data-dir），而非 --profile。
   Multi-account needs one user-data-dir per account.

## 许可证 / License

本项目基于上游 ethgan/TraeCN-cloudflare- 的生态并沿用其 GPL-3.0 许可证。详见 LICENSE。

This project follows the upstream ethgan/TraeCN-cloudflare- ecosystem and reuses its GPL-3.0
license. See LICENSE.

## 免责声明 / Disclaimer

本仓库仅供学习与研究，作者不对使用本工具产生的任何后果负责。
For educational and research purposes only. The author is not responsible for any consequences
of using this tool.
