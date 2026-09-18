#!/usr/bin/env node
/**
 * get-trae-credentials.js
 * ------------------------------------------------------------------
 * 从本机 TRAE SOLO CN (Trae Work CN) 的本地数据目录离线导出签到所需的
 * TOKEN (Cloud-IDE-JWT) 与 x-device-id —— 不抓包、不代理、不 Root。
 * 支持同时扫描多个数据目录（多账号）。
 *
 * 原理（逆向自 resources/app/out/main.js 的 byteCrypto.js）：
 *   登录态 AES 加密后存在  <userData>/User/globalStorage/storage.json
 *     键 iCubeAuthInfo://icube.cloudide   ← authProviderId 来自 product.json
 *   设备号存在              <userData>/aha/TinyStorage
 *     键 aha.device.device_id
 *
 *   密文结构： [6B magic 74 63 05 10 00 00][32B 随机key][AES-128-CBC 密文]
 *   密钥派生： derived  = SHA512( SHA512(key32) || pad64 )
 *              aesKey   = derived[0:16]   iv = derived[16:32]
 *              pad64[i] = SM4_SBOX[i] ^ SM4_SBOX2[i]     (AES)
 *              pad64[i] = PRIV_A[i]   ^ PRIV_B[i]        (AES_PRIVATE)
 *   明文：     [64B SHA512(body)][body]   body = UTF-8 JSON
 *
 * 重要：storage.json 的路径是 <userData>/User/globalStorage/storage.json，
 *   **不随 VS Code profile 变化**，所以 `--profile` 无法隔离账号；
 *   只有 `--user-data-dir <目录>` 或 `VSCODE_PORTABLE` 能真正隔离。
 *
 * 用法：
 *   node get-trae-credentials.js                    # 扫描默认数据目录并输出配置行
 *   node get-trae-credentials.js --h                # 中文帮助（列出全部参数）
 *   node get-trae-credentials.js --list             # 列出所有发现的账号
 *   node get-trae-credentials.js --all              # 输出所有账号的配置行
 *   node get-trae-credentials.js --dir D:\trae-acc2 # 指定数据目录（可重复）
 *   node get-trae-credentials.js --scan D:\trae     # 递归发现子目录中的数据目录
 *   node get-trae-credentials.js --json             # 全部明细 JSON
 *   node get-trae-credentials.js --check            # 联网验证 token 是否可用
 *   node get-trae-credentials.js --all --out a.txt  # 批量追加写入
 *   node get-trae-credentials.js --note 主号        # 指定备注（单目录时生效）
 *
 * 续期（refresh，默认离线预览，--live 才联网）：
 *   node get-trae-credentials.js --live                  # 真刷新，只打印结果，不改本地文件
 *   node get-trae-credentials.js --live --write-back     # 刷新并写回 storage.json（先退出 Trae）
 *   node get-trae-credentials.js --refresh               # 等于 --live --write-back
 *
 * 注意：2026-09-18 实测，Trae 0.1.67 下服务端对续期请求固定返回 20403
 *       "Token device not match."，且与请求内容无关（详见 --h 第二节）。
 *       此时不要反复重试，按 --h 的【重要提醒】第 6 条处理。
 *   node get-trae-credentials.js --self-test             # 加解密往返自检
 *   node get-trae-credentials.js --probe                 # 零风险探针（篡改 token 打接口）
 *
 * 环境变量 TRAE_DATA_DIRS 用 ; 分隔多个数据目录。
 * 仅用 Node 内置模块，无第三方依赖。Node >= 18。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

// ---------------- byteCrypto ----------------
const SM4_SBOX = Uint8Array.from([82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37]);
const SM4_SBOX2 = Uint8Array.from([31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125]);
const PRIV_A = Uint8Array.from([191,192,216,250,122,246,220,97,31,254,98,27,8,72,71,176,135,99,96,18,127,101,203,104,211,102,191,125,37,72,150,156,51,229,121,35,17,153,141,177,110,131,150,128,172,255,254,6,18,140,55,62,236,249,135,64,135,12,117,4,89,149,168,209]);
const PRIV_B = Uint8Array.from([246,204,26,232,232,70,129,109,223,146,169,242,23,241,105,145,50,196,165,42,254,120,3,54,244,207,209,85,53,6,138,106,175,148,31,204,186,186,165,182,87,142,49,10,39,110,26,154,86,56,173,125,18,64,198,225,99,99,83,82,191,134,76,170]);

const HDR = 6, KEYLEN = 32, BH = 64;
const MAGIC_AES = [116, 99, 5, 16, 0, 0];
const MAGIC_PRIV = [18, 57, 32, 32, 2, 3];
const sha512 = (b) => crypto.createHash('sha512').update(b).digest();

function detectType(b) {
  if (MAGIC_AES.every((v, i) => b[i] === v)) return 'AES';
  if (MAGIC_PRIV.every((v, i) => b[i] === v)) return 'AES_PRIVATE';
  return 'UNKNOWN';
}
function pad64(type) {
  const A = type === 'AES_PRIVATE' ? PRIV_A : SM4_SBOX;
  const B = type === 'AES_PRIVATE' ? PRIV_B : SM4_SBOX2;
  const o = Buffer.alloc(64);
  for (let i = 0; i < 64; i++) o[i] = A[i] ^ B[i];
  return o;
}
/** 解密 dGMFEAAA... 形式的 base64 密文 */
function decrypt(container) {
  const blob = Buffer.from(String(container), 'base64');
  const type = detectType(blob);
  if (type === 'UNKNOWN') throw new Error('未知密文类型（Trae 版本可能已变）');
  const key = blob.subarray(HDR, HDR + KEYLEN);
  const ct = blob.subarray(HDR + KEYLEN);
  const derived = sha512(Buffer.concat([sha512(key), pad64(type)]));
  const dec = crypto.createDecipheriv('aes-128-cbc', derived.subarray(0, 16), derived.subarray(16, 32));
  const plain = Buffer.concat([dec.update(ct), dec.final()]);
  const body = plain.subarray(BH);
  if (!sha512(body).equals(plain.subarray(0, BH))) throw new Error('MAC 校验失败');
  return body.toString('utf8');
}
function unwrapValue(v) {
  if (typeof v === 'string' && v.length > 1 && v[0] === '"' && v[v.length - 1] === '"') {
    try { return JSON.parse(v); } catch { /* keep raw */ }
  }
  return v;
}

/** 与 Trae 的 MUe 等价：6B magic + 32B 随机 key + AES-128-CBC(PKCS7)。仅 --write-back 用到 */
function encrypt(text, type = 'AES') {
  const body = Buffer.from(text, 'utf8');
  const plain = Buffer.concat([sha512(body), body]);
  const key = crypto.randomBytes(KEYLEN);
  const derived = sha512(Buffer.concat([sha512(key), pad64(type)]));
  const enc = crypto.createCipheriv('aes-128-cbc', derived.subarray(0, 16), derived.subarray(16, 32));
  const ct = Buffer.concat([enc.update(plain), enc.final()]);
  const magic = Buffer.from(type === 'AES_PRIVATE' ? MAGIC_PRIV : MAGIC_AES);
  return Buffer.concat([magic, key, ct]).toString('base64');
}

// ---------------- 续期（refresh）辅助 ----------------
const EXCHANGE_PATH = '/trae/api/v3/oauth/ExchangeToken';
const DEFAULT_CLIENT_ID = 'en1oxy7wnw8j9n';   // product.json → iCubeApp.authConfig.SOLO.stable
const DEFAULT_APP_VERSION = '0.1.67';         // product.json → appVersion

/** 定位安装目录读 product.json，拿 appVersion / authConfig（客户端升级后比日志里的旧版本更准） */
function findAppMeta() {
  const cands = [];
  if (process.env.TRAE_APP_DIR) cands.push(process.env.TRAE_APP_DIR);
  const roots = [];
  if (process.platform === 'win32') {
    for (const r of ['D:\\Program Files', 'E:\\Program Files', process.env.ProgramFiles, process.env['ProgramFiles(x86)'],
      process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'Programs')]) if (r) roots.push(r);
  } else if (process.platform === 'darwin') roots.push('/Applications');
  else roots.push('/opt', '/usr/lib');
  for (const r of roots) for (const n of ['TRAE SOLO CN', 'Trae Solo CN', 'Trae CN']) cands.push(path.join(r, n));
  for (const c of cands) {
    try {
      const p = JSON.parse(fs.readFileSync(path.join(c, 'resources', 'app', 'product.json'), 'utf8'));
      if (p.appVersion) {
        return {
          dir: c,
          appVersion: p.appVersion,
          clientId: (p.iCubeApp && p.iCubeApp.authConfig && p.iCubeApp.authConfig.SOLO && p.iCubeApp.authConfig.SOLO.stable) || '',
        };
      }
    } catch { /* 继续找 */ }
  }
  return null;
}

/** 从历史日志里捞上次成功请求的 DeviceInfo —— 保证与服务器见过的字节一致 */
function harvestLogs(dir) {
  const logsRoot = path.join(dir, 'logs');
  const files = [];
  try {
    for (const d of fs.readdirSync(logsRoot, { withFileTypes: true })) {
      if (!d.isDirectory()) continue;
      const f = path.join(logsRoot, d.name, 'main.log');
      if (fs.existsSync(f)) files.push({ f, mtime: fs.statSync(f).mtimeMs });
    }
  } catch { return null; }
  files.sort((a, b) => b.mtime - a.mtime);
  for (const { f } of files) {
    let txt;
    try { txt = fs.readFileSync(f, 'utf8'); } catch { continue; }
    const re = /\[exchangeToken(?:ByRefreshToken|ByAuthCode)\] request (\S+) (\{.*\})\s*$/gm;
    let last = null, m;
    while ((m = re.exec(txt)) !== null) last = m;
    if (!last) continue;
    try {
      const b = JSON.parse(last[2]);
      return { ClientID: b.ClientID, IDEVersion: b.IDEVersion, DeviceInfo: b.DeviceInfo };
    } catch { /* 换下一个日志 */ }
  }
  return null;
}

function probeDev() {
  const plat = process.platform;
  const info = {
    DeviceName: os.hostname(),
    DeviceModel: '',
    DeviceBrand: '',
    DeviceCPU: (os.cpus()[0] && os.cpus()[0].model) || '',
    OSInfo: plat === 'darwin' ? 'mac' : plat === 'win32' ? 'windows' : plat,
    OSVersion: typeof os.version === 'function' ? os.version() : os.release(),
  };
  if (plat === 'win32') {
    const q = (ps) => {
      try { return require('child_process').execSync(`powershell -NoProfile -Command "${ps}"`, { encoding: 'utf8', timeout: 6000 }).trim(); }
      catch { return ''; }
    };
    info.DeviceModel = q('(Get-CimInstance Win32_BaseBoard).Product') || '';
    info.DeviceBrand = q('(Get-CimInstance Win32_BaseBoard).Manufacturer') || '';
  }
  return info;
}

function traeRunning() {
  if (process.platform !== 'win32') return false;
  try {
    const out = require('child_process').execSync('tasklist /FI "IMAGENAME eq TRAE SOLO CN.exe" /NH', { encoding: 'utf8', timeout: 8000 });
    return /TRAE SOLO CN\.exe/i.test(out);
  } catch { return false; }
}

function buildProof(acc, refreshToken, clientId) {
  const ts = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('hex');
  const msg = ['POST', EXCHANGE_PATH, clientId, refreshToken, String(ts), nonce].join(' ');
  const signature = crypto.createSign('sha256').update(msg).sign(acc.keyPair.privateKeyPEM).toString('base64');
  return { msg, DeviceProof: { Signature: signature, Timestamp: ts, Nonce: nonce } };
}

/** 篡改 refreshToken（末位取反），用于零风险验证请求管线 */
function tamperToken(t) {
  return t.slice(0, -1) + (t.slice(-1) === 'A' ? 'B' : 'A');
}

/** ExchangeToken 返回码 → 可执行结论（依据 2026-09 对本机 0.1.67 的实测） */
function explainExchangeError(code, msg) {
  const m = {
    10101: 'ClientID 不被服务端接受。用 --client-id 指定 product.json 里 iCubeApp.authConfig.SOLO.stable 的值。',
    20101: 'refreshToken 无效。若这是 --probe（篡改过 token），属预期：说明 ClientID/DeviceInfo/DeviceProof 均已被接受，管线正常。',
    20405: '请求缺少 DeviceProof 字段，服务端要求必须携带。',
    20401: '账号设备数超限，需在 Trae 中登出其他设备。',
    20403: 'refreshToken 有效（能查到记录），但其服务端绑定的设备与本请求不匹配。'
         + '\n                 实测：客户端字段 DeviceID / MachineID / DevicePublicKey / 签名 / IDEVersion / host /'
         + '\n                 各类 x-device-* 请求头全部改动后，返回码不变，DeviceInfo 置空亦同 —— 说明该判定与请求内容无关。'
         + '\n                 处置：① 直接登录 Trae 重新绑定（最稳）；② 等 token 过期后再让 Trae 自己刷新'
         + '\n                 （过期走"恢复"分支，服务端会重新绑定，9-12 那次就是这样成功的）。',
  };
  return m[code] || ('未知返回码 ' + code + ' ' + (msg || '') + '（可能是 Trae 版本升级改了协议，参考 skill 里的诊断顺序重逆）');
}

function fmtMs(ms) { return ms ? new Date(ms).toISOString() : '(未知)'; }
function leftMs(ms) {
  if (!ms) return '(未知)';
  const d = ms - Date.now();
  if (d <= 0) return '已过期 ' + Math.round(-d / 86400000) + ' 天';
  return Math.floor(d / 86400000) + ' 天 ' + Math.floor((d % 86400000) / 3600000) + ' 小时';
}
function redactBody(b) {
  const c = JSON.parse(JSON.stringify(b));
  if (c.RefreshToken) c.RefreshToken = c.RefreshToken.slice(0, 10) + '…(' + c.RefreshToken.length + ')';
  if (c.DeviceInfo && c.DeviceInfo.DevicePublicKey) c.DeviceInfo.DevicePublicKey = '<' + c.DeviceInfo.DevicePublicKey.length + 'B PEM>';
  if (c.DeviceProof && c.DeviceProof.Signature) c.DeviceProof.Signature = '<' + c.DeviceProof.Signature.length + 'B DER>';
  return c;
}

// ---------------- 读取单个数据目录 ----------------
const AUTH_KEY = 'iCubeAuthInfo://icube.cloudide';
const USERTAG_KEY = 'iCubeAuthInfo://usertag';

function readOne(dir) {
  const storageJson = path.join(dir, 'User', 'globalStorage', 'storage.json');
  const tinyStorage = path.join(dir, 'aha', 'TinyStorage');
  const rec = { dir, ok: false, error: null, raw: null, device: null, knownUsers: {},
    storagePath: storageJson, full: null, machineId: '', dcKey: '', keyPair: null };
  if (!fs.existsSync(storageJson)) { rec.error = '无 storage.json'; return rec; }

  let store;
  try { store = JSON.parse(fs.readFileSync(storageJson, 'utf8')); }
  catch (e) { rec.error = 'storage.json 解析失败: ' + e.message; return rec; }

  // usertag 记录该数据目录下登录过的所有 userId（历史账号清单）
  if (store[USERTAG_KEY]) {
    try { rec.knownUsers = JSON.parse(decrypt(unwrapValue(store[USERTAG_KEY]))); }
    catch (e) { rec.knownUsers = { _error: e.message }; }
  }

  if (!store[AUTH_KEY]) { rec.error = '未登录（无 ' + AUTH_KEY + '）'; return rec; }

  let info;
  try { info = JSON.parse(decrypt(unwrapValue(store[AUTH_KEY]))); }
  catch (e) { rec.error = '凭证解密失败: ' + e.message; return rec; }

  let dev = null;
  if (fs.existsSync(tinyStorage)) {
    try {
      const t = JSON.parse(fs.readFileSync(tinyStorage, 'utf8'));
      const rawDev = (t.tiny_storage_data || {})['aha.device.device_id'];
      if (rawDev) {
        const d = JSON.parse(decrypt(rawDev));
        dev = { id: String(d.device_id_str || ''), install: String(d.install_id_str || ''), uuid: d.uuid || '' };
      }
    } catch (e) { /* 设备号读不到不致命 */ }
  }

  const token = String(info.token || '');
  let jwtExp = null, jwtIat = null;
  try {
    const p = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    jwtExp = p.exp ? new Date(p.exp * 1000).toISOString() : null;
    jwtIat = p.iat ? new Date(p.iat * 1000).toISOString() : null;
  } catch { /* ignore */ }

  rec.ok = true;
  rec.device = dev;
  rec.full = info;
  rec.machineId = store['telemetry.machineId'] || '';
  rec.dcKey = dev && dev.id ? 'iCubeAuthInfo://icube-dc:' + dev.id : '';
  if (rec.dcKey) {
    try { if (store[rec.dcKey]) rec.keyPair = JSON.parse(decrypt(unwrapValue(store[rec.dcKey]))); }
    catch { /* 密钥对解不开不致命，续期时会单独报错 */ }
  }
  rec.raw = {
    token,
    deviceId: (dev && dev.id) || '',
    installId: (dev && dev.install) || '',
    userId: String(info.userId || ''),
    account: info.account || {},
    tokenExpiredAt: info.expiredAt || null,
    refreshExpiredAt: info.refreshExpiredAt || null,
    jwtExp, jwtIat,
    host: info.host || null,
    userRegion: info.userRegion || null,
  };
  return rec;
}

// ---------------- 数据目录发现 ----------------
const argv = process.argv.slice(2);
const argAll = (name) => {
  const out = [];
  for (let i = 0; i < argv.length; i++) if (argv[i] === name && argv[i + 1]) out.push(argv[i + 1]);
  return out;
};
const arg = (name, def) => (argAll(name).pop() || def);
const has = (name) => argv.includes(name);

// ---------------- 中文帮助 ----------------
if (argv.some((a) => ['--h', '-h', '--help', '-help', '/?', '--?', 'help'].includes(a))) {
  console.log(`get-trae-credentials.js —— 离线提取 + 续期 TRAE SOLO CN（Trae Work CN）本机登录凭证
不抓包、不 Root、不改动 Trae 本体。仅用 Node 内置模块，Node >= 18。

【凭证在哪】凭证不在安装目录，在用户数据目录：
  %APPDATA%\\TRAE SOLO CN\\User\\globalStorage\\storage.json
      iCubeAuthInfo://icube.cloudide         -> token / refreshToken / 到期时间
      iCubeAuthInfo://icube-dc:<deviceId>     -> 设备 EC 密钥对（续期签名用）
  %APPDATA%\\TRAE SOLO CN\\aha\\TinyStorage   -> aha.device.device_id（即 x-device-id）

【一、提取凭证】
  (无参数)                    扫描默认数据目录，输出可直接粘贴的配置行 TOKEN#x-device-id#备注
  --list                      列出所有发现的账号（userId / 到期时间 / 该目录登录过谁）
  --all                       输出所有账号的配置行
  --json                      输出全部明细 JSON
  --dir <目录>                指定数据目录，可重复；也可用环境变量 TRAE_DATA_DIRS（分号分隔）
  --scan <目录>               在指定父目录下递归发现数据目录
  --note <备注>               指定配置行里的备注（单目录时生效）
  --out <文件>                把配置行追加写入文件
  --proxy <URL>               走代理，如 http://127.0.0.1:10808
  --check                     联网验证 token 是否有效（打签到状态接口，只看状态不改数据）

【二、续期（token 14 天，refreshToken 180 天且每次刷新顺延）】
  续期用本机 icube-dc 里的 EC 私钥做 DeviceProof 签名，所以能离线签名。

  ! 2026-09-18 实测结论：截至 Trae 0.1.67，服务端对本机账号的续期请求一律返回
    HTTP 401 / Code 20403 "Token device not match."。已逐项验证该判定与请求内容
    无关（DeviceID、MachineID、DevicePublicKey、签名是否合法、IDEVersion、host、
    x-device-token/x-device-* 请求头、把 DeviceInfo 置空 —— 返回码全部一致）。
    也就是说：这不是脚本 bug，是服务端侧设备绑定状态。
    可行路径见下面【重要提醒】第 6 条。

  --live                      真正调用 ExchangeToken 续期，只打印结果，不改本地文件
                              （调用前会先打印剩余有效期 + 用本机公钥验签自检）
  --live --write-back         续期并写回 storage.json（自动备份 + 回读校验）
  --refresh                   等于 --live --write-back，一条命令搞定
  --self-test                 加解密往返自检，确认写回用的密文格式 Trae 能读
  --probe                     零风险探针：用篡改过的 refreshToken 打接口，验证请求管线，不动真实凭证
                              （正常返回 20101 refresh token is invalid，说明管线通）
  --host <URL>                覆盖 API 主机（默认取 storage.json 里的 host）
  --client-id <ID>            覆盖 ClientID（默认读 product.json 的 authConfig.SOLO.stable）
  --app-version <版本>        覆盖 IDEVersion（默认读 product.json 的 appVersion）
  --force                     --write-back 时即使 Trae 正在运行也强制写入（危险）

【三、其他】
  --h, --help                 显示本帮助

【重要提醒】
  1. --write-back 前必须先完全退出 TRAE SOLO CN，否则内存里的旧值会覆盖新值。
     脚本默认检测到 TRAE SOLO CN.exe 在运行就拒绝写；要强行写加 --force。
  2. 刷新可能轮换 refreshToken。若只用 --live 不写回，Trae 客户端手里的 refreshToken
     可能已失效，下次自动刷新会失败 -> 建议 --live 一定配 --write-back。
  3. 续期用的私钥就存在本机 icube-dc 里，所以整个续期过程可以离线签名。
  4. 写回前建议先跑 --self-test，确认加解密与 Trae 容器格式一致。
  5. token 等于账号密码，别贴到聊天/日志里。
  6. 续期走不通时的两条路（按推荐顺序）：
     A. 在 Trae 里重新登录一次 —— 会重新绑定设备并签发新的 token+refreshToken，
        之后本机重新跑一次 node get-trae-credentials.js 即可。
     B. 什么都不做，等 token 自然过期（expiredAt 之后）。过期时客户端走的是
        "恢复" 分支（NEED_LOGIN -> 仍用 refreshToken 换新），服务端会重新绑定设备；
        9-12 那次成功刷新就是这么发生的。做法：过期后打开一次 Trae，再跑本脚本。
     无论哪条路，跑完都建议用 --check 验证。

【示例】
  node get-trae-credentials.js                                  提取当前账号配置行
  node get-trae-credentials.js --check                          验证 token 还能用
  node get-trae-credentials.js --list                           看有哪些账号、什么时候过期
  node get-trae-credentials.js --refresh                        续期并写回（先退出 Trae）
  node get-trae-credentials.js --probe                          不消耗凭证地验证续期管线
  node get-trae-credentials.js --dir D:\\trae-acc2 --json        指定数据目录导出明细`);
  process.exit(0);
}

// ---------------- 续期相关开关 ----------------
const R_SELFTEST = has('--self-test');
const R_REFRESH = has('--refresh');            // 等于 --live --write-back
const R_LIVE = has('--live') || R_REFRESH;
const R_WB = has('--write-back') || R_REFRESH;
const R_PROBE = has('--probe');
const R_FORCE = has('--force');
const R_QUIET = R_SELFTEST || R_LIVE || R_PROBE;   // 这些模式下不打印凭证转储

function isDataDir(p) {
  try { return fs.existsSync(path.join(p, 'User', 'globalStorage', 'storage.json')); }
  catch { return false; }
}

function discoverDirs() {
  const out = [];
  const push = (p) => { if (p && !out.includes(p)) out.push(p); };

  for (const d of argAll('--dir')) push(path.resolve(d));
  for (const d of (process.env.TRAE_DATA_DIRS || '').split(';').map((s) => s.trim()).filter(Boolean)) push(path.resolve(d));
  if (process.env.TRAE_DATA_DIR) push(path.resolve(process.env.TRAE_DATA_DIR));

  // 默认根
  if (process.platform === 'win32' && process.env.APPDATA) {
    push(path.join(process.env.APPDATA, 'TRAE SOLO CN'));
  } else {
    push(path.join(os.homedir(), '.config', 'TRAE SOLO CN'));
  }

  // --scan：在给定父目录下递归（深度 3）找含 storage.json 的数据目录
  const scanRoots = argAll('--scan');
  if (scanRoots.length === 0 && process.platform === 'win32' && process.env.APPDATA) {
    scanRoots.push(process.env.APPDATA);   // 自动扫 %APPDATA% 下的 Trae 系目录
  }
  for (const root of scanRoots) {
    const base = path.resolve(root);
    let entries = [];
    try { entries = fs.readdirSync(base, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      if (root !== process.env.APPDATA && !/trae/i.test(e.name)) continue;
      if (root === process.env.APPDATA && !/trae/i.test(e.name)) continue;
      const cand = path.join(base, e.name);
      if (isDataDir(cand)) push(cand);
      // 再下一层（例如 D:\trae\acc2）
      try {
        for (const s of fs.readdirSync(cand, { withFileTypes: true })) {
          if (s.isDirectory() && isDataDir(path.join(cand, s.name))) push(path.join(cand, s.name));
        }
      } catch { /* ignore */ }
    }
  }
  return out;
}

// ---------------- 主流程 ----------------
const dirs = discoverDirs();
if (dirs.length === 0) {
  console.error('未发现任何 TRAE SOLO CN 数据目录');
  process.exit(1);
}

const records = dirs.map(readOne);
const alive = records.filter((r) => r.ok);
const dead = records.filter((r) => !r.ok);

// 历史 userId（来自 usertag），用于说明"曾经登录过但凭证已被覆盖"的账号
const historical = new Map();
for (const r of records) {
  for (const uid of Object.keys(r.knownUsers || {})) {
    if (uid.startsWith('_')) continue;
    if (!historical.has(uid)) historical.set(uid, []);
    historical.get(uid).push(r.dir);
  }
}

const note = arg('--note', '');
const lines = alive.map((r) => {
  const n = note || (r.raw.account && r.raw.account.userTag) || '';
  return { rec: r, configLine: [r.raw.token, r.raw.deviceId, n].join('#') };
});

if (has('--json')) {
  console.log(JSON.stringify({
    scannedDirs: dirs,
    accounts: lines.map(({ rec, configLine }) => ({
      dataDir: rec.dir,
      configLine,
      ...rec.raw,
      knownUsers: rec.knownUsers,
    })),
    errors: dead.map((r) => ({ dataDir: r.dir, error: r.error })),
  }, null, 2));
} else if (has('--list')) {
  console.log('扫描到 ' + dirs.length + ' 个数据目录，其中 ' + alive.length + ' 个有有效凭证\n');
  for (const { rec } of lines) {
    console.log('数据目录 :', rec.dir);
    console.log('  userId      :', rec.raw.userId, '| 备注:', rec.raw.account?.userTag || '-');
    console.log('  x-device-id :', rec.raw.deviceId || '(未取到)');
    console.log('  token 到期  :', rec.raw.tokenExpiredAt || rec.raw.jwtExp || '(未知)');
    console.log('  refresh 到期:', rec.raw.refreshExpiredAt || '(未知)');
    console.log('  该目录登录过:', Object.keys(rec.knownUsers || {}).filter((k) => !k.startsWith('_')).join(', ') || '(未知)');
    console.log('');
  }
  if (historical.size) {
    console.log('历史登录过但已被覆盖的 userId（无有效 token）:');
    for (const [uid, where] of historical) if (!alive.some((r) => r.raw.userId === uid)) console.log('  ', uid, '←', where[0]);
  }
} else if (R_QUIET) {
  // 续期 / 自检 / 探针模式：不转储凭证，下面单独处理
} else {
  if (alive.length === 0) {
    console.error('没有找到有效凭证。');
    for (const r of dead) console.error('  ', r.dir, '→', r.error);
    if (historical.size) {
      console.error('  注：以下 userId 曾登录过，但本地 token 已被后来登录的账号覆盖:', [...historical.keys()].join(', '));
    }
    process.exit(1);
  }
  console.log('账号数: ' + alive.length + '\n');
  for (const { rec, configLine } of lines) {
    console.log('--- ' + rec.dir);
    console.log('userId      :', rec.raw.userId, '| 备注:', rec.raw.account?.userTag || '-');
    console.log('region      :', rec.raw.userRegion, '| host:', rec.raw.host);
    console.log('token 到期  :', rec.raw.tokenExpiredAt || rec.raw.jwtExp || '(未知)');
    console.log('refresh 到期:', rec.raw.refreshExpiredAt || '(未知)', '（续期见 --h）');
    console.log('x-device-id :', rec.raw.deviceId || '(未取到)');
    console.log('配置行      :', configLine);
    console.log('');
  }
  if (alive.length > 1) {
    console.log('=== 全部配置行（可直接粘贴到 worker /admin） ===');
    for (const { configLine } of lines) console.log(configLine);
  }
  if (historical.size) {
    const covered = [...historical.keys()].filter((uid) => !alive.some((r) => r.raw.userId === uid));
    if (covered.length) {
      console.log('\n注意：以下 userId 曾在本机登录，但本地 token 已被覆盖，无法再取到:');
      for (const uid of covered) console.log('  ', uid, '←', historical.get(uid)[0]);
    }
  }
}

const outFile = arg('--out', null);
if (outFile) {
  const target = has('--all') || lines.length > 1 ? lines : lines.slice(-1);
  for (const { configLine } of target) fs.appendFileSync(outFile, configLine + '\n', 'utf8');
  console.error('\n已追加 ' + target.length + ' 行到: ' + path.resolve(outFile));
}

// ---------------- --check ----------------
if (has('--check')) {
  const proxy = arg('--proxy', process.env.HTTPS_PROXY || '');
  (async () => {
    for (const { rec } of lines) {
      const base = (rec.raw.host || 'https://api.trae.cn').replace(/\/$/, '');
      const url = base + '/trae/api/v2/ug/checkin_credits/status';
      console.error('\n=== 验证 ' + rec.raw.userId + ' (GET ' + url + ') ===');
      const opt = {
        method: 'GET',
        headers: {
          Authorization: 'Cloud-IDE-JWT ' + rec.raw.token,
          'x-device-id': rec.raw.deviceId,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        signal: AbortSignal.timeout(20000),
      };
      if (proxy) {
        try { opt.dispatcher = new (require('undici').ProxyAgent)(proxy); } catch { /* undici 不可用则直连 */ }
      }
      try {
        const res = await fetch(url, opt);
        console.log('HTTP ' + res.status, (await res.text()).slice(0, 600));
      } catch (e) {
        console.error('请求失败: ' + e.message);
      }
    }
  })().catch((e) => { console.error(e.message); process.exitCode = 2; });
}

// ---------------- 续期：--self-test / --probe / --live / --write-back / --refresh ----------------
(async () => {
  // ---- 加解密往返自检 ----
  if (R_SELFTEST) {
    let bad = 0;
    for (const d of dirs) {
      const sp = path.join(d, 'User', 'globalStorage', 'storage.json');
      if (!fs.existsSync(sp)) continue;
      const st = JSON.parse(fs.readFileSync(sp, 'utf8'));
      for (const k of Object.keys(st).filter((x) => x.startsWith('iCubeAuthInfo'))) {
        const t0 = detectType(Buffer.from(st[k], 'base64'));
        const p1 = decrypt(unwrapValue(st[k]));
        const ct = encrypt(p1, t0 === 'UNKNOWN' ? 'AES' : t0);
        const blob = Buffer.from(ct, 'base64');
        let ok = false, err = '';
        try { ok = decrypt(ct) === p1; } catch (e) { err = e.message; }
        const hdrOk = MAGIC_AES.every((v, i) => blob[i] === v) && (blob.length - HDR - KEYLEN) % 16 === 0;
        if (!ok || !hdrOk) bad++;
        console.log((ok && hdrOk ? '  PASS  ' : '  FAIL  ') + k + ' | 原文 ' + p1.length + 'B | 密文 ' + blob.length + 'B ' + (hdrOk ? '' : '头/对齐异常 ') + err);
      }
    }
    console.log(bad === 0 ? '\n自检通过：加解密与 Trae 容器格式一致。' : '\n自检失败，请勿使用 --write-back。');
    process.exitCode = bad === 0 ? 0 : 4;
    return;
  }

  if (!R_LIVE && !R_PROBE) return;      // 默认只提取，不做续期

  if (alive.length === 0) { console.error('没有可用凭证，无法续期。'); process.exitCode = 1; return; }

  // 写回前必须退出 Trae。这个检查放在发请求之前，避免白白消耗一次刷新。
  if (R_WB && !R_PROBE && traeRunning() && !R_FORCE) {
    console.error('! 检测到 TRAE SOLO CN.exe 正在运行，已中止。');
    console.error('  原因：写回 storage.json 会被 Trae 内存里的旧值覆盖；且刷新可能轮换 refreshToken。');
    console.error('  做法：完全退出 TRAE SOLO CN 后重跑；确要强行写入加 --force。');
    console.error('  只想验证管线不消耗凭证：node get-trae-credentials.js --probe');
    process.exitCode = 2;
    return;
  }

  // --live 不写回时给个提醒：刷新可能轮换 refreshToken，Trae 手里的就废了
  if (R_LIVE && !R_WB && !R_PROBE && traeRunning() && !R_FORCE) {
    console.error('! 提醒：TRAE SOLO CN 正在运行，且本次不写回 storage.json。');
    console.error('  若服务端轮换了 refreshToken，Trae 客户端手里的那把会失效，下次自动刷新将失败。');
    console.error('  建议改用 --refresh（刷新 + 写回），或先退出 Trae。');
  }

  const meta = findAppMeta();
  const host0 = arg('--host', '');
  const proxy = arg('--proxy', process.env.HTTPS_PROXY || '');
  let failed = 0;

  for (const rec of alive) {
    const info = rec.full || {};
    const host = (host0 || info.host || 'https://api.trae.cn').replace(/\/$/, '');
    const tokenExp = info.expiredAt ? Date.parse(info.expiredAt) : null;
    const refExp = info.refreshExpiredAt ? Date.parse(info.refreshExpiredAt) : null;

    console.log('\n=== 续期 ' + rec.dir);
    console.log('  userId       :', info.userId, '| 备注:', info.account?.userTag || '-');
    console.log('  x-device-id  :', rec.raw.deviceId || '(未取到)');
    console.log('  token 到期   :', fmtMs(tokenExp), '→ 剩余', leftMs(tokenExp));
    console.log('  refresh 到期 :', fmtMs(refExp), '→ 剩余', leftMs(refExp));

    if (!info.refreshToken) { console.log('  ! 本地没有 refreshToken，无法续期'); failed++; continue; }
    if (!rec.keyPair || !rec.keyPair.privateKeyPEM) {
      console.log('  ! 缺少设备密钥对（' + (rec.dcKey || 'iCubeAuthInfo://icube-dc:<deviceId>') + '），无法签名');
      failed++; continue;
    }
    if (!R_PROBE && refExp && refExp <= Date.now()) {
      console.log('  ! refreshToken 已过期，本机救不回来，需要重新登录'); failed++; continue;
    }

    // DeviceInfo：优先从历史日志还原，保证与服务器见过的字节一致
    const harvested = harvestLogs(rec.dir);
    const devInfo = { ...(harvested && harvested.DeviceInfo ? harvested.DeviceInfo : probeDev()) };
    devInfo.DeviceID = rec.raw.deviceId || devInfo.DeviceID || '';
    devInfo.DevicePublicKey = rec.keyPair.publicKeyPEM;
    devInfo.PlatformCode = devInfo.PlatformCode || 'SOLO_PC';
    devInfo.DeviceType = devInfo.DeviceType || 'PC';

    const clientId = arg('--client-id', '') || (meta && meta.clientId) || (harvested && harvested.ClientID) || DEFAULT_CLIENT_ID;
    const ideVersion = arg('--app-version', '') || (meta && meta.appVersion) || (harvested && harvested.IDEVersion) || DEFAULT_APP_VERSION;
    devInfo.ClientVersion = ideVersion;   // 与 IDEVersion 保持一致

    const effToken = R_PROBE ? tamperToken(info.refreshToken) : info.refreshToken;
    const proof = buildProof(rec, effToken, clientId);
    const body = {
      ClientID: clientId, ClientSecret: '', RefreshToken: effToken,
      DeviceInfo: devInfo, DeviceProof: proof.DeviceProof, IDEVersion: ideVersion,
    };

    let selfTest = 'fail';
    try {
      selfTest = crypto.createVerify('sha256').update(proof.msg).verify(
        { key: rec.keyPair.publicKeyPEM, format: 'pem' }, Buffer.from(proof.DeviceProof.Signature, 'base64')) ? 'pass' : 'fail';
    } catch (e) { selfTest = 'error: ' + e.message; }

    console.log('  host         :', host, '| ClientID:', clientId, '| IDEVersion:', ideVersion);
    console.log('  DeviceInfo   :', harvested && harvested.DeviceInfo ? '历史日志还原' : '本机探测');
    console.log('  签名自检     :', selfTest);
    console.log('  请求预览     :', JSON.stringify(redactBody(body)).slice(0, 320) + ' …');
    console.log('\n  → POST ' + host + EXCHANGE_PATH + (R_PROBE ? '  [探针：refreshToken 已篡改]' : '  ' + (R_WB ? '(将写回)' : '(不写回)')));

    let res;
    try {
      const opt = {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-cloudide-token': info.token || '' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(30000),
      };
      if (proxy) { try { opt.dispatcher = new (require('undici').ProxyAgent)(proxy); } catch { console.log('  ! 无法加载 undici，改为直连'); } }
      res = await fetch(host + EXCHANGE_PATH, opt);
    } catch (e) { console.log('  ! 请求异常: ' + e.message); failed++; continue; }

    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch { /* 保留原文 */ }
    const R = json && (json.Result || json.result);
    console.log('  ← HTTP ' + res.status);
    if (R && R.Token) {
      console.log('     DeviceBindStatus :', R.DeviceBindStatus, '| BoundDeviceID:', R.BoundDeviceID);
      console.log('     新 token 到期    :', fmtMs(R.TokenExpireAt), '(' + (R.TokenExpireDuration / 86400000) + ' 天)');
      console.log('     新 refresh 到期  :', fmtMs(R.RefreshExpireAt));
      console.log('     refreshToken     :', R.RefreshToken !== info.refreshToken ? '已轮换 ⚠' : '未变化');
    } else {
      const code = json && json.ResponseMetadata && json.ResponseMetadata.Error && json.ResponseMetadata.Error.Code;
      const msg = json && json.ResponseMetadata && json.ResponseMetadata.Error && json.ResponseMetadata.Error.Message;
      console.log('     原始响应:', text.slice(0, 600));
      if (code) console.log('     诊断      : ' + explainExchangeError(code, msg));
    }

    if (R_PROBE) { console.log('  （探针不会改动任何本地文件）'); continue; }
    if (!R || !R.Token) { failed++; continue; }

    if (!R_WB) {
      console.log('  （未加 --write-back，本地 storage.json 未改动）');
      console.log('  ! 若服务端已轮换 refreshToken，请尽快用 --refresh 写回，否则 Trae 下次自动刷新会失败');
      continue;
    }
    if (traeRunning() && !R_FORCE) {
      console.log('  ! Trae 正在运行（TRAE SOLO CN.exe），写回会被内存里的旧值覆盖。');
      console.log('    请先完全退出 TRAE SOLO CN 再执行；确要强行写入加 --force。');
      failed++; continue;
    }

    const bak = rec.storagePath + '.traebak-' + Date.now();
    fs.copyFileSync(rec.storagePath, bak);
    const newInfo = {
      ...info,
      token: R.Token,
      refreshToken: R.RefreshToken,
      expiredAt: new Date(R.TokenExpireAt).toISOString(),
      refreshExpiredAt: new Date(R.RefreshExpireAt).toISOString(),
      tokenReleaseAt: new Date().toISOString(),
    };
    const fresh = JSON.parse(fs.readFileSync(rec.storagePath, 'utf8'));
    fresh[AUTH_KEY] = encrypt(JSON.stringify(newInfo));
    fs.writeFileSync(rec.storagePath, JSON.stringify(fresh, null, 4), 'utf8');

    let ok = false;
    try {
      const back = JSON.parse(decrypt(unwrapValue(JSON.parse(fs.readFileSync(rec.storagePath, 'utf8'))[AUTH_KEY])));
      ok = back.token === R.Token && back.refreshToken === R.RefreshToken;
    } catch { /* ok 保持 false */ }

    if (ok) {
      console.log('  ✔ 已写回 ' + rec.storagePath);
      console.log('    备份:', bak);
      console.log('    回读校验: pass');
      console.log('\n  新配置行:', [R.Token, rec.raw.deviceId, info.account?.userTag || ''].join('#'));
    } else {
      console.log('  ✘ 写回后回读校验失败 ' + rec.storagePath);
      console.log('    请用备份还原:', bak);
      failed++;
    }
  }

  if (failed) { console.error('\n有 ' + failed + ' 个账号处理失败。'); process.exitCode = 2; }
})().catch((e) => { console.error('续期异常:', e.message); process.exitCode = 3; });
