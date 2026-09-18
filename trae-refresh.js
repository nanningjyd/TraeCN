#!/usr/bin/env node
/**
 * trae-refresh.js
 * ------------------------------------------------------------------
 * 在 TOKEN 过期前主动续期（refresh）本机 TRAE SOLO CN 的登录态。
 * 全程离线读取本机文件，只有 --live 才联网；默认只做预览和签名自检。
 *
 * 接口（逆向自 resources/app/out/main.js）：
 *   POST {host}/trae/api/v3/oauth/ExchangeToken
 *   body = {
 *     ClientID: <product.json iCubeApp.authConfig.SOLO.stable>   // en1oxy7wnw8j9n
 *     ClientSecret: "",
 *     RefreshToken: <本地 storage.json 里的 refreshToken>,
 *     DeviceInfo: { DeviceID, MachineID, PlatformCode:"SOLO_PC", DeviceType:"PC", ... },
 *     DeviceProof: { Signature, Timestamp, Nonce },
 *     IDEVersion: <product.json appVersion>
 *   }
 *   DeviceProof.Signature = ECDSA-SHA256(
 *       "POST /trae/api/v3/oauth/ExchangeToken <ClientID> <RefreshToken> <ts> <nonce>",
 *       <本地 icube-dc 里的 EC P-256 私钥>
 *   ).base64   ← 私钥就存在本机，所以完全离线可签
 *
 * 有效期语义（逆向自 authUtil.js）：
 *   Token          14 天 (TokenExpireDuration = 1209600000)
 *   RefreshToken  180 天，**每次刷新后顺延 180 天** → 只要 180 天内刷一次就能一直续下去
 *   剩余 <= 24h 时客户端会自己触发 NEED_REFRESH
 *
 * 用法：
 *   node trae-refresh.js                      # 预览：剩余有效期 + 决策 + 签名自检（不联网）
 *   node trae-refresh.js --self-test           # 加解密往返自检（写回前的格式校验）
 *   node trae-refresh.js --probe               # 零风险探针：用篡改的 refreshToken 打接口
 *   node trae-refresh.js --live                # 真正刷新，只打印结果，不改本地文件
 *   node trae-refresh.js --live --write-back   # 刷新并写回 storage.json（需先退出 Trae）
 *   node trae-refresh.js --dir D:\trae-acc2    # 指定数据目录（可重复）
 *   node trae-refresh.js --json                # JSON 输出（默认不含明文 token）
 *   node trae-refresh.js --proxy http://127.0.0.1:10808
 *
 * 安全说明：
 *   - 默认不发任何网络请求；--live 才会调 ExchangeToken。
 *   - --live 不带 --write-back 时不动本地文件，但服务端可能已轮换 refreshToken，
 *     此时建议立刻用 --write-back 写回，否则 Trae 客户端下次刷新会失败。
 *   - --write-back 会先备份为 storage.json.traebak-<时间戳>，写完回读校验；
 *     检测到 TRAE SOLO CN.exe 在运行会拒绝执行（可用 --force 覆盖）。
 *
 * 仅用 Node 内置模块，无第三方依赖。Node >= 18。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execSync } = require('child_process');

// ---------------- byteCrypto（与 get-trae-credentials.js 保持一致） ----------------
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
function derive(key, type) {
  return sha512(Buffer.concat([sha512(key), pad64(type)]));
}
function decrypt(container) {
  const blob = Buffer.from(String(container), 'base64');
  const type = detectType(blob);
  if (type === 'UNKNOWN') throw new Error('未知密文类型（Trae 版本可能已变）');
  const key = blob.subarray(HDR, HDR + KEYLEN);
  const ct = blob.subarray(HDR + KEYLEN);
  const derived = derive(key, type);
  const dec = crypto.createDecipheriv('aes-128-cbc', derived.subarray(0, 16), derived.subarray(16, 32));
  const plain = Buffer.concat([dec.update(ct), dec.final()]);
  const body = plain.subarray(BH);
  if (!sha512(body).equals(plain.subarray(0, BH))) throw new Error('MAC 校验失败');
  return body.toString('utf8');
}
/** 与 Trae 的 MUe 等价：6B magic + 32B 随机key + AES-128-CBC(PKCS7) */
function encrypt(text, type = 'AES') {
  const body = Buffer.from(text, 'utf8');
  const plain = Buffer.concat([sha512(body), body]);
  const key = crypto.randomBytes(KEYLEN);
  const derived = derive(key, type);
  const enc = crypto.createCipheriv('aes-128-cbc', derived.subarray(0, 16), derived.subarray(16, 32));
  const ct = Buffer.concat([enc.update(plain), enc.final()]);
  const magic = Buffer.from(type === 'AES_PRIVATE' ? MAGIC_PRIV : MAGIC_AES);
  return Buffer.concat([magic, key, ct]).toString('base64');
}

// ---------------- CLI ----------------
const argv = process.argv.slice(2);
const argAll = (name) => {
  const out = [];
  for (let i = 0; i < argv.length; i++) if (argv[i] === name && argv[i + 1]) out.push(argv[i + 1]);
  return out;
};
const arg = (name, def) => (argAll(name).pop() || def);
const has = (name) => argv.includes(name);

const AUTH_KEY = 'iCubeAuthInfo://icube.cloudide';
const DEFAULT_CLIENT_ID = 'en1oxy7wnw8j9n';   // product.json → iCubeApp.authConfig.SOLO.stable
const DEFAULT_APP_VERSION = '0.1.67';         // product.json → appVersion
const EXCHANGE_PATH = '/trae/api/v3/oauth/ExchangeToken';

// ---------------- 读数据目录 ----------------
function readDeviceId(dir) {
  try {
    const t = JSON.parse(fs.readFileSync(path.join(dir, 'aha', 'TinyStorage'), 'utf8'));
    const raw = (t.tiny_storage_data || {})['aha.device.device_id'];
    if (!raw) return null;
    const d = JSON.parse(decrypt(raw));
    return String(d.device_id_str || '');
  } catch { return null; }
}

/** 从历史日志里捞上次成功请求的 DeviceInfo / ClientID / IDEVersion —— 保证与服务器见过的字节一致 */
function harvestFromLogs(dir) {
  const logsRoot = path.join(dir, 'logs');
  let files = [];
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
      const body = JSON.parse(last[2]);
      return { url: last[1], ClientID: body.ClientID, IDEVersion: body.IDEVersion, DeviceInfo: body.DeviceInfo };
    } catch { /* 换下一个日志 */ }
  }
  return null;
}

/** 定位安装目录，读 product.json 拿 appVersion / authConfig（客户端已升级时比日志里的旧版本更准） */
function findAppMeta() {
  const cands = [];
  if (process.env.TRAE_APP_DIR) cands.push(process.env.TRAE_APP_DIR);
  const roots = [];
  if (process.platform === 'win32') {
    for (const r of ['D:\\Program Files', 'E:\\Program Files', process.env.ProgramFiles, process.env['ProgramFiles(x86)'],
      process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'Programs')]) if (r) roots.push(r);
  } else if (process.platform === 'darwin') roots.push('/Applications');
  else roots.push('/opt', '/usr/lib');
  for (const r of roots) {
    for (const n of ['TRAE SOLO CN', 'Trae Solo CN', 'Trae CN']) cands.push(path.join(r, n));
  }
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

function probeDeviceInfo() {
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
      try { return execSync(`powershell -NoProfile -Command "${ps}"`, { encoding: 'utf8', timeout: 6000 }).trim(); }
      catch { return ''; }
    };
    info.DeviceModel = q('(Get-CimInstance Win32_BaseBoard).Product') || '';
    info.DeviceBrand = q('(Get-CimInstance Win32_BaseBoard).Manufacturer') || '';
  }
  return info;
}

// ---------------- 单个账号的读 + 刷新 ----------------
function loadAccount(dir, opts) {
  const storagePath = path.join(dir, 'User', 'globalStorage', 'storage.json');
  if (!fs.existsSync(storagePath)) return { dir, ok: false, error: '无 storage.json' };
  let store;
  try { store = JSON.parse(fs.readFileSync(storagePath, 'utf8')); }
  catch (e) { return { dir, ok: false, error: 'storage.json 解析失败: ' + e.message }; }
  if (!store[AUTH_KEY]) return { dir, ok: false, error: '未登录（无 ' + AUTH_KEY + '）' };

  let info;
  try { info = JSON.parse(decrypt(store[AUTH_KEY])); }
  catch (e) { return { dir, ok: false, error: '凭证解密失败: ' + e.message }; }

  const deviceId = readDeviceId(dir) || '';
  const dcKey = `iCubeAuthInfo://icube-dc:${deviceId}`;
  let keyPair = null;
  try {
    if (store[dcKey]) keyPair = JSON.parse(decrypt(store[dcKey]));
  } catch (e) { /* 下面统一报错 */ }

  const harvested = harvestFromLogs(dir);
  const devSource = harvested && harvested.DeviceInfo ? '历史日志还原' : '本机探测';
  const devInfo = { ...(harvested && harvested.DeviceInfo ? harvested.DeviceInfo : probeDeviceInfo()) };
  // 这两项必须用**本机当前**的真实值，不能沿用日志里的旧值
  devInfo.DeviceID = deviceId;
  if (keyPair && keyPair.publicKeyPEM) devInfo.DevicePublicKey = keyPair.publicKeyPEM;
  devInfo.PlatformCode = devInfo.PlatformCode || 'SOLO_PC';
  devInfo.DeviceType = devInfo.DeviceType || 'PC';

  const meta = findAppMeta();
  const clientId = opts.clientId || (meta && meta.clientId) || (harvested && harvested.ClientID) || DEFAULT_CLIENT_ID;
  const ideVersion = opts.appVersion || (meta && meta.appVersion) || (harvested && harvested.IDEVersion) || DEFAULT_APP_VERSION;
  devInfo.ClientVersion = ideVersion;   // DeviceInfo.ClientVersion 与 IDEVersion 必须一致
  return {
    dir, ok: true, storagePath, store,
    info, deviceId, keyPair, devInfo, devSource,
    clientId, ideVersion,
    appDir: meta ? meta.dir : '',
    machineId: store['telemetry.machineId'] || '',
    dcKey,
    tokenExpiredAt: info.expiredAt ? Date.parse(info.expiredAt) : null,
    refreshExpiredAt: info.refreshExpiredAt ? Date.parse(info.refreshExpiredAt) : null,
  };
}

function buildProof(acc, refreshToken) {
  const ts = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('hex');
  const msg = ['POST', EXCHANGE_PATH, acc.clientId, refreshToken, String(ts), nonce].join(' ');
  const signature = crypto.createSign('sha256').update(msg).sign(acc.keyPair.privateKeyPEM).toString('base64');
  return { msg, DeviceProof: { Signature: signature, Timestamp: ts, Nonce: nonce } };
}

function buildBody(acc, proof, refreshTokenOverride) {
  return {
    ClientID: acc.clientId,
    ClientSecret: '',
    RefreshToken: refreshTokenOverride !== undefined ? refreshTokenOverride : acc.info.refreshToken,
    DeviceInfo: acc.devInfo,
    DeviceProof: proof.DeviceProof,
    IDEVersion: acc.ideVersion,
  };
}

/** 篡改 refreshToken（最后一个字符取反），用于验证签名是否被服务端接受 */
function tamperToken(t) {
  const last = t.slice(-1);
  return t.slice(0, -1) + (last === 'A' ? 'B' : 'A');
}

const fmt = (ms) => (ms ? new Date(ms).toISOString() : '(未知)');
const left = (ms) => {
  if (!ms) return '(未知)';
  const d = ms - Date.now();
  if (d <= 0) return '已过期 ' + Math.round(-d / 86400000) + ' 天';
  const days = Math.floor(d / 86400000), hours = Math.floor((d % 86400000) / 3600000);
  return days + ' 天 ' + hours + ' 小时';
};
const mask = (s) => (typeof s === 'string' && s.length > 12 ? s.slice(0, 10) + '…(' + s.length + ')' : '<empty>');

function redact(body) {
  const c = JSON.parse(JSON.stringify(body));
  if (c.RefreshToken) c.RefreshToken = mask(c.RefreshToken);
  if (c.DeviceInfo && c.DeviceInfo.DevicePublicKey) c.DeviceInfo.DevicePublicKey = '<' + c.DeviceInfo.DevicePublicKey.length + 'B PEM>';
  if (c.DeviceProof && c.DeviceProof.Signature) c.DeviceProof.Signature = '<' + c.DeviceProof.Signature.length + 'B DER>';
  return c;
}

async function callExchange(host, acc, body, proxy) {
  const url = host.replace(/\/$/, '') + EXCHANGE_PATH;
  const headers = { 'Content-Type': 'application/json', 'x-cloudide-token': acc.info.token || '' };
  const opt = { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(30000) };
  if (proxy) {
    try {
      const { ProxyAgent } = require('undici');
      opt.dispatcher = new ProxyAgent(proxy);
    } catch { console.error('  ! 无法加载 undici，改为直连'); }
  }
  const res = await fetch(url, opt);
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* 保留原文 */ }
  return { status: res.status, url, json, text };
}

// ---------------- 主流程 ----------------
function discoverDirs() {
  const out = [];
  const push = (p) => { if (p && !out.includes(p)) out.push(p); };
  for (const d of argAll('--dir')) push(path.resolve(d));
  for (const d of (process.env.TRAE_DATA_DIRS || '').split(';').map((s) => s.trim()).filter(Boolean)) push(path.resolve(d));
  if (process.env.TRAE_DATA_DIR) push(path.resolve(process.env.TRAE_DATA_DIR));
  if (process.platform === 'win32' && process.env.APPDATA) push(path.join(process.env.APPDATA, 'TRAE SOLO CN'));
  else push(path.join(os.homedir(), '.config', 'TRAE SOLO CN'));
  return out;
}

function traeRunning() {
  if (process.platform !== 'win32') return false;
  try {
    const out = execSync('tasklist /FI "IMAGENAME eq TRAE SOLO CN.exe" /NH', { encoding: 'utf8', timeout: 8000 });
    return /TRAE SOLO CN\.exe/i.test(out);
  } catch { return false; }
}

const JSON_OUT = has('--json');
const LIVE = has('--live');
const PROBE = has('--probe');          // 零风险探针：用篡改后的 refreshToken 打接口
const WRITE_BACK = has('--write-back');
const FORCE = has('--force');
const PROXY = arg('--proxy', process.env.HTTPS_PROXY || '');
const HOST_OVERRIDE = arg('--host', '');

(async () => {
  const dirs = discoverDirs();

  // ---- --self-test：加密/解密往返自检（确认写回用的密文 Trae 能读）----
  if (has('--self-test')) {
    let bad = 0;
    for (const d of dirs) {
      const sp = path.join(d, 'User', 'globalStorage', 'storage.json');
      if (!fs.existsSync(sp)) continue;
      const st = JSON.parse(fs.readFileSync(sp, 'utf8'));
      for (const k of Object.keys(st).filter((x) => x.startsWith('iCubeAuthInfo'))) {
        const t0 = detectType(Buffer.from(st[k], 'base64'));
        const p1 = decrypt(st[k]);
        const ct = encrypt(p1, t0 === 'UNKNOWN' ? 'AES' : t0);
        let ok = false, err = '';
        try { ok = decrypt(ct) === p1; } catch (e) { err = e.message; }
        const blob = Buffer.from(ct, 'base64');
        const hdrOk = MAGIC_AES.every((v, i) => blob[i] === v) && (blob.length - HDR - KEYLEN) % 16 === 0;
        if (!ok || !hdrOk) bad++;
        console.log((ok && hdrOk ? '  PASS  ' : '  FAIL  ') + k, '| 原文长度', p1.length, '| 密文', blob.length, 'B', hdrOk ? '' : '头/对齐异常', err);
      }
    }
    console.log(bad === 0 ? '\n自检通过：加解密与 Trae 容器格式一致。' : '\n自检失败，请勿使用 --write-back。');
    process.exitCode = bad === 0 ? 0 : 4;
    return;
  }

  const accounts = dirs.map((d) => loadAccount(d, {
    clientId: arg('--client-id', ''),
    appVersion: arg('--app-version', ''),
  })).filter((a) => a.ok || (JSON_OUT || !a.ok));

  const good = accounts.filter((a) => a.ok);
  if (good.length === 0) {
    console.error('没有找到可用凭证。');
    for (const a of accounts) console.error('  ', a.dir, '→', a.error);
    process.exit(1);
  }

  const results = [];

  // 写回前必须退出 Trae。这个检查放在发请求之前，避免白白消耗一次刷新。
  if (WRITE_BACK && !PROBE && LIVE && traeRunning() && !FORCE) {
    console.error('! 检测到 TRAE SOLO CN.exe 正在运行，已中止。');
    console.error('  原因：写回 storage.json 会被 Trae 内存里的旧值覆盖；且刷新可能轮换 refreshToken。');
    console.error('  做法：完全退出 TRAE SOLO CN 后重跑；确要强行写入加 --force。');
    process.exitCode = 2;
    return;
  }

  for (const acc of good) {
    const host = HOST_OVERRIDE || (acc.info.host || 'https://api.trae.cn');
    const needRefresh = acc.tokenExpiredAt && acc.tokenExpiredAt - Date.now() <= 24 * 3600 * 1000;
    const r = {
      dataDir: acc.dir, host, userId: acc.info.userId, deviceId: acc.deviceId,
      tokenExpiredAt: acc.tokenExpiredAt, refreshExpiredAt: acc.refreshExpiredAt,
      needRefresh, refreshed: false, error: null,
    };

    // 构造请求 + 用公钥验签（离线自检，确认私钥与设备绑定公钥一致）
    let body = null, selfTest = null;
    if (!acc.keyPair || !acc.keyPair.privateKeyPEM) {
      r.error = `缺少设备密钥对（${acc.dcKey}）——无法签名，需先在这台机器登录过一次`;
    } else {
      const effToken = PROBE ? tamperToken(acc.info.refreshToken) : acc.info.refreshToken;
      const proof = buildProof(acc, effToken);
      body = buildBody(acc, proof, effToken);
      try {
        const ok = crypto.createVerify('sha256').update(proof.msg).verify(
          { key: acc.keyPair.publicKeyPEM, format: 'pem' }, Buffer.from(proof.DeviceProof.Signature, 'base64'));
        selfTest = ok ? 'pass' : 'fail';
      } catch (e) { selfTest = 'error: ' + e.message; }
    }
    r.selfTest = selfTest;

    if (!JSON_OUT) {
      console.log('=== ' + acc.dir);
      console.log('  userId         :', acc.info.userId, '| 备注:', acc.info.account && acc.info.account.userTag);
      console.log('  API host       :', host);
      console.log('  x-device-id    :', acc.deviceId || '(未取到)');
      console.log('  MachineID      :', acc.machineId || '(未取到)');
      console.log('  ClientID       :', acc.clientId, '| IDEVersion:', acc.ideVersion, acc.appDir ? '(' + acc.appDir + ')' : '');
      console.log('  DeviceInfo 来源:', acc.devSource);
      console.log('  token 到期     :', fmt(acc.tokenExpiredAt), '→ 剩余', left(acc.tokenExpiredAt));
      console.log('  refresh 到期   :', fmt(acc.refreshExpiredAt), '→ 剩余', left(acc.refreshExpiredAt));
      console.log('  签名自检       :', selfTest || 'skipped');
      console.log('  判定           :', needRefresh ? '需要续期（剩余 ≤ 24h）' : '暂不需要续期（客户端也在剩余 ≤ 24h 时自动刷）');
      if (body) console.log('  请求预览       :', JSON.stringify(redact(body)).slice(0, 400) + ' …');
    }

    if ((LIVE || PROBE) && body) {
      if (!JSON_OUT) console.log('\n  → 发起 POST ' + host + EXCHANGE_PATH + (PROBE ? '  [探针：refreshToken 已篡改]' : ''));
      try {
        const res = await callExchange(host, acc, body, PROXY);
        const R = res.json && (res.json.Result || res.json.result);
        if (!JSON_OUT) {
          console.log('  ← HTTP ' + res.status);
          if (R && R.Token) {
            console.log('     DeviceBindStatus :', R.DeviceBindStatus);
            console.log('     BoundDeviceID    :', R.BoundDeviceID);
            console.log('     新 token 到期    :', fmt(R.TokenExpireAt), '(时长 ' + (R.TokenExpireDuration / 86400000) + ' 天)');
            console.log('     新 refresh 到期  :', fmt(R.RefreshExpireAt));
            const rotated = R.RefreshExpireAt !== acc.refreshExpiredAt;
            console.log('     refreshToken     :', (R.RefreshToken && R.RefreshToken !== acc.info.refreshToken) ? '已轮换 ⚠' : '未变化');
            console.log('     refreshExpireAt  :', rotated ? '已顺延 ⚠' : '未变化');
          } else {
            console.log('     原始响应:', res.text.slice(0, 700));
          }
        }
        r.rawResponse = res.text.slice(0, 700);
        if (PROBE) {
          r.probe = true;
          if (!JSON_OUT) console.log('  （探针不会改动任何本地文件）');
        } else if (!R || !R.Token) {
          r.error = '刷新失败: HTTP ' + res.status + ' ' + res.text.slice(0, 240);
        } else {
          r.refreshed = true;
          r.newTokenExpiredAt = R.TokenExpireAt;
          r.newRefreshExpiredAt = R.RefreshExpireAt;
          r.refreshTokenRotated = R.RefreshToken !== acc.info.refreshToken;
          r.newToken = R.Token;
          r.newRefreshToken = R.RefreshToken;

          if (WRITE_BACK) {
            if (traeRunning() && !FORCE) {
              r.error = 'Trae 正在运行，写回会导致会话错乱。请先完全退出 TRAE SOLO CN，或加 --force。';
              if (!JSON_OUT) console.log('  ! ' + r.error);
            } else {
              const bak = acc.storagePath + '.traebak-' + Date.now();
              fs.copyFileSync(acc.storagePath, bak);
              const newInfo = { ...acc.info,
                token: R.Token,
                refreshToken: R.RefreshToken,
                expiredAt: new Date(R.TokenExpireAt).toISOString(),
                refreshExpiredAt: new Date(R.RefreshExpireAt).toISOString(),
                tokenReleaseAt: new Date().toISOString(),
              };
              const fresh = JSON.parse(fs.readFileSync(acc.storagePath, 'utf8'));
              fresh[AUTH_KEY] = encrypt(JSON.stringify(newInfo));
              fs.writeFileSync(acc.storagePath, JSON.stringify(fresh, null, 4), 'utf8');
              // 回读校验
              const back = JSON.parse(decrypt(JSON.parse(fs.readFileSync(acc.storagePath, 'utf8'))[AUTH_KEY]));
              const okRead = back.token === R.Token && back.refreshToken === R.RefreshToken;
              r.wroteBack = okRead;
              r.backup = bak;
              if (!JSON_OUT) {
                console.log('  ✔ 已写回 ' + acc.storagePath);
                console.log('    备份: ' + bak);
                console.log('    回读校验: ' + (okRead ? 'pass' : 'FAIL'));
              }
              if (!okRead) r.error = '写回后回读校验失败，请用备份还原';
            }
          } else if (!JSON_OUT) {
            console.log('  （未加 --write-back，本地 storage.json 未改动）');
          }
        }
      } catch (e) {
        r.error = '请求异常: ' + e.message;
        if (!JSON_OUT) console.log('  ! ' + r.error);
      }
    }
    if (!JSON_OUT) console.log('');
    results.push(r);
  }

  if (JSON_OUT) {
    // 默认不输出明文 token，除非 --show-token
    const out = results.map((r) => {
      const c = { ...r };
      if (!has('--show-token')) { delete c.newToken; delete c.newRefreshToken; }
      else if (c.newToken) c.configLine = [c.newToken, c.deviceId, ''].join('#');
      return c;
    });
    console.log(JSON.stringify(out, null, 2));
  } else {
    const failed = results.filter((r) => r.error);
    if (failed.length) { console.error('有 ' + failed.length + ' 个账号处理失败。'); process.exitCode = 2; }
  }
})().catch((e) => { console.error('致命错误:', e.message); process.exitCode = 3; });
