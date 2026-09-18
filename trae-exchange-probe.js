#!/usr/bin/env node
/**
 * trae-exchange-probe.js —— TRAE SOLO CN 续期接口「单变量探测」诊断工具
 *
 * 用途：当 ExchangeToken 返回非预期错误码时，用它逐个改动单个变量，观察服务端
 *       返回码是否随之变化，从而判断「是请求构造错了」还是「服务端侧状态问题」。
 *
 * 原理：失败的回包不会消耗 refreshToken（只有成功才可能轮换），所以反复试探安全。
 *
 * 用法：
 *   node trae-exchange-probe.js                     # 基线：完全复刻客户端请求
 *   node trae-exchange-probe.js --matrix            # 跑一整组单变量，输出对照表（推荐）
 *   node trae-exchange-probe.js --broken-sig        # 签名损坏
 *   node trae-exchange-probe.js --fresh-key         # 换成新生成的 EC 密钥对
 *   node trae-exchange-probe.js --deviceid 123     # 改 DeviceID
 *   node trae-exchange-probe.js --machineid abc    # 改 MachineID
 *   node trae-exchange-probe.js --ide 0.1.65       # 改 IDEVersion + ClientVersion
 *   node trae-exchange-probe.js --host https://api.trae.com.cn
 *   node trae-exchange-probe.js --no-cloudide      # 不带 x-cloudide-token 头
 *   node trae-exchange-probe.js --device-headers   # 加 x-device-id/brand/type/os-version/app-version
 *   node trae-exchange-probe.js --chrome           # 伪装 Chromium 的 UA/Accept
 *   node trae-exchange-probe.js --empty-device     # DeviceInfo 置为 {}
 *   node trae-exchange-probe.js --no-proof         # 去掉 DeviceProof
 *   node trae-exchange-probe.js --client-id xxx    # 换 ClientID
 *   node trae-exchange-probe.js --proxy http://127.0.0.1:10808
 *
 * 已知返回码（2026-09 实测，Trae 0.1.67 / 账号 1430893319435833）：
 *   10101 Invalid client          ClientID 不对（校验在设备校验之前）
 *   20101 refresh token is invalid refreshToken 无效（篡改 token 时的预期结果）
 *   20405 Device proof required    缺 DeviceProof
 *   20403 Token device not match   refreshToken 有效但服务端绑定设备不匹配
 *                                  → 实测与请求内容完全无关，见 README / SKILL.md
 *
 * 零第三方依赖，只用 Node 内置模块。只读本地文件，不写任何东西。
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SM4_SBOX = [82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37];
const SM4_SBOX2 = [31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125];

function decrypt(v) {
  const b = Buffer.isBuffer(v) ? v : Buffer.from(v, 'base64');
  const key = b.slice(6, 38), ct = b.slice(38);
  const pad = Buffer.alloc(64);
  for (let i = 0; i < 64; i++) pad[i] = SM4_SBOX[i] ^ SM4_SBOX2[i];
  const der = crypto.createHash('sha512').update(Buffer.concat([
    crypto.createHash('sha512').update(key).digest(), pad])).digest();
  const d = crypto.createDecipheriv('aes-128-cbc', der.slice(0, 16), der.slice(16, 32));
  return Buffer.concat([d.update(ct), d.final()]).slice(64);
}

const APP = process.env.TRAE_DATA_DIR || path.join(process.env.APPDATA, 'TRAE SOLO CN');
const store = JSON.parse(fs.readFileSync(path.join(APP, 'User', 'globalStorage', 'storage.json'), 'utf8'));
const ak = Object.keys(store).find((k) => k.startsWith('iCubeAuthInfo://icube.cloudide'));
const dk = Object.keys(store).find((k) => k.startsWith('iCubeAuthInfo://icube-dc'));
if (!ak || !dk) { console.error('storage.json 里缺少 iCubeAuthInfo 键，先跑 get-trae-credentials.js'); process.exit(1); }
const info = JSON.parse(decrypt(store[ak]).toString('utf8'));
const keyPair = JSON.parse(decrypt(store[dk]).toString('utf8'));

// DeviceInfo 基线：从历史日志里还原真实请求体（最忠实）
function deviceInfoFromLogs() {
  const root = path.join(APP, 'logs');
  if (!fs.existsSync(root)) return null;
  const dirs = fs.readdirSync(root).filter((d) => /^\d{8}T\d{6}$/.test(d)).sort().reverse();
  for (const d of dirs) {
    const f = path.join(root, d, 'main.log');
    if (!fs.existsSync(f)) continue;
    const m = fs.readFileSync(f, 'utf8').match(/\[exchangeToken(?:ByRefreshToken|ByAuthCode)\] request \S+ (\{.*\})/);
    if (m) { try { return JSON.parse(m[1]).DeviceInfo; } catch { /* 继续找 */ } }
  }
  return null;
}
const devInfo = deviceInfoFromLogs();
if (!devInfo) { console.error('日志里找不到历史 ExchangeToken 请求，无法还原 DeviceInfo；请手动构造。'); process.exit(1); }

const args = process.argv.slice(2);
const val = (k, d = null) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const has = (k) => args.includes(k);

const EXCHANGE_PATH = '/trae/api/v3/oauth/ExchangeToken';
const CLIENT_ID = val('--client-id', 'en1oxy7wnw8j9n');
const IDE = val('--ide', null);
const HOST = (val('--host') || info.host || 'https://api.trae.cn').replace(/\/$/, '');
const PROXY = val('--proxy', '');

/** 单次探测，返回 {status, code, msg, result} */
async function probe(variant) {
  // IDEVersion 默认与 DeviceInfo.ClientVersion 保持一致（客户端就是这么做的）
  const ideVersion = variant.ide || IDE || '0.1.67';

  const useKey = variant.freshKey
    ? (() => { const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
        return { privateKeyPEM: kp.privateKey, publicKeyPEM: kp.publicKey }; })()
    : keyPair;

  const di = { ...devInfo, ClientVersion: ideVersion, DevicePublicKey: useKey.publicKeyPEM };
  if (variant.deviceId) di.DeviceID = variant.deviceId;
  if (variant.machineId) di.MachineID = variant.machineId;

  const clientId = variant.clientId || CLIENT_ID;
  const refreshToken = variant.tamper
    ? info.refreshToken.slice(0, -1) + (info.refreshToken.slice(-1) === 'A' ? 'B' : 'A')
    : info.refreshToken;

  const ts = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('hex');
  const msg = ['POST', EXCHANGE_PATH, clientId, refreshToken, String(ts), nonce].join(' ');
  let sig = crypto.createSign('sha256').update(msg).sign(useKey.privateKeyPEM).toString('base64');
  if (variant.brokenSig) sig = Buffer.from('not-a-signature').toString('base64');

  const body = { ClientID: clientId, ClientSecret: '', RefreshToken: refreshToken,
    DeviceInfo: variant.emptyDevice ? {} : di,
    DeviceProof: { Signature: sig, Timestamp: ts, Nonce: nonce }, IDEVersion: ideVersion };
  if (variant.noProof) delete body.DeviceProof;

  const headers = { 'Content-Type': 'application/json' };
  if (!variant.noCloudide) headers['x-cloudide-token'] = info.token;
  if (variant.deviceHeaders) Object.assign(headers, {
    'x-device-id': di.DeviceID, 'x-device-brand': di.DeviceModel,
    'x-device-type': di.OSInfo, 'x-os-version': di.OSVersion, 'x-app-version': ideVersion,
  });
  if (variant.chrome) Object.assign(headers, {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    Accept: 'application/json, text/plain, */*', 'Accept-Language': 'zh-CN,zh;q=0.9',
  });

  const opt = { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(25000) };
  if (PROXY) { try { opt.dispatcher = new (require('undici').ProxyAgent)(PROXY); } catch { /* 直连 */ } }
  try {
    const r = await fetch(HOST + EXCHANGE_PATH, opt);
    const t = await r.text();
    let j = null; try { j = JSON.parse(t); } catch { /* 原文 */ }
    const err = j && j.ResponseMetadata && j.ResponseMetadata.Error;
    return { status: r.status, code: err ? err.Code : (j && j.Result ? 'OK' : '?'),
      msg: err ? err.Message : '', result: j && j.Result, raw: t.slice(0, 200) };
  } catch (e) { return { status: 0, code: 'NET', msg: e.message }; }
}

const MATRIX = [
  ['基线（完全复刻客户端）', {}],
  ['签名损坏', { brokenSig: true }],
  ['换新 EC 密钥对', { freshKey: true }],
  ['DeviceID 换成 install_id', { deviceId: '304993413208299' }],
  ['DeviceID 换成 BoundDeviceID', { deviceId: 'xjryy0jo7or5ve' }],
  ['MachineID 改成乱值', { machineId: 'deadbeef' }],
  ['IDEVersion 回退 0.1.65', { ide: '0.1.65' }],
  ['host 换 api.trae.com.cn', { host: 'https://api.trae.com.cn' }],
  ['去掉 x-cloudide-token 头', { noCloudide: true }],
  ['补全套 x-device-* 头', { deviceHeaders: true }],
  ['伪装 Chromium UA', { chrome: true }],
  ['DeviceInfo 置空 {}', { emptyDevice: true }],
  ['去掉 DeviceProof', { noProof: true }],
  ['ClientID 换成 TRAE 的', { clientId: 'ono9krqynydwx5' }],
  ['刷新令牌篡改为无效', { tamper: true }],
];

(async () => {
  if (has('--matrix')) {
    console.log('变量对照表（host=' + HOST + '）\n');
    console.log('  ' + '变量'.padEnd(28) + 'HTTP  Code   说明');
    console.log('  ' + '-'.repeat(74));
    for (const [label, v] of MATRIX) {
      const r = await probe(v);
      console.log('  ' + label.padEnd(26) + ' ' + String(r.status).padEnd(6) + String(r.code).padEnd(8) + (r.msg || '').slice(0, 34));
    }
    console.log('\n判读：若除"刷新令牌篡改"外返回码全部一致，说明该判定与请求内容无关，属服务端状态问题。');
    return;
  }
  const single = {
    brokenSig: has('--broken-sig'), freshKey: has('--fresh-key'), emptyDevice: has('--empty-device'),
    noProof: has('--no-proof'), noCloudide: has('--no-cloudide'), chrome: has('--chrome'),
    deviceHeaders: has('--device-headers'), tamper: has('--tamper'),
    deviceId: val('--deviceid'), machineId: val('--machineid'),
    ide: val('--ide'), clientId: val('--client-id'),
    host: val('--host'),
  };
  const r = await probe(single);
  console.log('变体    :', args.join(' ') || '(基线：完全复刻客户端)');
  console.log('请求目标:', (single.host ? single.host.replace(/\/$/, '') : HOST) + EXCHANGE_PATH);
  console.log('返回    : HTTP ' + r.status + (r.code ? ' | Code ' + r.code : '') + (r.msg ? ' "' + r.msg + '"' : ''));
  if (r.result) console.log('Result  :', JSON.stringify(r.result).slice(0, 300));
  else console.log('原文    :', (r.raw || '').slice(0, 300));
})();
