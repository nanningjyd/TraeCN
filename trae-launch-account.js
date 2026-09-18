#!/usr/bin/env node
/**
 * trae-launch-account.js
 * ------------------------------------------------------------------
 * 用独立的 user-data-dir 启动 TRAE SOLO CN，实现"一号一目录"。
 *
 * 为什么必须用 --user-data-dir：
 *   Trae 的登录态存在 <userData>/User/globalStorage/storage.json，键名固定为
 *   iCubeAuthInfo://icube.cloudide —— 换账号即覆盖，且该路径 **不随 VS Code
 *   profile 变化**，所以 `--profile` 无法隔离账号，只有换 userData 根目录才行。
 *   Electron 的 IPC 句柄由 user-data-dir 派生，因此不同目录可同时运行多个实例。
 *
 * 用法：
 *   node trae-launch-account.js --dir D:\trae-acc2
 *   node trae-launch-account.js --dir D:\trae-acc2 --exe "D:\Program Files\TRAE SOLO CN\TRAE SOLO CN.exe"
 *
 * 启动后在该窗口登录第二个账号，然后用：
 *   node get-trae-credentials.js --dir D:\trae-acc2
 * 即可取出该账号的 TOKEN 与 x-device-id。
 *
 * 注意：首次用新目录启动时，设备号（aha/TinyStorage）会重新生成，
 *       因此各账号会拿到 **不同** 的 x-device-id，符合 worker 的防关联建议。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const argv = process.argv.slice(2);
const arg = (name, def) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : def;
};

const DEFAULT_EXE = 'D:\\Program Files\\TRAE SOLO CN\\TRAE SOLO CN.exe';
const exe = arg('--exe', process.env.TRAE_EXE || DEFAULT_EXE);
const dir = arg('--dir', null);

if (!dir) {
  console.error('用法: node trae-launch-account.js --dir <该账号专用的数据目录>');
  console.error('例如: node trae-launch-account.js --dir D:\\trae-acc2');
  process.exit(1);
}
if (!fs.existsSync(exe)) {
  console.error('找不到主程序: ' + exe + '\n用 --exe 指定路径。');
  process.exit(1);
}

const abs = path.resolve(dir);
fs.mkdirSync(abs, { recursive: true });

console.error('主程序   : ' + exe);
console.error('数据目录 : ' + abs + '  (与主账号完全隔离)');
console.error('登录完成后执行: node get-trae-credentials.js --dir "' + abs + '"');
console.error('');

const child = spawn(exe, ['--user-data-dir', abs], {
  detached: true,
  stdio: 'ignore',
  windowsHide: false,
});
child.unref();
console.error('已启动 (pid ' + child.pid + ')');
