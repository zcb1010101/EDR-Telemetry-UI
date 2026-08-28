'use strict';

const http = require('http');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { spawn, spawnSync, execFileSync } = require('child_process');
const crypto = require('crypto');
const readline = require('readline');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const WEB_ROOT = path.join(PROJECT_ROOT, 'web');
const SERVER_DIR = __dirname;
const WORK_DIR = path.join(SERVER_DIR, 'work');
const REQUEST_DIR = path.join(WORK_DIR, 'requests');
const IMPORT_DIR = path.join(PROJECT_ROOT, 'import');
const REPORT_DIR = path.join(PROJECT_ROOT, 'reports');
const RUNS_DIR = path.join(PROJECT_ROOT, 'runs');
const CONFIG_PATH = path.join(PROJECT_ROOT, 'config', 'project.json');
const CATALOG_PATH = path.join(PROJECT_ROOT, 'config', 'scenario-catalog.csv');
const THREAT_PATH = path.join(PROJECT_ROOT, 'config', 'threat-levels.json');
const RUN_SCRIPT = path.join(SERVER_DIR, 'scripts', 'run-suite.ps1');
const NORMALIZE_SCRIPT = path.join(SERVER_DIR, 'scripts', 'normalize.ps1');
const COMPARE_SCRIPT = path.join(SERVER_DIR, 'scripts', 'compare.ps1');
const PID_FILE = path.join(SERVER_DIR, 'server.pid');
const PORT_FILE = path.join(SERVER_DIR, 'server.port');

const DEFAULT_PORT = 8787;
const HOST = '127.0.0.1';
const MAX_JSON_BODY_BYTES = 16 * 1024 * 1024;
const MAX_UPLOAD_BYTES = 1024 * 1024 * 1024;
const MAX_RUN_LOG_LINES = 6000;
const REPORT_LIST_LIMIT = 100;

const portArg = process.argv.find((item) => item.startsWith('--port='));
const PORT = Number(portArg ? portArg.split('=')[1] : process.env.EDR_WEB_PORT || DEFAULT_PORT);

const DISABLED_SCENARIOS = new Map([
  ['win.edr_sysops.agent_start', 'EDR Agent 能力暂未实现，平台已置灰。'],
  ['win.edr_sysops.agent_stop', 'EDR Agent 能力暂未实现，平台已置灰。'],
  ['win.edr_sysops.agent_install', 'EDR Agent 能力暂未实现，平台已置灰。'],
  ['win.edr_sysops.agent_uninstall', 'EDR Agent 能力暂未实现，平台已置灰。'],
  ['win.edr_sysops.agent_keepalive', 'EDR Agent 能力暂未实现，平台已置灰。'],
  ['win.edr_sysops.agent_error', 'EDR Agent 能力暂未实现，平台已置灰。'],
  ['win.driver.load', '驱动能力暂未实现，平台已置灰。'],
  ['win.driver.modify', '驱动能力暂未实现，平台已置灰。'],
  ['win.driver.unload', '驱动能力暂未实现，平台已置灰。'],
  ['win.account.logoff', '账号登录/注销执行链路不可靠，平台已置灰。']
]);

const activeRuns = new Map();

function ensureDirs() {
  for (const dir of [WORK_DIR, REQUEST_DIR, IMPORT_DIR, REPORT_DIR, RUNS_DIR]) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function stripAnsi(value) {
  return String(value).replace(/\u001b\[[0-9;]*m/g, '');
}

function safeFileName(name, fallback) {
  const raw = String(name || '').replace(/\\/g, '/').split('/').pop() || fallback;
  const cleaned = raw.replace(/[<>:"|?*\u0000-\u001f]/g, '_').replace(/^\.+/, '').trim();
  return cleaned || fallback;
}

function isInside(child, parent) {
  const childFull = path.resolve(child);
  const parentFull = path.resolve(parent);
  return childFull === parentFull || childFull.startsWith(parentFull + path.sep);
}

function sendJson(res, status, data) {
  const body = Buffer.from(JSON.stringify(data), 'utf8');
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function sendError(res, status, message, extra = {}) {
  sendJson(res, status, { ok: false, error: message, ...extra });
}

function readJsonFile(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

async function readJsonBody(req, maxBytes = MAX_JSON_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let received = 0;
    req.on('data', (chunk) => {
      received += chunk.length;
      if (received > maxBytes) {
        reject(new Error('请求体过大，已拒绝处理。'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!chunks.length) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch (error) {
        reject(new Error('请求体不是有效 JSON。'));
      }
    });
    req.on('error', reject);
  });
}

async function streamUpload(req, destPath, maxBytes = MAX_UPLOAD_BYTES) {
  await fsp.mkdir(path.dirname(destPath), { recursive: true });
  return new Promise((resolve, reject) => {
    const output = fs.createWriteStream(destPath, { flags: 'w' });
    let received = 0;
    let settled = false;
    const cleanup = (message) => {
      if (settled) return;
      settled = true;
      output.destroy();
      fs.unlink(destPath, () => {});
      reject(new Error(message || '上传失败。'));
    };
    output.on('error', () => cleanup('写入上传文件失败。'));
    req.on('data', (chunk) => {
      received += chunk.length;
      if (received > maxBytes) {
        req.pause();
        cleanup('上传文件超过 1GB 限制。');
        return;
      }
      if (!output.write(chunk)) req.pause();
    });
    req.on('end', () => {
      if (settled) return;
      output.end(() => resolve({ path: destPath, size: received }));
    });
    req.on('error', () => cleanup('读取上传请求失败。'));
    output.on('drain', () => req.resume());
  });
}

function parseCsv(text) {
  const rows = [];
  const lines = String(text).replace(/^\uFEFF/, '').split(/\r?\n/).filter((line) => line.trim());
  if (!lines.length) return rows;
  const headers = lines.shift().split(',').map((item) => item.trim());
  for (const line of lines) {
    const values = line.split(',').map((item) => item.trim());
    const row = {};
    headers.forEach((header, index) => {
      row[header] = values[index] === undefined ? '' : values[index];
    });
    rows.push(row);
  }
  return rows;
}

async function loadCatalog() {
  const [csvText, config, threatLevels] = await Promise.all([
    fsp.readFile(CATALOG_PATH, 'utf8'),
    fsp.readFile(CONFIG_PATH, 'utf8'),
    fsp.readFile(THREAT_PATH, 'utf8')
  ]);
  const rows = parseCsv(csvText);
  const configJson = JSON.parse(config.replace(/^\uFEFF/, ''));
  const threatJson = JSON.parse(threatLevels.replace(/^\uFEFF/, ''));
  const scenarios = rows.map((row) => {
    const disabled = DISABLED_SCENARIOS.get(row.ScenarioId);
    return {
      category: row.Category,
      categoryFolder: row.CategoryFolder,
      scenarioId: row.ScenarioId,
      scenarioName: row.ScenarioName,
      behaviorKind: row.BehaviorKind,
      threatLevel: row.ThreatLevel,
      requiresAdmin: String(row.RequiresAdmin).toLowerCase() === 'true',
      operation: row.Operation,
      available: !disabled,
      disabledReason: disabled || null
    };
  });
  const categories = [];
  const seen = new Set();
  for (const scenario of scenarios) {
    if (seen.has(scenario.category)) continue;
    seen.add(scenario.category);
    categories.push({
      name: scenario.category,
      folder: scenario.categoryFolder,
      total: scenarios.filter((item) => item.category === scenario.category).length,
      available: scenarios.filter((item) => item.category === scenario.category && item.available).length
    });
  }
  return {
    scenarios,
    categories,
    total: scenarios.length,
    available: scenarios.filter((item) => item.available).length,
    disabled: scenarios.filter((item) => !item.available).length,
    config: configJson,
    threatLevels: threatJson,
    isAdmin: isAdminSync()
  };
}

function isAdminSync() {
  try {
    const command = "[bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)";
    const output = execFileSync('powershell.exe', ['-NoProfile', '-Command', command], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 10000
    });
    return output.trim().toLowerCase() === 'true';
  } catch (_error) {
    return false;
  }
}

function commandAvailable(command, args = ['--version']) {
  const result = spawnSync(command, args, { windowsHide: true, encoding: 'utf8', timeout: 10000 });
  return result.status === 0;
}

function healthPayload() {
  let powershellVersion = '';
  let pythonVersion = '';
  try {
    powershellVersion = execFileSync('powershell.exe', ['-NoProfile', '-Command', '$PSVersionTable.PSVersion.ToString()'], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 10000
    }).trim();
  } catch (_error) {
    powershellVersion = '不可用';
  }
  try {
    pythonVersion = execFileSync('python', ['--version'], { encoding: 'utf8', windowsHide: true, timeout: 10000 }).trim();
  } catch (_error) {
    pythonVersion = '不可用';
  }
  return {
    ok: true,
    projectRoot: PROJECT_ROOT,
    webRoot: WEB_ROOT,
    port: PORT,
    isAdmin: isAdminSync(),
    node: process.version,
    powershell: powershellVersion,
    python: pythonVersion,
    startedAt: new Date().toISOString()
  };
}

function writeRequestFile(prefix, data) {
  const id = crypto.randomUUID();
  const filePath = path.join(REQUEST_DIR, `${prefix}-${id}.json`);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
  return filePath;
}

function spawnPowerShell(scriptPath, args = [], options = {}) {
  return spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', scriptPath, ...args], {
    cwd: PROJECT_ROOT,
    windowsHide: true,
    env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
    ...options
  });
}

function runPowerShell(scriptPath, args = [], timeoutMs = 0) {
  return new Promise((resolve, reject) => {
    const child = spawnPowerShell(scriptPath, args);
    let stdout = '';
    let stderr = '';
    let settled = false;
    const timer = timeoutMs > 0 ? setTimeout(() => {
      if (settled) return;
      settled = true;
      killProcessTree(child.pid);
      reject(new Error(`操作超过 ${Math.round(timeoutMs / 1000)} 秒，已终止。`));
    }, timeoutMs) : null;
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

function killProcessTree(pid) {
  if (!pid) return;
  try {
    spawnSync('taskkill.exe', ['/PID', String(pid), '/T', '/F'], {
      windowsHide: true,
      encoding: 'utf8',
      timeout: 15000
    });
  } catch (_error) {
    try {
      const child = activeRuns.get(pid);
      if (child) child.kill('SIGKILL');
    } catch (_ignored) {}
  }
}

function pathForRequestPath(prefix) {
  return path.join(REQUEST_DIR, `${prefix}-${crypto.randomUUID()}.json`);
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function serveStatic(req, res, pathname) {
  let relative = pathname === '/' ? 'index.html' : decodeURIComponent(pathname).replace(/^\/+/, '');
  const target = path.resolve(WEB_ROOT, relative);
  if (!isInside(target, WEB_ROOT)) {
    sendError(res, 403, '禁止访问该路径。');
    return;
  }
  fs.readFile(target, (error, data) => {
    if (error) {
      if (error.code === 'ENOENT') {
        sendError(res, 404, '页面或静态资源不存在。');
        return;
      }
      sendError(res, 500, '读取静态资源失败。');
      return;
    }
    const ext = path.extname(target).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}async function validateLocalLog(filePath) {
  const stat = await fsp.stat(filePath);
  if (stat.size === 0) throw new Error('本地日志为空文件，请重新选择。');
  const first = Buffer.alloc(8192);
  const handle = await fsp.open(filePath, 'r');
  const { bytesRead } = await handle.read(first, 0, first.length, 0);
  await handle.close();
  const head = first.slice(0, bytesRead).toString('utf8').replace(/^\uFEFF/, '').trimStart();
  if (head.startsWith('[')) {
    throw new Error('本地运行日志应使用 JSONL（events.jsonl）格式。');
  }
  let validCount = 0;
  const input = fs.createReadStream(filePath, { encoding: 'utf8', highWaterMark: 64 * 1024 });
  const rl = readline.createInterface({ input, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    try {
      JSON.parse(line.replace(/^\uFEFF/, ''));
      validCount += 1;
    } catch (_error) {
      throw new Error(`本地日志第 ${validCount + 1} 条记录不是有效 JSON。`);
    }
    if (validCount >= 300) break;
  }
  if (validCount === 0) throw new Error('本地日志中没有可识别的 JSONL 记录。');
  return { validCount, size: stat.size };
}

async function validateVendorLog(filePath) {
  const stat = await fsp.stat(filePath);
  if (stat.size === 0) throw new Error('厂商日志为空文件，请重新选择。');
  const first = Buffer.alloc(8192);
  const handle = await fsp.open(filePath, 'r');
  const { bytesRead } = await handle.read(first, 0, first.length, 0);
  await handle.close();
  const head = first.slice(0, bytesRead).toString('utf8').replace(/^\uFEFF/, '').trimStart();
  if (head.startsWith('[')) {
    if (stat.size <= 64 * 1024 * 1024) {
      const parsed = JSON.parse(await fsp.readFile(filePath, 'utf8'));
      if (!Array.isArray(parsed) || parsed.length === 0) throw new Error('厂商日志 JSON 数组为空或格式异常。');
    }
    return { format: 'json-array', size: stat.size };
  }
  if (head.startsWith('{')) {
    let validCount = 0;
    const input = fs.createReadStream(filePath, { encoding: 'utf8', highWaterMark: 64 * 1024 });
    const rl = readline.createInterface({ input, crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line.trim()) continue;
      try {
        JSON.parse(line.replace(/^\uFEFF/, ''));
        validCount += 1;
      } catch (_error) {
        throw new Error(`厂商日志第 ${validCount + 1} 条记录不是有效 JSON。`);
      }
      if (validCount >= 500) break;
    }
    if (validCount === 0) throw new Error('厂商日志中没有可识别的 JSONL 记录。');
    return { format: 'jsonl', size: stat.size };
  }
  throw new Error('厂商日志不是有效的 JSON 数组或 JSONL 格式。');
}

async function handleLocalUpload(req, res, url) {
  const rawName = url.searchParams.get('name') || 'local.jsonl';
  const fileName = safeFileName(rawName, 'local.jsonl');
  const stamp = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14);
  const destPath = path.join(IMPORT_DIR, `local-${stamp}-${fileName}`);
  await streamUpload(req, destPath);
  try {
    const validation = await validateLocalLog(destPath);
    sendJson(res, 200, {
      ok: true,
      path: destPath,
      name: fileName,
      size: validation.size,
      format: 'jsonl',
      message: '本地日志已导入并通过基础校验。'
    });
  } catch (error) {
    fs.unlink(destPath, () => {});
    sendError(res, 400, error.message);
  }
}

async function handleVendorUpload(req, res, url) {
  const rawName = url.searchParams.get('name') || 'vendor.json';
  const fileName = safeFileName(rawName, 'vendor.json');
  const vendorId = (url.searchParams.get('vendorId') || 'tencent').toLowerCase();
  const normalize = url.searchParams.get('normalize') === 'true';
  const stamp = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14);
  const baseName = `${vendorId}-${stamp}-${fileName}`;
  const destPath = path.join(IMPORT_DIR, baseName);
  await streamUpload(req, destPath);
  try {
    const validation = await validateVendorLog(destPath);
    let normalizedPath = null;
    if (normalize) {
      const outputPath = path.join(IMPORT_DIR, `${path.parse(baseName).name}.normalized.json`);
      const requestPath = writeRequestFile('normalize', { inputPath: destPath, vendorId, outputPath });
      await runPowerShell(NORMALIZE_SCRIPT, ['-RequestPath', requestPath], 10 * 60 * 1000);
      normalizedPath = outputPath;
    }
    sendJson(res, 200, {
      ok: true,
      path: destPath,
      normalizedPath,
      vendorId,
      name: fileName,
      size: validation.size,
      format: validation.format,
      message: normalize ? '厂商日志已导入并完成标准化。' : '厂商日志已导入并通过基础校验。'
    });
  } catch (error) {
    fs.unlink(destPath, () => {});
    sendError(res, 400, error.message);
  }
}

async function handleCompare(req, res) {
  const body = await readJsonBody(req);
  const localLogPath = path.resolve(body.localLogPath || '');
  const cloudPaths = Array.isArray(body.cloudPaths) ? body.cloudPaths.map((item) => path.resolve(item)) : [];
  const vendorId = String(body.vendorId || 'tencent').toLowerCase();
  if (!localLogPath || !isInside(localLogPath, PROJECT_ROOT)) throw new Error('本地日志路径无效。');
  if (!cloudPaths.length || cloudPaths.some((item) => !isInside(item, PROJECT_ROOT))) throw new Error('厂商日志路径无效。');
  for (const filePath of [localLogPath, ...cloudPaths]) {
    const stat = await fsp.stat(filePath);
    if (!stat.isFile()) throw new Error(`日志路径不是文件：${filePath}`);
  }
  const stamp = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14);
  const outputPath = body.outputPath ? path.resolve(body.outputPath) : path.join(REPORT_DIR, `validation-result-${stamp}.json`);
  if (!isInside(outputPath, PROJECT_ROOT)) throw new Error('结果输出路径无效。');
  const requestPath = writeRequestFile('compare', {
    localLogPath,
    cloudPaths,
    vendorId,
    outputPath,
    baselineDirectory: body.baselineDirectory || '',
    cloudManifest: body.cloudManifest || '',
    strongCorrelationTimeMs: Number(body.strongCorrelationTimeMs || 0),
    candidateTimeLimitMs: Number(body.candidateTimeLimitMs || 0)
  });
  const runResult = await runPowerShell(COMPARE_SCRIPT, ['-RequestPath', requestPath], 30 * 60 * 1000);
  if (runResult.code !== 0) {
    const detail = (runResult.stderr || runResult.stdout || '').trim();
    throw new Error(`日志对比失败（退出码 ${runResult.code}）：${detail}`);
  }
  const result = readJsonFile(outputPath);
  const conclusionPath = outputPath.replace(/\.json$/i, '-conclusion.md');
  let conclusionMarkdown = '';
  if (fs.existsSync(conclusionPath)) conclusionMarkdown = await fsp.readFile(conclusionPath, 'utf8');
  sendJson(res, 200, {
    ok: true,
    outputPath,
    conclusionPath,
    result,
    conclusionMarkdown
  });
}

async function listReportFiles() {
  const results = [];
  async function walk(dir) {
    let entries;
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch (_error) {
      return;
    }
    for (const entry of entries) {
      if (results.length >= REPORT_LIST_LIMIT) return;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
      } else if (entry.isFile() && /\.json$/i.test(entry.name)) {
        let stat;
        try {
          stat = await fsp.stat(full);
        } catch (_error) {
          continue;
        }
        results.push({
          path: full,
          name: entry.name,
          size: stat.size,
          modifiedAt: stat.mtime.toISOString()
        });
      }
    }
  }
  await walk(REPORT_DIR);
  results.sort((a, b) => new Date(b.modifiedAt) - new Date(a.modifiedAt));
  return results.slice(0, REPORT_LIST_LIMIT);
}

async function handleReportContent(req, res, url) {
  const rawPath = url.searchParams.get('path');
  if (!rawPath) throw new Error('缺少结果文件路径。');
  const filePath = path.resolve(rawPath);
  if (!isInside(filePath, REPORT_DIR)) throw new Error('结果文件必须在 reports 目录内。');
  const result = readJsonFile(filePath);
  const conclusionPath = filePath.replace(/\.json$/i, '-conclusion.md');
  let conclusionMarkdown = '';
  if (fs.existsSync(conclusionPath)) conclusionMarkdown = await fsp.readFile(conclusionPath, 'utf8');
  sendJson(res, 200, { ok: true, path: filePath, result, conclusionMarkdown });
}

async function handleReportImport(req, res, url) {
  const rawName = url.searchParams.get('name') || 'validation-result.json';
  const fileName = safeFileName(rawName, 'validation-result.json');
  const stamp = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14);
  const destPath = path.join(REPORT_DIR, `imported-${stamp}-${fileName}`);
  await streamUpload(req, destPath, 512 * 1024 * 1024);
  try {
    const result = readJsonFile(destPath);
    if (!result || !result.summary || !result.conclusion || !Array.isArray(result.capabilities)) {
      throw new Error('文件结构不是有效的 EDR 比对结果。');
    }
    sendJson(res, 200, { ok: true, path: destPath, result });
  } catch (error) {
    fs.unlink(destPath, () => {});
    sendError(res, 400, error.message);
  }
}

function activeRun() {
  for (const run of activeRuns.values()) {
    if (run.status === 'running') return run;
  }
  return null;
}

async function handleStartRun(req, res) {
  const body = await readJsonBody(req);
  const mode = String(body.mode || 'single');
  if (!['single', 'category', 'all', 'batch'].includes(mode)) throw new Error('不支持的运行模式。');
  if (activeRun()) throw new Error('已有场景批次正在运行，请等待完成或先停止。');
  const catalog = await loadCatalog();
  const intervalSeconds = Math.max(0, Math.min(300, Number(body.intervalSeconds ?? catalog.config.default_interval_seconds)));
  let scenarioIds = [];
  let categories = [];
  if (mode === 'all') {
    scenarioIds = catalog.scenarios.filter((item) => item.available).map((item) => item.scenarioId);
  } else if (mode === 'category') {
    categories = Array.isArray(body.categories) ? body.categories.map(String) : [];
    if (!categories.length) throw new Error('请至少选择一个场景分类。');
  } else {
    scenarioIds = Array.isArray(body.scenarioIds) ? body.scenarioIds.map(String) : [];
    if (!scenarioIds.length) throw new Error('请至少选择一个可运行场景。');
  }
  for (const id of scenarioIds) {
    const scenario = catalog.scenarios.find((item) => item.scenarioId === id);
    if (!scenario) throw new Error(`未知场景：${id}`);
    if (!scenario.available) throw new Error(`场景 ${scenario.scenarioName} 暂未开放，不能运行。`);
  }
  const runId = crypto.randomUUID();
  const dateDir = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const outputLog = path.join(RUNS_DIR, dateDir, runId, 'events.jsonl');
  const summaryPath = outputLog.replace(/events\.jsonl$/i, 'suite-summary.json');
  const requestBody = {
    mode,
    scenarioIds,
    categories,
    runId,
    outputLog,
    intervalSeconds,
    skipCleanup: Boolean(body.skipCleanup),
    stopOnFailure: Boolean(body.stopOnFailure),
    threatLevel: body.threatLevel || '',
    serviceName: body.serviceName || '',
    usbWaitSeconds: Number(body.usbWaitSeconds || 0),
    confirmManual: Boolean(body.confirmManual)
  };
  const requestPath = writeRequestFile(`run-${runId}`, requestBody);
  const child = spawnPowerShell(RUN_SCRIPT, ['-RequestPath', requestPath]);
  const run = {
    id: runId,
    status: 'running',
    process: child,
    logs: [],
    clients: new Set(),
    outputLog,
    summaryPath,
    startedAt: new Date().toISOString(),
    endedAt: null,
    summary: null,
    cancelRequested: false,
    remainder: ''
  };
  activeRuns.set(runId, run);
  attachRunProcess(run);
  sendJson(res, 201, {
    ok: true,
    runId,
    status: 'running',
    outputLog,
    summaryPath,
    selectedCount: mode === 'category' ? catalog.scenarios.filter((item) => categories.includes(item.category)).length : scenarioIds.length
  });
}

function appendRunLog(run, chunk, streamName = 'stdout') {
  const clean = stripAnsi(chunk).replace(/\r\n/g, '\n');
  const combined = run.remainder + clean;
  const parts = combined.split('\n');
  run.remainder = parts.pop() || '';
  for (const line of parts) {
    if (!line.trim()) continue;
    const entry = {
      time: new Date().toISOString(),
      stream: streamName,
      message: line.trim()
    };
    run.logs.push(entry);
    if (run.logs.length > MAX_RUN_LOG_LINES) run.logs.shift();
    for (const send of run.clients) {
      try {
        send('logs', { lines: [entry] });
      } catch (_error) {}
    }
  }
}

function flushRunLog(run) {
  if (!run.remainder.trim()) return;
  const entry = {
    time: new Date().toISOString(),
    stream: 'stdout',
    message: run.remainder.trim()
  };
  run.logs.push(entry);
  run.remainder = '';
  for (const send of run.clients) {
    try {
      send('logs', { lines: [entry] });
    } catch (_error) {}
  }
}

function attachRunProcess(run) {
  run.process.stdout.setEncoding('utf8');
  run.process.stderr.setEncoding('utf8');
  run.process.stdout.on('data', (chunk) => appendRunLog(run, chunk, 'stdout'));
  run.process.stderr.on('data', (chunk) => appendRunLog(run, chunk, 'stderr'));
  run.process.on('error', (error) => {
    appendRunLog(run, `后端启动 PowerShell 失败：${error.message}`, 'stderr');
  });
  run.process.on('close', (code) => {
    flushRunLog(run);
    let summary = null;
    try {
      summary = readJsonFile(run.summaryPath);
    } catch (_error) {
      summary = null;
    }
    if (run.cancelRequested) {
      run.status = 'cancelled';
    } else if (code === 0 && summary) {
      run.status = 'completed';
    } else {
      run.status = 'failed';
    }
    run.summary = summary;
    run.endedAt = new Date().toISOString();
    for (const send of run.clients) {
      try {
        send('done', { status: run.status, summary });
      } catch (_error) {}
    }
  });
}

function handleRunStatus(res, run) {
  sendJson(res, 200, {
    ok: true,
    id: run.id,
    status: run.status,
    outputLog: run.outputLog,
    summaryPath: run.summaryPath,
    summary: run.summary,
    startedAt: run.startedAt,
    endedAt: run.endedAt,
    logs: run.logs.slice(-500)
  });
}

function handleRunCancel(res, run) {
  if (run.status !== 'running') {
    sendJson(res, 200, { ok: true, status: run.status, message: '该批次已经结束。' });
    return;
  }
  run.cancelRequested = true;
  killProcessTree(run.process.pid);
  sendJson(res, 202, { ok: true, status: 'cancelling', message: '已发送停止指令。' });
}

function handleRunEvents(req, res, run) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.write('retry: 2000\n\n');
  const send = (type, payload) => {
    if (res.writableEnded) return;
    res.write(`data: ${JSON.stringify({ type, ...payload })}\n\n`);
  };
  send('history', { lines: run.logs.slice(-1000), status: run.status });
  run.clients.add(send);
  const heartbeat = setInterval(() => {
    try {
      res.write(': heartbeat\n\n');
    } catch (_error) {
      clearInterval(heartbeat);
    }
  }, 15000);
  req.on('close', () => {
    clearInterval(heartbeat);
    run.clients.delete(send);
  });
}

async function handleRecentRuns(req, res) {
  const summaries = [];
  async function walk(dir, depth = 0) {
    if (depth > 4) return;
    let entries;
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch (_error) {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full, depth + 1);
      } else if (entry.name.toLowerCase() === 'suite-summary.json') {
        try {
          const stat = await fsp.stat(full);
          const summary = readJsonFile(full);
          summaries.push({
            runId: summary.run_id,
            startedAt: summary.started_at_utc,
            endedAt: summary.ended_at_utc,
            total: summary.total,
            completed: summary.completed,
            skipped: summary.skipped,
            failed: summary.failed,
            aborted: summary.aborted,
            outputLog: summary.output_log,
            summaryPath: full,
            modifiedAt: stat.mtime.toISOString()
          });
        } catch (_error) {
          continue;
        }
      }
    }
  }
  await walk(RUNS_DIR);
  summaries.sort((a, b) => new Date(b.modifiedAt) - new Date(a.modifiedAt));
  sendJson(res, 200, { ok: true, runs: summaries.slice(0, 30) });
}async function handleApi(req, res, url) {
  const method = req.method || 'GET';
  const pathname = url.pathname.replace(/\/+$/, '') || '/';
  if (method === 'GET' && pathname === '/api/health') {
    sendJson(res, 200, healthPayload());
    return;
  }
  if (method === 'GET' && pathname === '/api/catalog') {
    sendJson(res, 200, { ok: true, ...(await loadCatalog()) });
    return;
  }
  if (method === 'GET' && pathname === '/api/runs/recent') {
    await handleRecentRuns(req, res);
    return;
  }
  if (method === 'GET' && pathname === '/api/reports') {
    sendJson(res, 200, { ok: true, reports: await listReportFiles() });
    return;
  }
  if (method === 'GET' && pathname === '/api/report/content') {
    await handleReportContent(req, res, url);
    return;
  }
  if (method === 'POST' && pathname === '/api/report/import') {
    await handleReportImport(req, res, url);
    return;
  }
  if (method === 'POST' && pathname === '/api/import/local') {
    await handleLocalUpload(req, res, url);
    return;
  }
  if (method === 'POST' && pathname === '/api/import/vendor') {
    await handleVendorUpload(req, res, url);
    return;
  }
  if (method === 'POST' && pathname === '/api/compare') {
    await handleCompare(req, res);
    return;
  }
  if (method === 'POST' && pathname === '/api/run') {
    await handleStartRun(req, res);
    return;
  }
  if (method === 'POST' && pathname === '/api/run/cancel') {
    const id = url.searchParams.get('id');
    const run = activeRuns.get(id);
    if (!run) {
      sendError(res, 404, '没有找到该运行批次。');
      return;
    }
    handleRunCancel(res, run);
    return;
  }
  const runEventMatch = pathname.match(/^\/api\/run\/([^/]+)\/events$/);
  if (method === 'GET' && runEventMatch) {
    const run = activeRuns.get(runEventMatch[1]);
    if (!run) {
      sendError(res, 404, '没有找到该运行批次。');
      return;
    }
    handleRunEvents(req, res, run);
    return;
  }
  const runMatch = pathname.match(/^\/api\/run\/([^/]+)$/);
  if (method === 'GET' && runMatch) {
    const run = activeRuns.get(runMatch[1]);
    if (!run) {
      sendError(res, 404, '没有找到该运行批次。');
      return;
    }
    handleRunStatus(res, run);
    return;
  }
  sendError(res, 404, '接口不存在。');
}

async function requestHandler(req, res) {
  const url = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);
  try {
    if (url.pathname.startsWith('/api/')) {
      await handleApi(req, res, url);
      return;
    }
    if (methodAllowsFile(req)) {
      serveStatic(req, res, url.pathname);
      return;
    }
    sendError(res, 405, '该接口不支持当前请求方法。');
  } catch (error) {
    const message = error && error.message ? error.message : String(error);
    if (!res.headersSent) sendError(res, 400, message);
    else res.end();
  }
}

function methodAllowsFile(req) {
  const method = req.method || 'GET';
  return method === 'GET' || method === 'HEAD';
}

function shutdown(signal) {
  for (const run of activeRuns.values()) {
    if (run.status === 'running') killProcessTree(run.process.pid);
  }
  fs.writeFileSync(PORT_FILE, String(PORT), 'utf8');
  try {
    fs.unlinkSync(PID_FILE);
  } catch (_error) {}
  process.exit(0);
}

ensureDirs();
const server = http.createServer(requestHandler);
server.listen(PORT, HOST, () => {
  fs.writeFileSync(PID_FILE, String(process.pid), 'utf8');
  fs.writeFileSync(PORT_FILE, String(PORT), 'utf8');
  console.log(`EDR Web platform started at http://${HOST}:${PORT}`);
  console.log(`Project root: ${PROJECT_ROOT}`);
});
server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`端口 ${PORT} 已被占用，请先运行停止脚本或更换端口。`);
    process.exit(1);
  }
  console.error(error && error.message ? error.message : error);
  process.exit(1);
});
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));