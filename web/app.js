'use strict';

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const state = {
  catalog: null,
  mode: 'single',
  selectedScenario: null,
  selectedCategories: new Set(),
  isAdmin: false,
  running: false,
  runId: null,
  eventSource: null,
  progress: { total: 0, completed: 0, succeeded: 0, current: 0, running: false },
  runScenarioIds: [],
  scenarioRunState: new Map(),
  currentScenarioId: null,
  localFile: null,
  vendorFile: null,
  localUpload: null,
  vendorUpload: null,
  compareLoading: false,
  result: null,
  conclusionMarkdown: ''
};

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const contentType = response.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await response.json() : await response.text();
  if (!response.ok) {
    const message = data && data.error ? data.error : `请求失败（${response.status}）`;
    throw new Error(message);
  }
  return data;
}

async function uploadBinary(path, file) {
  const response = await fetch(path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-File-Name': encodeURIComponent(file.name),
      'X-File-Size': String(file.size)
    },
    body: file
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || '文件上传失败。');
  return data;
}

function showToast(message, type = '') {
  const toast = $('#toast');
  toast.textContent = message;
  toast.className = `toast show ${type}`;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove('show'), 2600);
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / Math.pow(1024, index)).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[char]);
}

function scenarioStatus(scenario) {
  if (!scenario.available) return 'disabled';
  if (scenario.requiresAdmin && !state.isAdmin) return 'permission';
  return 'ready';
}

function updateAdminBadge() {
  const badge = $('#adminBadge');
  if (state.catalog === null) {
    badge.textContent = '权限检测中';
    badge.className = 'badge admin-badge';
    return;
  }
  badge.textContent = state.isAdmin ? '管理员权限' : '普通用户权限';
  badge.className = `badge admin-badge${state.isAdmin ? ' is-admin' : ''}`;
}

async function loadHealth() {
  try {
    const health = await api('/api/health');
    $('#serverDot').className = 'server-dot online';
    $('#serverDetail').textContent = `127.0.0.1:${health.port}`;
    state.isAdmin = health.isAdmin;
    updateAdminBadge();
  } catch (_error) {
    $('#serverDot').className = 'server-dot offline';
    $('#serverDetail').textContent = '服务不可用';
    updateAdminBadge();
  }
}

async function loadCatalog() {
  try {
    const data = await api('/api/catalog');
    state.catalog = data;
    state.isAdmin = data.isAdmin;
    fillCategoryFilter();
    updateAdminBadge();
    renderScenarioArea();
    updateStats();
  } catch (error) {
    showToast(error.message, 'error');
    $('#scenarioArea').innerHTML = `<div class="empty-state">无法加载场景目录：${escapeHtml(error.message)}</div>`;
  }
}

function fillCategoryFilter() {
  const select = $('#categoryFilter');
  const current = select.value;
  select.innerHTML = '<option value="">全部分类</option>';
  for (const category of state.catalog.categories) {
    const option = document.createElement('option');
    option.value = category.name;
    option.textContent = `${category.name}（${category.available} 项可运行）`;
    select.appendChild(option);
  }
  select.value = current;
}

function filteredScenarios() {
  const keyword = $('#scenarioSearch').value.trim().toLowerCase();
  const threat = $('#threatFilter').value;
  const category = $('#categoryFilter').value;
  return state.catalog.scenarios.filter((scenario) => {
    if (threat && scenario.threatLevel !== threat) return false;
    if (category && scenario.category !== category) return false;
    if (keyword && !`${scenario.scenarioName} ${scenario.scenarioId} ${scenario.operation}`.toLowerCase().includes(keyword)) return false;
    return true;
  });
}

function threatClass(level) {
  return String(level).toLowerCase();
}

function scenarioRunStatus(scenario) {
  if (!scenario.available) return 'unavailable';
  return state.scenarioRunState.get(scenario.scenarioId) || 'pending';
}

function runStateLabel(status) {
  return {
    pending: '待检测',
    running: '测试中',
    done: '已测试',
    failed: '失败',
    skipped: '跳过',
    unavailable: '暂未开放'
  }[status] || '待检测';
}

function scenarioFlagsHtml(scenario) {
  const runStatus = scenarioRunStatus(scenario);
  const adminTag = scenario.requiresAdmin ? '<span class="tag admin">需管理员</span>' : '<span class="tag">普通权限</span>';
  return `<div class="scenario-flags">${adminTag}<span class="scenario-run-state ${runStatus}">${runStateLabel(runStatus)}</span></div>`;
}

function scenarioIdentityHtml(scenario, reason = '') {
  return `<div class="scenario-id">${escapeHtml(scenario.scenarioId)}</div><div class="scenario-name">${escapeHtml(scenario.scenarioName)}${reason}</div>`;
}

function renderSingleArea() {
  const area = $('#scenarioArea');
  const scenarios = filteredScenarios();
  $('#visibleScenarioCount').textContent = `显示 ${scenarios.length} / ${state.catalog.total} 项`;
  const groups = new Map();
  for (const scenario of scenarios) {
    if (!groups.has(scenario.category)) groups.set(scenario.category, []);
    groups.get(scenario.category).push(scenario);
  }
  if (!scenarios.length) {
    area.innerHTML = '<div class="empty-state">没有符合条件的场景</div>';
    return;
  }
  const html = [];
  for (const [category, items] of groups.entries()) {
    html.push('<div class="category-group">');
    html.push(`<div class="category-title"><span>${escapeHtml(category)}</span><span class="muted">${items.length} 项</span></div>`);
    html.push('<div class="scenario-list">');
    for (const scenario of items) {
      const status = scenarioStatus(scenario);
      const disabled = status !== 'ready';
      const selected = state.selectedScenario === scenario.scenarioId;
      const runStatus = scenarioRunStatus(scenario);
      const reason = scenario.disabledReason ? `<div class="scenario-reason">${escapeHtml(scenario.disabledReason)}</div>` : (scenario.requiresAdmin && !state.isAdmin ? '<div class="scenario-reason">当前权限不足，运行时会记录为跳过</div>' : '');
      html.push(`<label class="scenario-row${selected ? ' selected' : ''}${disabled ? ' disabled' : ''} run-${runStatus}" data-scenario-id="${escapeHtml(scenario.scenarioId)}" title="${disabled ? escapeHtml(scenario.disabledReason || '当前权限不足') : ''}">`);
      html.push(`<input class="scenario-check" type="radio" name="singleScenario" value="${escapeHtml(scenario.scenarioId)}" ${selected ? 'checked' : ''} ${disabled ? 'disabled' : ''}>`);
      html.push(scenarioIdentityHtml(scenario, reason));
      html.push(`<span class="threat ${threatClass(scenario.threatLevel)}">${escapeHtml(scenario.threatLevel)}</span>`);
      html.push(scenarioFlagsHtml(scenario));
      html.push(`<span class="tag">${escapeHtml(scenario.category)}</span>`);
      html.push(`<span class="scenario-id">${escapeHtml(scenario.operation)}</span>`);
      html.push('</label>');
    }
    html.push('</div>');
    html.push('</div>');
  }
  area.innerHTML = html.join('');
  updateScenarioRunVisuals();
}

function renderCategoryArea() {
  const area = $('#scenarioArea');
  if (!state.catalog.categories.length) {
    area.innerHTML = '<div class="empty-state">暂无场景分类</div>';
    return;
  }
  const html = ['<div class="category-cards">'];
  for (const category of state.catalog.categories) {
    const selected = state.selectedCategories.has(category.name);
    const disabled = category.available === 0;
    html.push(`<label class="category-card${selected ? ' selected' : ''}${disabled ? ' disabled' : ''}" data-category="${escapeHtml(category.name)}">`);
    html.push('<div class="category-card-top">');
    html.push(`<h3>${escapeHtml(category.name)}</h3>`);
    html.push(`<input type="checkbox" class="scenario-check" ${selected ? 'checked' : ''} ${disabled ? 'disabled' : ''}>`);
    html.push('</div>');
    html.push(`<div class="category-count">可运行 ${category.available} 项 / 共 ${category.total} 项</div>`);
    html.push('</label>');
  }
  html.push('</div>');
  area.innerHTML = html.join('');
}

function renderAllArea() {
  const area = $('#scenarioArea');
  const available = state.catalog.available;
  const disabled = state.catalog.disabled;
  const groups = new Map();
  for (const scenario of state.catalog.scenarios) {
    if (!groups.has(scenario.category)) groups.set(scenario.category, []);
    groups.get(scenario.category).push(scenario);
  }
  const html = ['<div class="all-panel">'];
  html.push(`<h2>运行全部可开放场景</h2>`);
  html.push(`<p>系统将按目录顺序串行执行全部 ${available} 个可开放场景。当前暂未实现的 Agent、驱动等 ${disabled} 个场景不会纳入本轮运行。需管理员场景在普通权限下会跳过。</p>`);
  html.push(`<div class="all-total">可运行 ${available} 项 · 已排除 ${disabled} 项 · 共展示 ${state.catalog.total} 项</div>`);
  html.push('</div>');
  for (const [category, scenarios] of groups.entries()) {
    html.push('<div class="category-group">');
    html.push(`<div class="category-title"><span>${escapeHtml(category)}</span><span class="muted">${scenarios.length} 项</span></div>`);
    html.push('<div class="scenario-list">');
    scenarios.forEach((scenario, index) => {
      const disabled = !scenario.available;
      const runStatus = scenarioRunStatus(scenario);
      const reason = scenario.disabledReason ? `<div class="scenario-reason">${escapeHtml(scenario.disabledReason)}</div>` : (scenario.requiresAdmin && !state.isAdmin ? '<div class="scenario-reason">当前权限不足，运行时会记录为跳过</div>' : '');
      html.push(`<div class="scenario-row${disabled ? ' disabled' : ''} run-${runStatus}" data-scenario-id="${escapeHtml(scenario.scenarioId)}">`);
      html.push(`<span class="scenario-index">${index + 1}</span>`);
      html.push(scenarioIdentityHtml(scenario, reason));
      html.push(`<span class="threat ${threatClass(scenario.threatLevel)}">${escapeHtml(scenario.threatLevel)}</span>`);
      html.push(scenarioFlagsHtml(scenario));
      html.push(`<span class="tag">${escapeHtml(scenario.category)}</span>`);
      html.push(`<span class="scenario-id">${escapeHtml(scenario.operation)}</span>`);
      html.push('</div>');
    });
    html.push('</div>');
    html.push('</div>');
  }
  area.innerHTML = html.join('');
  updateScenarioRunVisuals();
}

function renderScenarioArea() {
  if (!state.catalog) return;
  $('#singleToolbar').classList.toggle('hidden', state.mode !== 'single');
  if (state.mode === 'single') renderSingleArea();
  else if (state.mode === 'category') renderCategoryArea();
  else renderAllArea();
  updateStats();
}

function selectedScenarioCount() {
  if (!state.catalog) return 0;
  if (state.mode === 'single') return state.selectedScenario ? 1 : 0;
  if (state.mode === 'category') {
    return state.catalog.scenarios.filter((scenario) => state.selectedCategories.has(scenario.category)).length;
  }
  return state.catalog.available;
}

function selectedScenarioIds() {
  if (!state.catalog) return [];
  if (state.mode === 'single') return state.selectedScenario ? [state.selectedScenario] : [];
  if (state.mode === 'category') {
    return state.catalog.scenarios.filter((scenario) => state.selectedCategories.has(scenario.category) && scenario.available).map((scenario) => scenario.scenarioId);
  }
  return state.catalog.scenarios.filter((scenario) => scenario.available).map((scenario) => scenario.scenarioId);
}

function selectedCategories() {
  return [...state.selectedCategories];
}

function modeForSelection(payload) {
  if (!state.catalog) return [];
  if (payload.mode === 'single') return state.selectedScenario ? [state.selectedScenario] : [];
  if (payload.mode === 'category') {
    return state.catalog.scenarios.filter((scenario) => payload.categories.includes(scenario.category) && scenario.available).map((scenario) => scenario.scenarioId);
  }
  return state.catalog.scenarios.filter((scenario) => scenario.available).map((scenario) => scenario.scenarioId);
}

function updateStats() {
  const selected = state.progress.running ? state.progress.total : selectedScenarioCount();
  let pending = selected;
  let running = 0;
  let completed = 0;
  let succeeded = 0;
  let rate = '--';
  if (state.progress.running) {
    running = state.progress.current > 0 ? 1 : 0;
    completed = state.progress.completed;
    succeeded = state.progress.succeeded;
    pending = Math.max(0, selected - completed - running);
    if (completed > 0) rate = `${Math.round((succeeded / completed) * 100)}%`;
  }
  $('#statSelected').textContent = String(selected);
  $('#statPending').textContent = String(pending);
  $('#statRunning').textContent = String(running);
  $('#statCompleted').textContent = String(completed);
  $('#statRate').textContent = rate;
}

function setMode(mode) {
  state.mode = mode;
  state.selectedScenario = null;
  state.selectedCategories.clear();
  $$('.segment').forEach((button) => button.classList.toggle('active', button.dataset.mode === mode));
  renderScenarioArea();
}

function setRunningUI(running) {
  state.running = running;
  $('#runSelected').disabled = running;
  $('#cancelRun').disabled = !running;
  $$('.segment').forEach((button) => button.disabled = running);
  $$('.scenario-check').forEach((input) => input.disabled = running);
  $('#runStatePill').textContent = running ? '运行中' : (state.progress.total ? '已完成' : '未运行');
  $('#runStatePill').className = `status-pill${running ? ' running' : state.progress.total ? ' success' : ''}`;
}

async function startRun() {
  if (state.running) return;
  try {
    let payload;
    if (state.mode === 'single') {
      if (!state.selectedScenario) throw new Error('请选择一个场景。');
      payload = { mode: 'single', scenarioIds: [state.selectedScenario] };
    } else if (state.mode === 'category') {
      if (!state.selectedCategories.size) throw new Error('请至少选择一个场景分类。');
      payload = { mode: 'category', categories: selectedCategories() };
    } else {
      payload = { mode: 'all' };
    }
    payload.intervalSeconds = Number($('#intervalSeconds').value || 0);
    const selectedIds = modeForSelection(payload);
    state.runScenarioIds = selectedIds;
    state.scenarioRunState = new Map(selectedIds.map((id) => [id, 'pending']));
    state.currentScenarioId = null;

    const response = await api('/api/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    state.runId = response.runId;
    state.progress = { total: response.selectedCount, completed: 0, succeeded: 0, current: 0, running: true };
    $('#runResult').classList.add('hidden');
    $('#runResult').innerHTML = '';
    $('#logOutput').innerHTML = '';
    setRunningUI(true);
    renderScenarioArea();
    updateStats();
    openEventStream(response.runId);
  } catch (error) {
    showToast(error.message, 'error');
  }
}

function openEventStream(runId) {
  if (state.eventSource) state.eventSource.close();
  const stream = new EventSource(`/api/run/${runId}/events`);
  state.eventSource = stream;
  stream.onopen = () => {
    appendLogEntry({ stream: 'stdout', message: '已连接到运行日志流。' });
  };
  stream.onmessage = (event) => {
    let data;
    try {
      data = JSON.parse(event.data);
    } catch (_error) {
      return;
    }
    if (data.type === 'history') {
      if (data.status && data.status !== 'running') {
        finalizeRun({ status: data.status, summary: data.summary });
        return;
      }
      if (Array.isArray(data.lines)) appendLogEntries(data.lines);
    } else if (data.type === 'logs' && Array.isArray(data.lines)) {
      appendLogEntries(data.lines);
    } else if (data.type === 'done') {
      finalizeRun(data);
    }
  };
  stream.onerror = () => {
    if (!state.running) return;
    setTimeout(async () => {
      if (!state.running) return;
      try {
        const status = await api(`/api/run/${runId}`);
        if (status.status !== 'running') finalizeRun({ status: status.status, summary: status.summary });
      } catch (_error) {}
    }, 1200);
  };
}

function appendLogEntries(lines) {
  for (const line of lines) {
    appendLogEntry(line);
    updateProgressFromLog(line.message || '');
  }
}

function appendLogEntry(entry) {
  const output = $('#logOutput');
  const empty = $('.log-empty', output);
  if (empty) empty.remove();
  const line = document.createElement('div');
  const level = logLevel(entry.message || '');
  line.className = `log-line ${level}`;
  const time = entry.time ? new Date(entry.time).toLocaleTimeString('zh-CN', { hour12: false }) : '';
  line.innerHTML = `<span class="log-time">${escapeHtml(time)}</span>${escapeHtml(entry.message || '')}`;
  output.appendChild(line);
  const nearBottom = output.scrollHeight - output.scrollTop - output.clientHeight < 80;
  if (nearBottom) output.scrollTop = output.scrollHeight;
}

function logLevel(message) {
  const value = String(message);
  if (/失败|错误|异常|FAILED|ERROR|Exception/i.test(value)) return 'error';
  if (/跳过|未检测|无法|SKIPPED|ADMINISTRATOR_REQUIRED|NO_EDR_SERVICE|MANUAL_REQUIRED|USB_/i.test(value)) return 'warning';
  if (/成功|完成|SUCCESS|PASS|比对完成|已标准化/i.test(value)) return 'success';
  if (/等待|按策略|开始|执行器|Run ID/i.test(value)) return 'muted';
  return 'info';
}

function updateProgressFromLog(message) {
  const value = String(message);
  const startMatch = value.match(/\[(\d+)\/(\d+)\]\s*开始：.+?（([^)]+)）/);
  if (startMatch) {
    state.progress.current = Number(startMatch[1]);
    state.progress.running = true;
    const scenarioId = startMatch[2];
    if (state.scenarioRunState.has(scenarioId)) {
      if (state.currentScenarioId && state.scenarioRunState.get(state.currentScenarioId) === 'running') {
        state.scenarioRunState.set(state.currentScenarioId, 'pending');
      }
      state.currentScenarioId = scenarioId;
      state.scenarioRunState.set(scenarioId, 'running');
    }
  }
  const resultMatch = value.match(/结果：([A-Z_]+)/);
  if (resultMatch) {
    state.progress.completed += 1;
    state.progress.current = 0;
    if (resultMatch[1] === 'SUCCESS') state.progress.succeeded += 1;
    if (state.currentScenarioId) {
      const nextStatus = resultMatch[1] === 'SUCCESS' ? 'done' : resultMatch[1] === 'SKIPPED' ? 'skipped' : 'failed';
      state.scenarioRunState.set(state.currentScenarioId, nextStatus);
      state.currentScenarioId = null;
    }
  }
  updateStats();
  updateScenarioRunVisuals();
}

function updateScenarioRunVisuals() {
  const rows = $$('.scenario-row[data-scenario-id]');
  for (const row of rows) {
    const id = row.dataset.scenarioId;
    const scenario = state.catalog.scenarios.find((item) => item.scenarioId === id);
    if (!scenario) continue;
    const status = scenarioRunStatus(scenario);
    row.classList.remove('run-pending', 'run-running', 'run-done', 'run-failed', 'run-skipped', 'run-unavailable');
    row.classList.add(`run-${status}`);
    const badge = $('.scenario-run-state', row);
    if (badge) {
      badge.className = `scenario-run-state ${status}`;
      badge.textContent = runStateLabel(status);
    }
  }
}

async function finalizeRun(eventData) {
  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }
  state.progress.running = false;
  state.progress.current = 0;
  setRunningUI(false);
  let summary = eventData.summary;
  let status = eventData.status;
  if (!summary) {
    try {
      const current = await api(`/api/run/${state.runId}`);
      status = current.status;
      summary = current.summary;
    } catch (_error) {}
  }
  if (summary) {
    state.progress.total = Number(summary.total || state.progress.total);
    state.progress.completed = Number(summary.completed || 0);
    state.progress.succeeded = Number(summary.completed || 0);
    if (Array.isArray(summary.scenarios)) {
      for (const scenario of summary.scenarios) {
        if (!scenario || !scenario.scenario_id) continue;
        const resultStatus = scenario.status === 'SUCCESS' ? 'done' : scenario.status === 'SKIPPED' ? 'skipped' : 'failed';
        state.scenarioRunState.set(scenario.scenario_id, resultStatus);
      }
    }
  }
  state.currentScenarioId = null;
  updateStats();
  updateScenarioRunVisuals();
  showRunResult(status, summary);
  showToast(status === 'completed' ? '场景批次运行完成。' : status === 'cancelled' ? '场景批次已停止。' : '场景批次运行失败。', status === 'completed' ? 'success' : 'error');
}

function showRunResult(status, summary) {
  const box = $('#runResult');
  box.classList.remove('hidden');
  const label = status === 'completed' ? '批次运行完成' : status === 'cancelled' ? '批次已停止' : '批次运行异常';
  const summaryText = summary
    ? `成功 ${summary.completed} · 跳过 ${summary.skipped} · 失败 ${summary.failed} · 总数 ${summary.total}`
    : '未能读取轮次摘要';
  let html = `<h3>${escapeHtml(label)}</h3><p>${escapeHtml(summaryText)}</p>`;
  if (summary && summary.output_log) html += pathRow('事件日志完整路径', summary.output_log);
  if (summary) html += pathRow('轮次摘要完整路径', state.progress && state.runId ? summaryPathFromLog(summary.output_log) : '');
  box.innerHTML = html;
}

function summaryPathFromLog(outputLog) {
  return String(outputLog || '').replace(/events\.jsonl$/i, 'suite-summary.json');
}

function pathRow(label, value) {
  if (!value) return '';
  return `<div class="path-row"><span class="muted">${escapeHtml(label)}</span><code>${escapeHtml(value)}</code><button class="text-button" type="button" data-copy="${escapeHtml(value)}">复制路径</button></div>`;
}

async function cancelRun() {
  if (!state.runId) return;
  try {
    await api(`/api/run/cancel?id=${encodeURIComponent(state.runId)}`, { method: 'POST' });
    showToast('已发送停止指令。');
  } catch (error) {
    showToast(error.message, 'error');
  }
}

function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => showToast('路径已复制。', 'success')).catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
}

function fallbackCopy(text) {
  const area = document.createElement('textarea');
  area.value = text;
  area.style.position = 'fixed';
  area.style.opacity = '0';
  document.body.appendChild(area);
  area.select();
  document.execCommand('copy');
  area.remove();
  showToast('路径已复制。', 'success');
}
async function validateClientFile(file, type) {
  if (!file) throw new Error('请先选择文件。');
  if (file.size === 0) throw new Error('文件为空，请重新选择。');
  if (file.size > 1024 * 1024 * 1024) throw new Error('文件超过 1GB 限制。');
  const headText = await file.slice(0, 2 * 1024 * 1024).text();
  const trimmed = headText.replace(/^\uFEFF/, '').trimStart();
  if (type === 'local') {
    if (trimmed.startsWith('[')) throw new Error('本地运行日志应使用 JSONL（events.jsonl）格式。');
    const lines = trimmed.split(/\r?\n/).filter((line) => line.trim());
    if (!lines.length) throw new Error('本地日志中没有可识别记录。');
    for (const line of lines.slice(0, 300)) {
      try { JSON.parse(line); } catch (_error) { throw new Error('本地日志存在无效 JSON 记录。'); }
    }
  } else {
    if (trimmed.startsWith('[')) {
      if (file.size <= 64 * 1024 * 1024) {
        const full = await file.text();
        const parsed = JSON.parse(full);
        if (!Array.isArray(parsed) || parsed.length === 0) throw new Error('厂商日志 JSON 数组为空。');
      }
    } else if (trimmed.startsWith('{')) {
      const lines = trimmed.split(/\r?\n/).filter((line) => line.trim());
      if (!lines.length) throw new Error('厂商日志中没有可识别记录。');
      for (const line of lines.slice(0, 500)) {
        try { JSON.parse(line); } catch (_error) { throw new Error('厂商日志存在无效 JSON 记录。'); }
      }
    } else {
      throw new Error('厂商日志不是 JSON 数组或 JSONL 格式。');
    }
  }
  return true;
}

function bindCompareEvents() {
  $('#chooseLocalFile').addEventListener('click', () => $('#localFileInput').click());
  $('#chooseVendorFile').addEventListener('click', () => $('#vendorFileInput').click());

  $('#localFileInput').addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (!file) return;
    state.localFile = file;
    state.localUpload = null;
    $('#localFileMeta').textContent = `${file.name} · ${formatBytes(file.size)}`;
    $('#localImportStatus').textContent = '已选择';
    $('#localImportStatus').className = 'status-pill warning';
    $('#uploadLocal').disabled = false;
    $('#localPathBox').classList.add('hidden');
    updateCompareButton();
  });

  $('#vendorFileInput').addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (!file) return;
    state.vendorFile = file;
    state.vendorUpload = null;
    $('#vendorFileMeta').textContent = `${file.name} · ${formatBytes(file.size)}`;
    $('#vendorImportStatus').textContent = '已选择';
    $('#vendorImportStatus').className = 'status-pill warning';
    $('#uploadVendor').disabled = false;
    $('#vendorPathBox').classList.add('hidden');
    updateCompareButton();
  });

  $('#uploadLocal').addEventListener('click', async () => {
    try {
      await validateClientFile(state.localFile, 'local');
      $('#uploadLocal').disabled = true;
      $('#localImportStatus').textContent = '导入中';
      $('#localImportStatus').className = 'status-pill running';
      const query = `?name=${encodeURIComponent(state.localFile.name)}`;
      const data = await uploadBinary(`/api/import/local${query}`, state.localFile);
      state.localUpload = data;
      $('#localSavedPath').textContent = data.path;
      $('#localPathBox').classList.remove('hidden');
      $('#localImportStatus').textContent = '已导入';
      $('#localImportStatus').className = 'status-pill success';
      showToast('本地日志导入完成。', 'success');
    } catch (error) {
      $('#localImportStatus').textContent = '导入失败';
      $('#localImportStatus').className = 'status-pill failed';
      showToast(error.message, 'error');
    } finally {
      $('#uploadLocal').disabled = false;
      updateCompareButton();
    }
  });

  $('#uploadVendor').addEventListener('click', async () => {
    try {
      await validateClientFile(state.vendorFile, 'vendor');
      $('#uploadVendor').disabled = true;
      $('#vendorImportStatus').textContent = '导入中';
      $('#vendorImportStatus').className = 'status-pill running';
      const vendorId = $('#vendorId').value;
      const normalize = $('#normalizeVendor').checked;
      const query = `?name=${encodeURIComponent(state.vendorFile.name)}&vendorId=${encodeURIComponent(vendorId)}&normalize=${normalize}`;
      const data = await uploadBinary(`/api/import/vendor${query}`, state.vendorFile);
      state.vendorUpload = data;
      const shownPath = data.normalizedPath || data.path;
      $('#vendorSavedPath').textContent = shownPath;
      $('#vendorPathBox').classList.remove('hidden');
      $('#vendorImportStatus').textContent = normalize ? '已标准化' : '已导入';
      $('#vendorImportStatus').className = 'status-pill success';
      showToast(normalize ? '厂商日志已导入并标准化。' : '厂商日志已导入。', 'success');
    } catch (error) {
      $('#vendorImportStatus').textContent = '导入失败';
      $('#vendorImportStatus').className = 'status-pill failed';
      showToast(error.message, 'error');
    } finally {
      $('#uploadVendor').disabled = false;
      updateCompareButton();
    }
  });

  $('#startCompare').addEventListener('click', startCompare);
}

function updateCompareButton() {
  const ready = Boolean(state.localUpload && state.vendorUpload);
  $('#startCompare').disabled = !ready;
}

async function startCompare() {
  if (state.compareLoading) return;
  state.compareLoading = true;
  $('#startCompare').disabled = true;
  $('#startCompare').textContent = '比对中';
  $('#compareResult').classList.add('hidden');
  try {
    const vendorPath = state.vendorUpload.normalizedPath || state.vendorUpload.path;
    const data = await api('/api/compare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        localLogPath: state.localUpload.path,
        cloudPaths: [vendorPath],
        vendorId: state.vendorUpload.vendorId || $('#vendorId').value
      })
    });
    renderCompareResult(data);
    showToast('离线比对完成。', 'success');
  } catch (error) {
    showToast(error.message, 'error');
  } finally {
    state.compareLoading = false;
    $('#startCompare').disabled = false;
    $('#startCompare').textContent = '开始比对';
  }
}

function renderCompareResult(data) {
  const box = $('#compareResult');
  box.classList.remove('hidden');
  const result = data.result;
  const summary = result.summary || {};
  const conclusion = result.conclusion || {};
  const status = conclusion.verdict || 'INCONCLUSIVE';
  const statusLabel = conclusion.label_zh || status;
  const counts = [
    ['通过', Number(summary.pass || 0), 'pass'],
    ['部分通过', Number(summary.partial || 0), 'partial'],
    ['失败', Number(summary.fail || 0), 'fail'],
    ['无法判定', Number(summary.inconclusive || 0), 'inconclusive'],
    ['未比较', Number(summary.not_compared || 0), 'not_compared']
  ];
  const total = counts.reduce((sum, item) => sum + item[1], 0);
  const passRate = conclusion.pass_rate;
  box.innerHTML = `
    <div class="result-preview-header">
      <div>
        <div class="eyebrow">Comparison Conclusion</div>
        <h2>${escapeHtml(statusLabel)}</h2>
        <p class="page-desc">${escapeHtml(conclusion.statement_zh || '已生成离线比对结论。')}</p>
      </div>
      <span class="verdict ${escapeHtml(status)}">${escapeHtml(status)}</span>
    </div>
    <div class="summary-grid">
      ${counts.map(([label, count, cls]) => `<div class="summary-cell"><div class="stat-label">${label}</div><div class="stat-value">${count}</div></div>`).join('')}
    </div>
    ${statusBarRows(counts, total)}
    ${passRateRing(Number(passRate || 0))}
    ${capabilityTable(result.capabilities || [])}
    ${pathRow('比对结果完整路径', data.outputPath)}
    ${pathRow('Markdown 结论完整路径', data.conclusionPath)}
  `;
}

function statusBarRows(counts, total) {
  if (!total) return '';
  const bars = counts.map(([label, count, cls]) => `
    <div class="bar-row">
      <span>${label}</span>
      <div class="bar-track"><div class="bar-fill ${cls}" style="width:${Math.max(0, (count / total) * 100).toFixed(1)}%"></div></div>
      <span>${Math.round((count / total) * 100)}%</span>
    </div>
  `).join('');
  return `<div class="bar-list"><h3>结果占比</h3>${bars}</div>`;
}

function passRateRing(rate) {
  const percent = Math.max(0, Math.min(1, rate));
  const rounded = Math.round(percent * 100);
  return `
    <div class="pass-rate-grid">
      <div class="ring" style="background: conic-gradient(#16a34a ${rounded}%, #e5e7eb ${rounded}% 100%)">
        <div class="ring-inner">${rounded}%</div>
      </div>
      <div>
        <h3>场景达标率</h3>
        <p class="page-desc">达标率按已比较能力中通过或部分通过的比例计算，原始值来自 Comparator 的 conclusion.pass_rate。</p>
      </div>
    </div>
  `;
}

function capabilityTable(capabilities) {
  if (!capabilities.length) return '<div class="empty-state">没有能力明细</div>';
  const rows = capabilities.map((capability) => {
    const status = capability.validation_status || 'NOT_COMPARED';
    const cls = String(status).toLowerCase();
    return `<tr>
      <td><div>${escapeHtml(capability.display_name_zh || capability.capability_id)}</div><div class="capability-id">${escapeHtml(capability.capability_id || '')}</div></td>
      <td>${escapeHtml(capability.local_status || '-')}</td>
      <td><span class="verdict ${escapeHtml(status)}">${escapeHtml(status)}</span></td>
      <td>${Number(capability.candidate_count || 0)}</td>
      <td>${escapeHtml((capability.warnings || []).join('；') || capability.detail || '-')}</td>
    </tr>`;
  }).join('');
  return `
    <table class="capability-table">
      <thead><tr><th>能力</th><th>本地执行</th><th>EDR 验证</th><th>候选事件</th><th>说明</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function bindResultEvents() {
  $('#chooseResultFile').addEventListener('click', () => $('#resultFileInput').click());
  $('#refreshReports').addEventListener('click', loadReports);
  $('#reportItems').addEventListener('click', (event) => {
    const item = event.target.closest('.report-item');
    if (!item || !item.dataset.reportPath) return;
    $$('.report-item').forEach((node) => node.classList.remove('active'));
    item.classList.add('active');
    loadReport(item.dataset.reportPath);
  });
  $('#resultFileInput').addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    try {
      if (file.size === 0) throw new Error('结果文件为空。');
      const text = await file.text();
      const result = JSON.parse(text);
      if (!result || !result.summary || !result.conclusion || !Array.isArray(result.capabilities)) {
        throw new Error('文件不是有效的 EDR 比对结果。');
      }
      renderResult(result, '');
      showToast('结果已导入。', 'success');
    } catch (error) {
      showToast(error.message, 'error');
    }
  });

  $('#exportJson').addEventListener('click', () => {
    if (!state.result) return;
    downloadBlob('edr-validation-result.json', JSON.stringify(state.result, null, 2), 'application/json;charset=utf-8');
  });
  $('#exportMarkdown').addEventListener('click', () => {
    if (!state.result) return;
    downloadBlob('edr-validation-conclusion.md', state.conclusionMarkdown || generateMarkdown(state.result), 'text/markdown;charset=utf-8');
  });
  $('#exportHtml').addEventListener('click', () => {
    if (!state.result) return;
    downloadBlob('edr-validation-report.html', generateHtmlReport(state.result), 'text/html;charset=utf-8');
  });
}

async function loadReports() {
  try {
    const data = await api('/api/reports');
    const items = $('#reportItems');
    if (!data.reports.length) {
      items.innerHTML = '<div class="empty-state">暂无可用结果</div>';
      return;
    }
    items.innerHTML = data.reports.map((report) => `
      <div class="report-item" data-report-path="${escapeHtml(report.path)}">
        <div class="report-item-name">${escapeHtml(report.name)}</div>
        <div class="report-item-time">${escapeHtml(new Date(report.modifiedAt).toLocaleString('zh-CN', { hour12: false }))} · ${formatBytes(report.size)}</div>
      </div>
    `).join('');
  } catch (error) {
    showToast(error.message, 'error');
  }
}

async function loadReport(path) {
  try {
    const data = await api(`/api/report/content?path=${encodeURIComponent(path)}`);
    renderResult(data.result, data.conclusionMarkdown || '');
  } catch (error) {
    showToast(error.message, 'error');
  }
}

function renderResult(result, markdown) {
  state.result = result;
  state.conclusionMarkdown = markdown;
  $('#exportJson').disabled = false;
  $('#exportMarkdown').disabled = false;
  $('#exportHtml').disabled = false;
  const preview = $('#resultPreview');
  const summary = result.summary || {};
  const conclusion = result.conclusion || {};
  const status = conclusion.verdict || 'INCONCLUSIVE';
  const label = conclusion.label_zh || status;
  const counts = [
    ['通过', Number(summary.pass || 0), 'pass'],
    ['部分通过', Number(summary.partial || 0), 'partial'],
    ['失败', Number(summary.fail || 0), 'fail'],
    ['无法判定', Number(summary.inconclusive || 0), 'inconclusive'],
    ['未比较', Number(summary.not_compared || 0), 'not_compared']
  ];
  const total = counts.reduce((sum, item) => sum + item[1], 0);
  preview.innerHTML = `
    <div class="result-preview-header">
      <div>
        <div class="eyebrow">Result Preview</div>
        <h2>${escapeHtml(label)}</h2>
        <p class="page-desc">${escapeHtml(conclusion.statement_zh || '已生成离线比对结论。')}</p>
      </div>
      <span class="verdict ${escapeHtml(status)}">${escapeHtml(status)}</span>
    </div>
    <div class="summary-grid">
      ${counts.map(([itemLabel, count, cls]) => `<div class="summary-cell"><div class="stat-label">${itemLabel}</div><div class="stat-value">${count}</div></div>`).join('')}
    </div>
    ${statusBarRows(counts, total)}
    ${passRateRing(Number(conclusion.pass_rate || 0))}
    ${capabilityTable(result.capabilities || [])}
  `;
}

function downloadBlob(name, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function generateMarkdown(result) {
  const conclusion = result.conclusion || {};
  const summary = result.summary || {};
  const lines = [
    '# EDR 遥测离线比对结论',
    '',
    `- 比较编号：\`${result.comparison_id || ''}\``,
    `- 总体判定：**${conclusion.label_zh || conclusion.verdict}（${conclusion.verdict || ''}）**`,
    '',
    '## 总体结论',
    '',
    conclusion.statement_zh || '已生成离线比对结论。',
    '',
    '## 汇总',
    '',
    '| 通过 | 部分通过 | 失败 | 无法判定 | 未比较 |',
    '| ---: | ---: | ---: | ---: | ---: |',
    `| ${summary.pass || 0} | ${summary.partial || 0} | ${summary.fail || 0} | ${summary.inconclusive || 0} | ${summary.not_compared || 0} |`
  ];
  return lines.join('\n');
}

function generateHtmlReport(result) {
  const summary = result.summary || {};
  const conclusion = result.conclusion || {};
  const counts = {
    pass: summary.pass || 0,
    partial: summary.partial || 0,
    fail: summary.fail || 0,
    inconclusive: summary.inconclusive || 0,
    not_compared: summary.not_compared || 0
  };
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const rate = Math.round(Number(conclusion.pass_rate || 0) * 100);
  const rows = (result.capabilities || []).map((item) => `<tr><td>${escapeHtml(item.display_name_zh || item.capability_id)}</td><td>${escapeHtml(item.local_status || '-')}</td><td>${escapeHtml(item.validation_status || '-')}</td></tr>`).join('');
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>EDR 可视化报告</title><style>
    body{font-family:"Segoe UI","Microsoft YaHei",sans-serif;color:#1f2937;background:#f4f6f8;margin:0;padding:28px;}
    .sheet{max-width:1080px;margin:auto;background:#fff;border:1px solid #e5e7eb;border-radius:6px;padding:26px;}
    h1{margin:0 0 6px;font-size:24px;} .muted{color:#6b7280;} .grid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:20px 0;}
    .cell{border:1px solid #e5e7eb;border-radius:6px;padding:12px;background:#f8fafc;} .value{font-size:22px;font-weight:700;}
    .bar{height:12px;background:#e5e7eb;border-radius:6px;overflow:hidden;margin:6px 0 12px;} .bar span{display:block;height:100%;}
    table{width:100%;border-collapse:collapse;margin-top:20px;} th,td{text-align:left;border-bottom:1px solid #e5e7eb;padding:8px;}
    th{color:#6b7280;font-size:12px;} .verdict{display:inline-block;padding:3px 8px;border-radius:4px;font-weight:700;background:#e9f8ee;color:#15803d;}
    .pass{background:#16a34a}.partial{background:#f59e0b}.fail{background:#dc2626}.inconclusive{background:#64748b}.not_compared{background:#cbd5e1}
  </style></head><body><div class="sheet">
  <div class="muted">EDR Telemetry Offline Validation</div>
  <h1>${escapeHtml(conclusion.label_zh || conclusion.verdict || '比对结果')}</h1>
  <div class="muted">${escapeHtml(conclusion.statement_zh || '')}</div>
  <div class="grid">
    ${Object.entries(counts).map(([key, value]) => `<div class="cell"><div class="muted">${escapeHtml(key)}</div><div class="value">${value}</div></div>`).join('')}
  </div>
  <div><strong>场景达标率：${rate}%</strong><div class="bar"><span class="pass" style="width:${rate}%"></span></div></div>
  <table><thead><tr><th>能力</th><th>本地执行</th><th>EDR 验证</th></tr></thead><tbody>${rows}</tbody></table>
  </div></body></html>`;
}
function bindRunEvents() {
  $$('.nav-item').forEach((button) => {
    button.addEventListener('click', () => switchView(button.dataset.view));
  });

  $$('.segment').forEach((button) => {
    button.addEventListener('click', () => {
      if (state.running) return;
      setMode(button.dataset.mode);
    });
  });

  $('#refreshCatalog').addEventListener('click', loadCatalog);
  $('#scenarioSearch').addEventListener('input', renderSingleArea);
  $('#threatFilter').addEventListener('change', renderSingleArea);
  $('#categoryFilter').addEventListener('change', renderSingleArea);
  $('#runSelected').addEventListener('click', startRun);
  $('#cancelRun').addEventListener('click', cancelRun);
  $('#clearLog').addEventListener('click', () => {
    $('#logOutput').innerHTML = '<div class="log-empty">暂无运行日志</div>';
  });

  $('#scenarioArea').addEventListener('change', (event) => {
    if (state.running) return;
    if (event.target.matches('.scenario-check')) {
      if (state.mode === 'single') {
        const row = event.target.closest('[data-scenario-id]');
        state.selectedScenario = row ? row.dataset.scenarioId : null;
        renderSingleArea();
        updateStats();
      } else if (state.mode === 'category') {
        const card = event.target.closest('[data-category]');
        if (card) {
          const category = card.dataset.category;
          if (event.target.checked) state.selectedCategories.add(category);
          else state.selectedCategories.delete(category);
          renderCategoryArea();
          updateStats();
        }
      }
    }
  });

  $('#scenarioArea').addEventListener('click', (event) => {
    if (state.running) return;
    const row = event.target.closest('.scenario-row');
    if (row && state.mode === 'single') {
      const input = $('.scenario-check', row);
      if (input && !input.disabled) {
        input.checked = true;
        state.selectedScenario = row.dataset.scenarioId;
        renderSingleArea();
        updateStats();
      }
      return;
    }
    const card = event.target.closest('.category-card');
    if (card && state.mode === 'category') {
      const input = $('.scenario-check', card);
      if (input && !input.disabled) {
        input.checked = !input.checked;
        const category = card.dataset.category;
        if (input.checked) state.selectedCategories.add(category);
        else state.selectedCategories.delete(category);
        renderCategoryArea();
        updateStats();
      }
    }
  });

  document.addEventListener('click', (event) => {
    const copyButton = event.target.closest('[data-copy]');
    if (copyButton) copyText(copyButton.dataset.copy);
    const copyTarget = event.target.closest('[data-copy-target]');
    if (copyTarget) {
      const target = document.getElementById(copyTarget.dataset.copyTarget);
      if (target) copyText(target.textContent.trim());
    }
  });
}

function switchView(view) {
  $$('.nav-item').forEach((button) => button.classList.toggle('active', button.dataset.view === view));
  $$('.view').forEach((section) => section.classList.toggle('active', section.id === `view-${view}`));
}

async function init() {
  bindRunEvents();
  bindCompareEvents();
  bindResultEvents();
  await Promise.all([loadHealth(), loadCatalog(), loadReports()]);
  setMode('single');
  updateAdminBadge();
  updateCompareButton();
}

document.addEventListener('DOMContentLoaded', init);