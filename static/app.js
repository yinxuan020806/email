/* 邮箱管家 Web v3.0 - 前端逻辑（多用户隔离）
 * - 所有用户内容统一通过 textContent / createElement 写入，杜绝 XSS
 * - 邮件正文使用 srcdoc + sandbox 的 iframe 隔离渲染
 * - 鉴权通过 HttpOnly Cookie 携带，所有 fetch 都带 credentials: 'include'
 */
(() => {
'use strict';

const t = (k, p) => (window.I18N ? window.I18N.t(k, p) : k);

// ───────── State ─────────
const S = {
  accounts: [], groups: [], currentGroup: '全部', selected: new Set(),
  theme: 'cyber', lang: 'zh', view: 'table', searchText: '',
  emailAccount: null, emails: [], allEmails: [], currentEmail: null,
  detailAccount: null,
  user: null,
  registerEnabled: true,
  authMode: 'login',
  ready: false,
  // 全部邮箱总数 + 各分组邮箱数（来自 /api/dashboard）
  counts: { total: 0, byGroup: {} },
  // 已加入接码白名单的账号 id 集合（仅站长会被填充非空）
  publicIds: new Set(),
  publicCategories: {},
  codeReceiverRequireToken: true,
};

// ───────── SPA 路由 ─────────
// 把"用户当前在哪"反映到地址栏，刷新/分享 URL 时能保持状态。
function pushPath(path, replace = false) {
  const cur = window.location.pathname;
  if (cur === path) return;
  try {
    if (replace) history.replaceState({ path }, '', path);
    else history.pushState({ path }, '', path);
  } catch { /* file:// 等环境忽略 */ }
}

function applyPath(path) {
  // 已登录态：根据 path 切换主区视图
  if (!S.user) {
    if (path === '/register') setAuthMode('register');
    else setAuthMode('login');
    return;
  }
  if (path === '/dashboard') showView('dashboard');
  else if (path === '/settings') showView('settings');
  else if (path === '/help') showView('help');
  else {
    // /login /register 在已登录时回首页
    if (path === '/login' || path === '/register') {
      pushPath('/', true);
    }
    selectGroup(S.currentGroup || '全部');
  }
}

window.addEventListener('popstate', () => applyPath(window.location.pathname));

// ───────── DOM helpers ─────────
const $ = (id) => document.getElementById(id);
const el = (tag, attrs = {}, children = []) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'style') node.setAttribute('style', v);
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else if (v === true) node.setAttribute(k, '');
    else if (v !== false && v != null) node.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c == null) continue;
    node.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
};
const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); };

// ───────── API ─────────
// 普通 API 请求的默认客户端超时（毫秒）。
// 「测试连接」会触发服务端连 QQ IMAP（TLS）；VPS 网络偶发抖动时整条链路
// 可能 >30s 仍合法完成，太短会误 Abort。辅助邮箱三张接口单独用更长常量。
const DEFAULT_REQUEST_TIMEOUT_MS = 45000;
const HELPER_IMAP_FETCH_TIMEOUT_MS = 90000;
const HELPER_IMAP_TEST_TIMEOUT_MS = 125000;

async function request(url, options = {}) {
  const { noTimeout, timeoutMs, ...rest } = options || {};
  const opts = { credentials: 'include', headers: {}, ...rest };
  // 统一带上 cookie；显式声明，便于跨端口/HTTPS 一致
  opts.credentials = 'include';
  if (opts.body && !(opts.body instanceof FormData)) {
    opts.headers['Content-Type'] = 'application/json';
    if (typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);
  }
  // 给短请求接 AbortController；SSE 流（``api.stream``）显式跳过
  let timeoutId = null;
  if (!noTimeout && !opts.signal) {
    const ac = new AbortController();
    opts.signal = ac.signal;
    const ms = (typeof timeoutMs === 'number' && timeoutMs > 0)
      ? timeoutMs : DEFAULT_REQUEST_TIMEOUT_MS;
    timeoutId = setTimeout(() => ac.abort(), ms);
  }
  let r;
  try {
    r = await fetch(url, opts);
  } catch (e) {
    // AbortError → 把它包装成"网关超时"系列的可识别错误，避免上层显示
    // 原始 ``signal is aborted without reason``
    if (e && e.name === 'AbortError') {
      const secs = Math.round((timeoutMs || DEFAULT_REQUEST_TIMEOUT_MS) / 1000);
      const hint = secs >= 90
        ? '若刚点「测试连接」，多为服务器访问 QQ IMAP 较慢，可多试一两次。'
        : '';
      const err = new Error(
        `请求超时（已等待 ${secs}s，后端可能繁忙或重启）${hint}`,
      );
      err.status = 0;
      err.code = 'client_timeout';
      throw err;
    }
    throw e;
  } finally {
    if (timeoutId !== null) clearTimeout(timeoutId);
  }
  if (r.status === 401) {
    // 跳过 401 的特殊路径：不让 /api/auth/me 自身的 401 触发登录弹框反复展示
    if (!url.startsWith('/api/auth/')) {
      S.user = null;
      showAuthModal('login');
    }
    const err = new Error('unauthorized');
    err.status = 401;
    throw err;
  }
  return r;
}

// HTTP 状态码 → 用户能看懂的简短文案。空字符串 = 走 detail / fallback。
const _GATEWAY_ERROR_HINT = {
  502: '反代/网关错误（502 Bad Gateway）',
  503: '服务暂时不可用（503）',
  504: '反代超时（504 Gateway Timeout）',
  520: 'Cloudflare 520：源站返回了空响应',
  521: 'Cloudflare 521：源站拒绝连接（后端进程没起）',
  522: 'Cloudflare 522：源站 TCP 握手超时（防火墙/网络问题）',
  523: 'Cloudflare 523：源站不可达（路由问题）',
  524: 'Cloudflare 524：源站响应超时（最常见原因 = 后端 event loop 卡死，需要重启 docker compose restart email-web）',
  525: 'Cloudflare 525：源站 TLS 握手失败',
  526: 'Cloudflare 526：源站证书无效',
};

// 解析后端错误 detail（JSON / 文本），便于在 toast 中展示。
//
// 关键改动：旧实现拿不到 JSON 就 ``await r.text()`` 全文返回，而 Cloudflare
// 524/502 等会返一整页 HTML（~5KB），结果是 UI 卡片里堆一整坨
// ``<!DOCTYPE html>...`` 之类的字符。这里做三步处理：
//   1) 如果是 ``_GATEWAY_ERROR_HINT`` 里登记的 5xx 状态码，直接返登记文案
//   2) 否则尝试 JSON.parse；解出 detail/error 字段就回那一段
//   3) 否则 text() 取首段不含 HTML 标签的内容；全是 HTML 就只显示状态码
async function parseError(r) {
  const hint = _GATEWAY_ERROR_HINT[r.status];
  if (hint) return hint;
  try {
    const j = await r.clone().json();
    if (typeof j.detail === 'string') return j.detail;
    if (Array.isArray(j.detail)) return j.detail.map((d) => d.msg).join('; ');
    if (typeof j.error === 'string') return j.error;
    return JSON.stringify(j);
  } catch {
    /* not JSON, fall through */
  }
  try {
    const txt = await r.text();
    const trimmed = (txt || '').trim();
    // 看起来是 HTML 错误页（含 <html / <!DOCTYPE / </head> 等） → 不暴露全文
    if (/^<!doctype|^<html/i.test(trimmed) || /<\/head>/i.test(trimmed)) {
      // 尽量抓 <title> 里的内容（如 "524: A timeout occurred"）作为提示
      const m = trimmed.match(/<title[^>]*>([^<]{1,160})<\/title>/i);
      const title = m ? m[1].trim() : '';
      return `HTTP ${r.status}${title ? ' · ' + title : ''}（反代/CDN 返回了 HTML 错误页，源站多半没响应）`;
    }
    return trimmed.slice(0, 240) || r.statusText || `HTTP ${r.status}`;
  } catch { return r.statusText || `HTTP ${r.status}`; }
}

async function readJson(r) {
  if (!r.ok) {
    const msg = await parseError(r);
    const err = new Error(msg);
    err.status = r.status;
    throw err;
  }
  return r.json();
}

const api = {
  get: (u, opts = {}) => request(u, opts).then(readJson),
  post: (u, d, opts = {}) =>
    request(u, Object.assign({}, { method: 'POST', body: d }, opts)).then(readJson),
  put: (u, d, opts = {}) =>
    request(u, Object.assign({}, { method: 'PUT', body: d }, opts)).then(readJson),
  del: (u, opts = {}) =>
    request(u, Object.assign({}, { method: 'DELETE' }, opts)).then(readJson),
  stream: async (u, d, onData) => {
    // SSE 长连接显式 noTimeout，不被默认客户端 AbortController 切。
    // 反代/CF 端的 idle timeout 由后端 SSE keepalive 注释帧 (`: keepalive\n\n`)
    // 兜住，详见 core/helper_routes.py batch_mailbox 的实现。
    const r = await request(u, { method: 'POST', body: d, noTimeout: true });
    if (!r.ok) {
      const msg = await parseError(r);
      throw new Error(msg);
    }
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try { onData(JSON.parse(line.slice(6))); } catch (e) { /* ignore */ }
        }
      }
    }
  }
};

// ───────── Toast ─────────
function toast(msg, type = 'info') {
  const text = String(msg ?? '');
  const node = el('div', {
    class: 'toast toast-' + type,
    style: 'cursor:pointer;max-width:520px;white-space:pre-wrap;line-height:1.5;',
    title: '点击关闭',
  }, text);
  const ttl = (type === 'error' || type === 'warning') ? 10000 : 3000;
  const close = () => {
    node.style.opacity = '0';
    node.style.transition = '.3s';
    setTimeout(() => node.remove(), 300);
  };
  node.addEventListener('click', close);
  $('toastBox').appendChild(node);
  setTimeout(close, ttl);
}

// ───────── Modal ─────────
const openModal = (id) => $(id).classList.add('show');
const closeModal = (id) => $(id).classList.remove('show');

document.addEventListener('click', (e) => {
  const closeId = e.target?.dataset?.close;
  if (closeId) closeModal(closeId);
});

// ───────── Auth ─────────
function setAuthMode(mode) {
  S.authMode = (mode === 'register') ? 'register' : 'login';
  const isReg = S.authMode === 'register';
  $('tabLogin').classList.toggle('active', !isReg);
  $('tabRegister').classList.toggle('active', isReg);
  $('authPassword2Group').style.display = isReg ? '' : 'none';
  $('authSubmit').textContent = t(isReg ? 'auth_btn_register' : 'auth_btn_login');
  $('authSub').textContent = t(isReg ? 'auth_sub_register' : 'auth_sub_login');
  $('authPassword').setAttribute('autocomplete', isReg ? 'new-password' : 'current-password');
  $('authErr').textContent = '';
  if (!S.user) {
    pushPath(isReg ? '/register' : '/login', true);
  }
}

function showAuthModal(mode) {
  hideMain();
  setAuthMode(mode || 'login');
  $('authUsername').value = '';
  $('authPassword').value = '';
  $('authPassword2').value = '';
  $('authErr').textContent = '';
  if (!S.registerEnabled) $('tabRegister').style.display = 'none';
  openModal('authModal');
  pushPath(mode === 'register' ? '/register' : '/login', true);
  setTimeout(() => $('authUsername').focus(), 60);
}

function hideMain() {
  document.querySelector('.app').style.visibility = 'hidden';
}
function showMain() {
  document.querySelector('.app').style.visibility = '';
}

async function submitAuth() {
  const username = $('authUsername').value.trim();
  const password = $('authPassword').value;
  const errEl = $('authErr');
  errEl.textContent = '';

  if (!username) { errEl.textContent = t('auth_err_username_required'); return; }
  if (!password) { errEl.textContent = t('auth_err_password_required'); return; }

  const isReg = S.authMode === 'register';
  if (isReg) {
    if (password.length < 6) { errEl.textContent = t('auth_err_password_short'); return; }
    if ($('authPassword2').value !== password) {
      errEl.textContent = t('auth_err_password_mismatch'); return;
    }
  }

  const submitBtn = $('authSubmit');
  submitBtn.disabled = true;
  const oldText = submitBtn.textContent;
  submitBtn.textContent = '...';

  try {
    const url = isReg ? '/api/auth/register' : '/api/auth/login';
    const r = await request(url, {
      method: 'POST',
      body: JSON.stringify({ username, password }),
      headers: { 'Content-Type': 'application/json' },
    });
    if (!r.ok) {
      const msg = await parseError(r);
      errEl.textContent = msg || t('auth_err_failed');
      return;
    }
    const data = await r.json();
    S.user = { username: data.username };
    closeModal('authModal');
    showMain();
    pushPath('/', true);
    toast(t(isReg ? 'toast_register_ok' : 'toast_login_ok'), 'success');
    await init();
  } catch (e) {
    errEl.textContent = (e && e.message) || t('auth_err_failed');
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = oldText;
  }
}

async function logout() {
  if (!confirm(t('confirm_logout'))) return;
  try {
    await request('/api/auth/logout', { method: 'POST' });
  } catch { /* 即便失败也清前端态 */ }
  S.user = null;
  S.accounts = [];
  S.groups = [];
  S.selected.clear();
  S.publicIds.clear();
  S.publicCategories = {};
  S.ready = false;
  applyOwnerVisibility();
  showAuthModal('login');
}

/** 拉当前用户身份（含 is_owner / code_owner_username）。失败返回 false。 */
async function loadMe() {
  try {
    const r = await fetch('/api/auth/me', { credentials: 'include' });
    if (!r.ok) return false;
    const data = await r.json();
    S.user = {
      username: data.username || '',
      is_owner: !!data.is_owner,
      code_owner: data.code_owner_username || '',
    };
    return true;
  } catch {
    return false;
  }
}

/** 站长可见元素的统一显隐控制（按钮 + 表头 + 表格列）。 */
function applyOwnerVisibility() {
  const isOwner = !!(S.user && S.user.is_owner);
  // col-token 与 col-public 同样仅站长可见
  document.querySelectorAll('.owner-only, .col-public, .col-token').forEach((node) => {
    if (isOwner) node.removeAttribute('hidden');
    else node.setAttribute('hidden', '');
  });
  updateCodeRequireTokenToggle();
}

function updateCodeRequireTokenToggle() {
  const cb = $('codeRequireTokenToggle');
  if (cb) cb.checked = !!S.codeReceiverRequireToken;
}

async function setCodeReceiverRequireToken(enabled) {
  if (!S.user || !S.user.is_owner) return;
  const prev = S.codeReceiverRequireToken;
  S.codeReceiverRequireToken = !!enabled;
  updateCodeRequireTokenToggle();
  try {
    await api.put('/api/settings', {
      key: 'code_receiver_require_token',
      value: S.codeReceiverRequireToken ? '1' : '0',
    });
    toast(t(S.codeReceiverRequireToken
      ? 'toast_code_token_enabled'
      : 'toast_code_token_disabled'), 'success');
  } catch (e) {
    S.codeReceiverRequireToken = prev;
    updateCodeRequireTokenToggle();
    toast(t('toast_load_fail') + (e?.message || ''), 'error');
  }
}

function updateUserDisplay() {
  if (S.user && S.user.username) $('sbUserName').textContent = S.user.username;
  else $('sbUserName').textContent = '-';
}

$('authSubmit').addEventListener('click', submitAuth);
$('authUsername').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $('authPassword').focus();
});
$('authPassword').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    if (S.authMode === 'register') $('authPassword2').focus();
    else submitAuth();
  }
});
$('authPassword2').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') submitAuth();
});
$('tabLogin').addEventListener('click', () => setAuthMode('login'));
$('tabRegister').addEventListener('click', () => setAuthMode('register'));
$('logoutBtn').addEventListener('click', logout);

// ───────── Context Menu ─────────
const hideCtx = () => { $('ctxMenu').style.display = 'none'; };
document.addEventListener('click', hideCtx);

function showGroupCtx(e, name) {
  e.stopPropagation();
  e.preventDefault();
  const m = $('ctxMenu');
  clear(m);
  m.appendChild(el('button', { onclick: () => doRenameGroup(name) }, t('ctx_rename')));
  if (name !== '默认分组') m.appendChild(el('button', { onclick: () => doDeleteGroup(name) }, t('ctx_delete')));
  m.style.display = 'block';
  m.style.left = e.clientX + 'px';
  m.style.top = e.clientY + 'px';
}

// ───────── Groups ─────────
async function loadGroups() {
  S.groups = await api.get('/api/groups');
  renderGroups();
}

async function loadCounts() {
  try {
    const d = await api.get('/api/dashboard');
    S.counts = { total: d.total || 0, byGroup: d.groups || {} };
  } catch {
    /* 仪表盘接口失败时保持上次的计数即可 */
  }
  renderCounts();
}

function renderCounts() {
  // "全部邮箱"按钮上的徽标
  const navAll = $('navAll');
  let badge = navAll.querySelector('.nav-count');
  if (!badge) {
    badge = el('span', { class: 'nav-count' });
    navAll.appendChild(badge);
  }
  badge.textContent = String(S.counts.total || 0);

  // 各分组的徽标
  document.querySelectorAll('.grp-item').forEach((item) => {
    const name = item.dataset.group;
    if (!name) return;
    let b = item.querySelector('.grp-count');
    if (!b) {
      b = el('span', { class: 'grp-count' });
      // 插入到 ⋯ 之前
      const ctx = item.querySelector('.grp-ctx');
      if (ctx) item.insertBefore(b, ctx);
      else item.appendChild(b);
    }
    b.textContent = String(S.counts.byGroup[name] || 0);
  });
}

function renderGroups() {
  const list = $('groupList');
  clear(list);
  for (const g of S.groups) {
    const item = el('div', {
      class: 'grp-item' + (S.currentGroup === g.name ? ' active' : ''),
      dataset: { group: g.name },
      onclick: () => selectGroup(g.name),
      oncontextmenu: (e) => showGroupCtx(e, g.name),
    });
    item.appendChild(el('span', { class: 'grp-name' }, '📁 ' + g.name));
    item.appendChild(el('span', {
      class: 'grp-ctx',
      onclick: (e) => { e.stopPropagation(); showGroupCtx(e, g.name); }
    }, '⋯'));
    list.appendChild(item);
  }
  renderCounts();
}

function selectGroup(name) {
  S.currentGroup = name;
  S.view = 'table';
  document.querySelectorAll('.nav-btn').forEach((b) => b.classList.remove('active'));
  if (name === '全部') $('navAll').classList.add('active');
  renderGroups();
  showTableView();
  pushPath('/');
  loadAccounts();
}

async function addGroup() {
  const name = prompt(t('prompt_group_new'));
  if (!name || !name.trim()) return;
  try {
    await api.post('/api/groups', { name: name.trim() });
    await loadGroups();
    toast(t('toast_group_created'), 'success');
  } catch (e) { toast(t('toast_load_fail') + e.message, 'error'); }
}

async function doRenameGroup(oldName) {
  hideCtx();
  const name = prompt(t('prompt_group_rename'), oldName);
  if (!name || !name.trim() || name === oldName) return;
  try {
    await api.put('/api/groups/' + encodeURIComponent(oldName), { new_name: name.trim() });
    if (S.currentGroup === oldName) S.currentGroup = name.trim();
    await loadGroups();
    await loadAccounts();
    toast(t('toast_group_renamed'), 'success');
  } catch (e) { toast(t('toast_load_fail') + e.message, 'error'); }
}

async function doDeleteGroup(name) {
  hideCtx();
  if (!confirm(t('confirm_del_group', { name }))) return;
  try {
    await api.del('/api/groups/' + encodeURIComponent(name));
    if (S.currentGroup === name) S.currentGroup = '全部';
    await loadGroups();
    await loadAccounts();
    toast(t('toast_group_deleted'), 'success');
  } catch (e) { toast(t('toast_load_fail') + e.message, 'error'); }
}

// ───────── Accounts ─────────
async function loadAccounts() {
  const url = '/api/accounts' + (S.currentGroup !== '全部'
    ? '?group=' + encodeURIComponent(S.currentGroup) : '');

  // 账号列表 与 接码白名单 id 互不依赖，并行发请求把 RTT 压到 max(t1, t2)
  // 而非 t1+t2。两者中任意一个失败也不影响主表渲染（loadPublicIds 已自带兜底）。
  const [accs] = await Promise.all([
    api.get(url),
    loadPublicIds(),
  ]);
  S.accounts = accs;
  S.selected.clear();
  const selAll = $('selAll');
  if (selAll) {
    selAll.checked = false;
    selAll.indeterminate = false;
  }
  renderAccounts();
  // 顺带刷新侧边栏计数（账号变更时数字会跟着动）
  loadCounts();
}

/** 拉当前用户名下已加入接码白名单的账号 id 集合（仅站长返回非空）。 */
async function loadPublicIds() {
  if (!S.user || !S.user.is_owner) {
    S.publicIds = new Set();
    S.publicCategories = {};
    return;
  }
  try {
    const r = await api.get('/api/accounts/public-ids');
    S.publicIds = new Set(r.ids || []);
    S.publicCategories = r.categories || {};
  } catch {
    /* 网络失败时保持上次的集合，避免 UI 上忽闪忽现 */
  }
}

function tokenCategoryLabel(category) {
  if (category === 'cursor') return 'Cursor';
  if (category === 'openai') return 'GPT';
  return '';
}

function publicCategoryLabel(raw) {
  const v = String(raw || '').trim().toLowerCase();
  if (v === '*') return 'Cursor/GPT';
  if (!v) return '';
  const parts = v.split(',')
    .map((x) => x.trim())
    .filter((x) => x === 'cursor' || x === 'openai');
  return parts.map(tokenCategoryLabel).filter(Boolean).join('/');
}

function normalizeTokenEntries(value) {
  if (!value) return [];
  if (typeof value === 'string') {
    return value ? [{ category: '', token: value }] : [];
  }
  if (typeof value !== 'object') return [];
  return ['cursor', 'openai']
    .map((category) => ({ category, token: String(value[category] || '').trim() }))
    .filter((x) => x.token);
}

function tokenEntriesForAccount(account) {
  const entries = normalizeTokenEntries(account.access_tokens);
  if (entries.length) return entries;
  return normalizeTokenEntries({
    cursor: account.access_token_cursor || '',
    openai: account.access_token_openai || '',
  }).concat(
    (!account.access_token_cursor && !account.access_token_openai && account.access_token)
      ? [{ category: '', token: account.access_token }]
      : [],
  );
}

function tokenMapForAccount(account) {
  const out = { cursor: '', openai: '' };
  for (const entry of tokenEntriesForAccount(account || {})) {
    if (entry.category === 'cursor' || entry.category === 'openai') {
      out[entry.category] = entry.token;
    }
  }
  return out;
}

function tokenLinesFromResponse(tokens) {
  const lines = [];
  for (const [id, value] of Object.entries(tokens || {})) {
    const acc = S.accounts.find((x) => String(x.id) === String(id));
    const email = acc ? acc.email : '#' + id;
    if (!S.codeReceiverRequireToken) {
      lines.push(email);
      continue;
    }
    for (const entry of normalizeTokenEntries(value)) {
      lines.push(`${email}----${entry.token}`);
    }
  }
  return lines;
}

function codeLookupShareText(email, token) {
  return S.codeReceiverRequireToken && token ? `${email}----${token}` : email;
}

function choosePublicCategories() {
  const raw = prompt(t('prompt_public_categories'), '3');
  if (raw === null) return null;
  const v = String(raw || '').trim().toLowerCase();
  if (!v || v === '3' || v === 'both' || v === 'all' || v === '全部') {
    return ['cursor', 'openai'];
  }
  if (v === '1' || v === 'c' || v === 'cursor') return ['cursor'];
  if (v === '2' || v === 'g' || v === 'gpt' || v === 'openai' || v === 'chatgpt') {
    return ['openai'];
  }
  toast(t('toast_public_categories_invalid'), 'warning');
  return null;
}

function filterAccounts() {
  S.searchText = $('searchInp').value.toLowerCase();
  renderAccounts();
}

/**
 * 通用防抖 helper：延迟到最后一次调用之后 wait ms 才真正执行。
 * 用在 input 事件上，避免每敲一下键盘都把 256 行表格重建一遍。
 */
function debounce(fn, wait) {
  let h = null;
  return function (...args) {
    if (h !== null) clearTimeout(h);
    h = setTimeout(() => {
      h = null;
      fn.apply(this, args);
    }, wait);
  };
}

// 120ms 是搜索框防抖的甜区：
// - 比键盘最快的连击间隔（~80ms）略长，能合并连续输入
// - 又比"用户停顿后再敲"的等待感（>200ms）短，看起来还是即时响应
const filterAccountsDebounced = debounce(filterAccounts, 120);

function filteredAccounts() {
  return S.searchText
    ? S.accounts.filter((a) =>
        (a.email || '').toLowerCase().includes(S.searchText) ||
        (a.remark || '').toLowerCase().includes(S.searchText))
    : S.accounts;
}

// 单行渲染抽离出来供 renderAccounts 批量调用。返回构造好的 <tr>，
// 调用方负责插到 fragment / tbody 上。
//
// 与之前的"在 renderAccounts 闭包里写一大坨"相比：
// - 单一职责，方便单行重建（删除/添加 1 行无需全表重渲染）
// - 配合 DocumentFragment 批量插入，减少 256 次反复 reflow 为 1 次
function buildAccountRow(a, index, isOwner) {
  const tr = el('tr', {
    class: S.selected.has(a.id) ? 'selected' : '',
    dataset: { id: a.id },
  });

  const cb = el('input', { type: 'checkbox' });
  cb.checked = S.selected.has(a.id);
  cb.addEventListener('change', () => toggleSel(a.id, cb.checked));
  tr.appendChild(el('td', { class: 'sel-cell' }, cb));
  tr.appendChild(el('td', {}, String(index + 1)));

  // 邮箱单击复制邮箱、双击复制 邮箱----密码；查看详情走操作列的"详情"按钮
  let emailClickTimer = null;
  const emailText = el('span', {
    class: 'email-t',
    title: t('email_click_hint', { email: a.email }),
    onclick: () => {
      clearTimeout(emailClickTimer);
      emailClickTimer = setTimeout(() => {
        copyText(a.email, 'toast_copied_email');
      }, 220);
    },
    ondblclick: () => {
      clearTimeout(emailClickTimer);
      copyText(`${a.email}----${a.password || ''}`, 'toast_copied_email_pwd');
    },
  }, a.email);
  tr.appendChild(el('td', {}, el('div', { class: 'email-cell' }, emailText)));

  const pwdCell = el('div', { class: 'pwd-cell' });
  const pwdSpan = el('span', { class: 'pwd-t' }, '••••••');
  let shown = false;
  pwdCell.appendChild(pwdSpan);
  const showBtn = el('button', {
    onclick: () => {
      shown = !shown;
      pwdSpan.textContent = shown ? a.password : '••••••';
      showBtn.textContent = t(shown ? 'btn_hide' : 'btn_show');
    }
  }, t('btn_show'));
  pwdCell.appendChild(showBtn);
  pwdCell.appendChild(el('button', {
    'aria-label': t('op_copy_pwd_aria'),
    onclick: () => copyText(a.password)
  }, t('btn_copy')));
  tr.appendChild(el('td', {}, pwdCell));

  tr.appendChild(el('td', {}, a.group || ''));

  const statusCls = a.status === '正常' ? 'badge-ok' : a.status === '异常' ? 'badge-err' : 'badge-unk';
  tr.appendChild(el('td', {}, el('span', { class: 'badge ' + statusCls }, a.status)));
  tr.appendChild(el('td', {}, a.type || ''));
  tr.appendChild(el('td', {}, a.has_aws_code
    ? el('span', { style: 'color:var(--success)' }, t('d_yes')) : '-'));

  // 接码列（仅站长可见，与表头 .col-public 一一对应）
  if (isOwner) {
    const isPub = S.publicIds.has(a.id);
    const catLabel = isPub ? publicCategoryLabel(S.publicCategories[a.id]) : '';
    const badge = el(
      'span',
      { class: isPub ? 'public-badge' : 'private-badge' },
      isPub && catLabel ? `${t('public_yes')}·${catLabel}` : (
        isPub ? t('public_yes') : t('public_no')
      ),
    );
    tr.appendChild(el('td', { class: 'col-public' }, badge));

    // 凭证列（仅站长可见，与表头 .col-token 一一对应）
    tr.appendChild(el('td', { class: 'col-token' }, buildTokenCell(a)));
  }

  const tdRemark = el('td', { title: a.remark || '', ondblclick: () => editRemark(a.id, a.remark || '') });
  if (a.remark) tdRemark.textContent = a.remark;
  else tdRemark.appendChild(el('span', { style: 'color:var(--text3);font-size:11px' }, t('remark_double_click')));
  tr.appendChild(tdRemark);

  const ops = el('div', { class: 'op-btns' });

  // 帮助器：构造圆形 emoji 按钮（参考 cursor-manager 的 .btn-icon 风格）
  const mkIco = (icon, cls, titleKey, onclick, extra = {}) => el('button', Object.assign({
    class: `row-ico-btn ${cls}`,
    title: t(titleKey),
    'aria-label': t(titleKey),
    onclick,
  }, extra), icon);

  // ── 高频按钮（所有用户都看得到） ──────────────────────────────
  // 📋 复制完整账号串（兼容旧 op_copy_full_* i18n key）
  ops.appendChild(mkIco('📋', 'ico-copy', 'op_copy_full_hint', async () => {
    await ensureAccountRefreshToken(a);
    const { text, dirty } = buildAccountFullString(a);
    copyText(text, 'toast_copied_full', {
      warningKey: dirty ? 'toast_copied_field_sanitized' : null,
    });
  }));

  // ✉ 查看邮件
  ops.appendChild(mkIco('✉', 'ico-view', 'btn_view', () => viewEmails(a.id)));

  // ── 站长专属：4 个 Helper 行内按钮（圆形 + 彩色渐变） ───────────
  if (S.user && S.user.is_owner) {
    ops.appendChild(mkIco('📬', 'ico-h-open owner-only', 'help_row_open',
      () => triggerHelperRowAction(helperRowOpen, a, 'help_row_open')));
    ops.appendChild(mkIco('🔑', 'ico-h-tok owner-only', 'help_row_get_token',
      () => triggerHelperRowAction(helperRowGetToken, a, 'help_row_get_token')));
    ops.appendChild(mkIco('🔒', 'ico-h-pwd owner-only', 'help_row_chpwd',
      () => triggerHelperRowAction(helperRowChpwd, a, 'help_row_chpwd')));
    ops.appendChild(mkIco('🛡️', 'ico-h-bind owner-only', 'help_row_bind',
      () => triggerHelperRowAction(helperRowBind, a, 'help_row_bind')));
  }

  // 📝 备注（点开等同于双击备注列）
  ops.appendChild(mkIco('📝', 'ico-remark', 'op_remark_edit',
    () => editRemark(a.id, a.remark || '')));

  // ⋯ 更多下拉（详情 / 接码切换 / 复制邮箱 / 复制密码）
  const moreWrap = el('div', { class: 'row-more-wrap' });
  const moreBtn = mkIco('⋯', 'ico-more', 'op_more', (ev) => {
    ev.stopPropagation();
    showRowMoreMenu(moreBtn, a);
  });
  moreWrap.appendChild(moreBtn);
  ops.appendChild(moreWrap);

  // ✕ 删除（保留红色危险按钮）
  ops.appendChild(mkIco('✕', 'ico-del', 'btn_del', () => deleteSingle(a.id)));

  tr.appendChild(el('td', {}, ops));

  return tr;
}

// ── 行内「⋯ 更多」下拉菜单 ─────────────────────────────────────
//
// 设计：参考 cursor-manager `.more-dropdown-menu`，点击 ⋯ 按钮后 fixed 定位
// 在按钮下方；菜单项命中 click / Esc / 外部点击都会自动关闭。
// 不预渲染（每个 row 一个 div 占内存），用全局复用的 #rowMoreMenu。
function showRowMoreMenu(anchorBtn, account) {
  let menu = document.getElementById('rowMoreMenu');
  if (!menu) {
    menu = document.createElement('div');
    menu.id = 'rowMoreMenu';
    menu.className = 'row-more-menu';
    document.body.appendChild(menu);
  }
  clear(menu);

  const items = [];
  items.push({
    icon: '📋', label: t('op_detail'),
    onclick: () => showDetail(account.id),
  });
  items.push({
    icon: '✎', label: t('op_edit_credentials'),
    onclick: () => showCredentialsModal(account),
  });
  items.push({
    icon: '🆔', label: t('op_copy_email'),
    onclick: () => copyText(account.email, 'toast_copied_email'),
  });
  items.push({
    icon: '🔑', label: t('op_copy_pwd'),
    onclick: () => copyText(account.password || '', 'toast_copied'),
  });
  // 站长专属：单条加入 / 移出接码
  if (S.user && S.user.is_owner) {
    const isPub = S.publicIds.has(account.id);
    items.push({
      icon: isPub ? '📴' : '📡',
      label: isPub ? t('op_unset_public_single') : t('op_set_public_single'),
      onclick: () => toggleSinglePublic(account, !isPub),
    });
  }

  for (const it of items) {
    const btn = el('button', {
      class: 'row-more-item',
      onclick: () => {
        closeRowMoreMenu();
        try { it.onclick(); } catch (e) { console.error(e); }
      },
    }, [
      el('span', { class: 'row-more-icon' }, it.icon),
      el('span', { class: 'row-more-label' }, it.label),
    ]);
    menu.appendChild(btn);
  }

  // fixed 定位到 anchor 下方；按钮右对齐避免溢出右边界
  const r = anchorBtn.getBoundingClientRect();
  menu.style.display = 'block';
  // 先 display 出来才有正确尺寸；offset 后用 setTimeout 避免布局抖动
  const mw = menu.offsetWidth || 200;
  let left = r.left;
  if (left + mw > window.innerWidth - 8) left = window.innerWidth - mw - 8;
  menu.style.left = `${left}px`;
  menu.style.top = `${r.bottom + 4}px`;

  // 外部点击 / Esc 关闭：用持续监听 + close 时移除（不能 once: true，
  // 否则用户点到菜单内"消耗"了监听后，再点外面就关不掉了）
  // setTimeout 0 让"打开菜单的那次 click 冒泡"先结束，避免立刻自关
  setTimeout(_attachRowMoreOutsideHandlers, 0);
}

function _attachRowMoreOutsideHandlers() {
  document.addEventListener('click', _closeRowMoreMenuOnOutsideClick, true);
  document.addEventListener('keydown', _closeRowMoreMenuOnEsc);
}

function _detachRowMoreOutsideHandlers() {
  document.removeEventListener('click', _closeRowMoreMenuOnOutsideClick, true);
  document.removeEventListener('keydown', _closeRowMoreMenuOnEsc);
}

function _closeRowMoreMenuOnOutsideClick(e) {
  const menu = document.getElementById('rowMoreMenu');
  if (!menu || menu.style.display === 'none') return;
  if (menu.contains(e.target)) return;
  closeRowMoreMenu();
}

function _closeRowMoreMenuOnEsc(e) {
  if (e.key === 'Escape') closeRowMoreMenu();
}

function closeRowMoreMenu() {
  const menu = document.getElementById('rowMoreMenu');
  if (menu) menu.style.display = 'none';
  _detachRowMoreOutsideHandlers();
}

// 单条加入 / 移出接码（复用 batchSetPublic 的后端，传单个 id）
async function toggleSinglePublic(account, isPublic) {
  if (!S.user || !S.user.is_owner) return;
  const allowedCategories = isPublic ? choosePublicCategories() : null;
  if (isPublic && !allowedCategories) return;
  try {
    const r = await api.post('/api/accounts/set-public', {
      ids: [account.id],
      is_public: !!isPublic,
      allowed_categories: allowedCategories || undefined,
    });
    toast(t(isPublic ? 'toast_set_public_ok' : 'toast_unset_public_ok',
            { n: 1 }), 'success');
    await loadPublicIds();
    await loadAccounts();
    // 后端为新公开账号自动生成 token；返回里有就弹一个让站长马上看到/复制
    if (r && r.tokens && Object.keys(r.tokens).length > 0) {
      const lines = tokenLinesFromResponse(r.tokens);
      showTokenModal(lines, { fresh: true });
    }
  } catch (e) {
    toast(t('toast_load_fail') + (e?.message || ''), 'error');
  }
}

/* ── 接码凭证：渲染表格凭证单元格 + 单条旋转 + 批量旋转 ─────────
 *
 * 设计原则
 * --------
 * - 凭证明文仅在站长侧的内存里短暂存在；接码端拿到 token 后会立即 wipe
 * - 旋转 / 复制按钮只对当前用户=站长可见，UI 上的隐藏已由 .col-token[hidden] 控制
 * - "邮箱----凭证"是分发给下游的标准串，单条"复制 邮箱----凭证"按钮一键完成
 */

function buildTokenCell(account) {
  const wrap = el('span', { class: 'token-cell' });
  const entries = tokenEntriesForAccount(account);
  if (!entries.length) {
    wrap.appendChild(el('span', { class: 'token-empty' }, t('token_empty')));
  } else {
    for (const entry of entries) {
      const label = tokenCategoryLabel(entry.category);
      const item = el('span', { class: 'token-entry' });
      if (label) item.appendChild(el('span', { class: 'token-label' }, label));
      item.appendChild(el('span', { class: 'token-text', title: entry.token }, entry.token));
      item.appendChild(el('button', {
        type: 'button',
        title: t('token_copy_hint'),
        'aria-label': t('token_copy_hint'),
        onclick: () => copyText(
          codeLookupShareText(account.email, entry.token),
          S.codeReceiverRequireToken ? 'toast_token_copied' : 'toast_copied_email',
        ),
      }, '📋'));
      wrap.appendChild(item);
    }
  }
  wrap.appendChild(el('button', {
    type: 'button',
    title: t('token_rotate_hint'),
    'aria-label': t('token_rotate_hint'),
    onclick: () => rotateSingleToken(account),
  }, '🔄'));
  return wrap;
}

async function rotateSingleToken(account) {
  if (!S.user || !S.user.is_owner) return;
  if (!confirm(t('confirm_rotate_single', { email: account.email }))) return;
  try {
    const r = await api.post(`/api/accounts/${account.id}/rotate-token`, {});
    const entries = normalizeTokenEntries(r && (r.access_tokens || r.access_token));
    if (!entries.length) {
      toast(t('toast_load_fail'), 'error');
      return;
    }
    toast(t('toast_token_rotated', { email: account.email }), 'success');
    // 刷新列表让新 token 显示出来；同时弹出一个含分享串的弹窗便于站长复制
    await loadAccounts();
    showTokenModal(
      S.codeReceiverRequireToken
        ? entries.map((entry) => codeLookupShareText(account.email, entry.token))
        : [account.email],
      { fresh: true },
    );
  } catch (e) {
    toast(t('toast_load_fail') + (e?.message || ''), 'error');
  }
}

async function batchRotateTokens() {
  if (!S.user || !S.user.is_owner) return;
  const ids = [...S.selected];
  if (!ids.length) { toast(t('toast_select_acc'), 'warning'); return; }
  if (!confirm(t('confirm_rotate_n', { n: ids.length }))) return;
  try {
    // only_public=true：仅旋转已加入接码的账号；其它默默跳过
    // （未公开的账号生成 token 也没意义——前台 lookup 在 is_public=1 处就过不去）
    const r = await api.post('/api/accounts/rotate-tokens-bulk', {
      ids,
      only_public: true,
    });
    const tokens = r && r.tokens ? r.tokens : {};
    const count = Object.keys(tokens).length;
    if (!count) {
      toast(t('toast_rotate_none'), 'warning');
      return;
    }
    toast(t('toast_rotate_ok', { n: count }), 'success');
    await loadAccounts();
    const lines = tokenLinesFromResponse(tokens);
    showTokenModal(lines, { fresh: true });
  } catch (e) {
    toast(t('toast_load_fail') + (e?.message || ''), 'error');
  }
}

function showTokenModal(lines, opts) {
  opts = opts || {};
  const ta = $('tokenList');
  if (!ta) return;
  ta.value = (lines || []).join('\n');
  const intro = $('tokenModalIntro');
  if (intro) {
    intro.textContent = S.codeReceiverRequireToken
      ? t('modal_token_intro')
      : t('modal_token_intro_disabled');
  }
  const label = $('tokenListLabel');
  if (label) {
    label.textContent = S.codeReceiverRequireToken
      ? t('modal_token_list')
      : t('modal_token_list_disabled');
  }
  openModal('tokenModal');
  // 自动 focus 文本框 + 全选，方便键盘党直接 Ctrl+C
  setTimeout(() => {
    try { ta.focus(); ta.select(); } catch (_) {}
  }, 50);
}

// ── 表格行的 helper 操作（xiaoxuan 专属） ────────────────────

function triggerHelperRowAction(fn, account, titleKey) {
  // helper 状态用最新值判断；如果还没拉过状态，主动拉一次
  if (!window.HELPER_STATUS || !window.HELPER_STATUS.loaded) {
    refreshHelperStatus().then(() => triggerHelperRowAction(fn, account, titleKey));
    return;
  }
  if (!window.HELPER_STATUS.online) {
    toast(t('help_task_offline'), 'warning');
    return;
  }
  fn(account, titleKey);
}

// ── 单条 helper 操作 SSE 公共流程 ───────────────────────────────
//
// 设计动机
// --------
// 单条改密 / 绑辅助 / 取 Token 可以跑到 5 分钟，但 Cloudflare Free/Pro 套餐
// **默认 100s 就 524 死页**（用户也确实截到了 ``mail.evuzdnd.cn | 524``）。
// 同步 ``POST /api/helper/mailbox/*`` 会在 100s 处被拦截。
//
// 改用 ``POST /api/helper/batch/mailbox`` SSE 端点 + ``account_ids=[id]``
// 单条调用：SSE 流持续吐 progress 事件，Cloudflare 看到字节流就不 524；
// 后端 batch_mailbox 已支持 ``bind_recovery_email`` / ``change_email_password``
// 以及 action-specific 字段（alias_suffix / alias_email / new_password）。
//
// onSuccess 回调在 progress=success=true 时触发，用于行内成功后的副作用
// （比如取 Token 后刷新账号列表）。
async function runHelperSingleSse(action, accountId, extraParams, titleKey,
                                  onSuccess, opts = {}) {
  openHelperTaskModal(titleKey);
  const intro = opts.intro || `▶ SSE 派发 → ${action} → account_id=${accountId}`;
  appendHelperLog(intro, 'info');
  let okFinal = false;
  let errFinal = '';
  let emailFinal = '';
  try {
    const body = Object.assign(
      { action, account_ids: [accountId], timeout: 300 },
      extraParams || {},
    );
    await api.stream('/api/helper/batch/mailbox', body, (msg) => {
      if (msg.type === 'progress') {
        emailFinal = msg.email || '';
        okFinal = !!msg.success;
        errFinal = msg.error || '';
        if (msg.success) {
          appendHelperLog(`✓ ${msg.email} 操作完成`, 'success');
        } else {
          appendHelperLog(`✗ ${msg.email}: ${msg.error || '失败'}`,
                          msg.needs_helper_upgrade ? 'warning' : 'error');
          if (msg.needs_helper_upgrade) {
            appendHelperLog(
              '⚠ 本机 Helper 版本过低，请到「📥 下载」处更新',
              'warning',
            );
          }
        }
        // helper 操作成功但服务端写回 DB 失败 —— 改密 / get_ms_token 这类
        // 的灾难性边角：邮箱端密码 / refresh_token 已变，DB 没跟上，下次
        // 自动登录用旧凭据 → Outlook 风控锁号。必须显眼提醒用户手工修复。
        if (msg.db_update_failed) {
          appendHelperLog(
            `⚠ Helper 操作成功，但服务端写回 DB 失败：${msg.db_update_failed}` +
            `。请到「账号」页面手工修正该账号的对应字段后再继续，` +
            `否则下次自动登录会被风控拦下。`,
            'warning',
          );
          toast(
            'Helper 成功但 DB 未同步，请手工核对账号字段（见任务日志）',
            'warning',
          );
        }
      } else if (msg.type === 'done') {
        if (okFinal) {
          setHelperTaskDone(true, opts.successMsg || '');
          try { onSuccess && onSuccess({ email: emailFinal }); } catch { /* ignore */ }
        } else {
          setHelperTaskDone(false, errFinal);
        }
      }
    });
  } catch (e) {
    setHelperTaskDone(false, e.message || '');
  } finally {
    setTimeout(closeHelperLogStream, 2000);
  }
}

async function helperRowOpen(account, titleKey) {
  return runHelperSingleSse(
    'open_mailbox', account.id, {}, titleKey,
    () => toast(t('toast_help_open_ok', { email: account.email }), 'success'),
    { intro: `▶ 请求服务器派发 "登录邮箱" → ${account.email}（SSE）` },
  );
}

async function helperRowGetToken(account, titleKey) {
  return runHelperSingleSse(
    'get_ms_token', account.id, {}, titleKey,
    () => {
      toast(t('toast_help_updated', { email: account.email }), 'success');
      loadAccounts();
    },
    { intro: `▶ 请求服务器派发 "获取 refresh_token" → ${account.email}（SSE）` },
  );
}

function helperRowChpwd(account, titleKey) {
  // 行内改密 = 直接弹小框只问新密码（旧密码后端从 DB 自动取）
  $('helperChpwdEmail').value = account.email;
  $('helperChpwdOld').value = '__from_db__';  // 仅占位，后端会忽略并从 DB 取
  $('helperChpwdNew').value = '';
  $('helperChpwdErr').textContent = '';
  $('helperChpwdEmail').dataset.accountId = String(account.id);
  $('helperChpwdEmail').dataset.titleKey = titleKey || 'help_btn_chpwd';
  openModal('helperChangePwdModal');
}

// 全局缓存：避免每次点 🛡 都查一次 imap-config
window._IMAP_CFG_CACHE = window._IMAP_CFG_CACHE || null;

async function ensureRecoverySuffixConfigured() {
  // 已有缓存且 suffix 非空 → 直接通过
  if (window._IMAP_CFG_CACHE && (window._IMAP_CFG_CACHE.recovery_alias_suffix || '').trim()) {
    return true;
  }
  try {
    const r = await api.get('/api/helper/imap-config', { timeoutMs: HELPER_IMAP_FETCH_TIMEOUT_MS });
    window._IMAP_CFG_CACHE = r || {};
    if ((r.recovery_alias_suffix || '').trim()) return true;
  } catch (e) {
    // 拉不到就让用户继续走（modal 内部填 suffix 也能绑）
    return true;
  }
  // suffix 空 → 提示并跳到 Help 页 IMAP 卡片
  toast(t('toast_help_need_suffix'), 'warning');
  if (S.user && S.user.is_owner) {
    showView('help');
    setTimeout(() => {
      const el = $('helpImapBody');
      if (el && el.scrollIntoView) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      const inp = $('imapSuffix');
      if (inp) inp.focus();
    }, 250);
  }
  return false;
}

async function helperRowBind(account, titleKey) {
  // 没配 catch-all 后缀 → 引导到 Help 页 IMAP 卡片再回来
  const ok = await ensureRecoverySuffixConfigured();
  if (!ok) return;
  $('helperBindEmail').value = account.email;
  $('helperBindSuffix').value = '';
  $('helperBindAlias').value = '';
  $('helperBindErr').textContent = '';
  $('helperBindEmail').dataset.accountId = String(account.id);
  $('helperBindEmail').dataset.titleKey = titleKey || 'help_btn_bind';
  openModal('helperBindRecoveryModal');
}

function renderAccounts() {
  const list = filteredAccounts();
  $('recCnt').textContent = t('record_count', { n: list.length });
  const tb = $('accBody');
  clear(tb);

  // 站长会多出"接码"一列；空状态行的 colspan 也要相应调整（基础 10 列）
  const isOwner = !!(S.user && S.user.is_owner);
  const colSpan = isOwner ? 11 : 10;

  if (!list.length) {
    tb.appendChild(el('tr', {}, el('td', {
      colspan: colSpan,
      style: 'text-align:center;padding:40px;color:var(--text3)'
    }, t('empty'))));
    syncSelAllCheckbox();
    return;
  }

  // DocumentFragment 把 N 次 appendChild 合并成 1 次 DOM 写入：
  // - 浏览器只在最后 tb.appendChild(frag) 时做一次 reflow / paint
  // - N=256 实测从 ~30ms 降到 ~5ms（与机器/CPU 强相关，但比例稳定）
  // - 也减少了"渲染过程中触发 IntersectionObserver / mutation 监听"的边际成本
  const frag = document.createDocumentFragment();
  for (let i = 0; i < list.length; i++) {
    frag.appendChild(buildAccountRow(list[i], i, isOwner));
  }
  tb.appendChild(frag);
  syncSelAllCheckbox();
}

/** 找到给定 id 的 <tr>。表格不大时直接 querySelector 足够快，无需建 id→tr 映射。 */
function findAccountRow(id) {
  return $('accBody').querySelector(`tr[data-id="${id}"]`);
}

/** 把单行的视觉态（class=selected + checkbox.checked）同步到 DOM。 */
function applySelToRow(tr, sel) {
  if (!tr) return;
  if (sel) tr.classList.add('selected');
  else tr.classList.remove('selected');
  const cb = tr.querySelector('input[type="checkbox"]');
  if (cb) cb.checked = sel;
}

/**
 * 头部"全选"checkbox 的 indeterminate / checked 三态显示。
 *
 * - 当前可见行 0 条：全选不勾选、不半选
 * - 全部可见行都已选：勾选
 * - 部分可见行已选：indeterminate（半选）
 *
 * 这样行级更新（toggleSel）后头部 UI 不会出现"明明都勾完了还显示未勾"的错位。
 */
function syncSelAllCheckbox() {
  const cb = $('selAll');
  if (!cb) return;
  const visible = filteredAccounts();
  if (!visible.length) {
    cb.checked = false;
    cb.indeterminate = false;
    return;
  }
  let selectedCnt = 0;
  for (const a of visible) if (S.selected.has(a.id)) selectedCnt++;
  cb.checked = selectedCnt === visible.length;
  cb.indeterminate = selectedCnt > 0 && selectedCnt < visible.length;
}

function toggleSelAll(checked) {
  const visible = filteredAccounts();
  if (checked) visible.forEach((a) => S.selected.add(a.id));
  else visible.forEach((a) => S.selected.delete(a.id));
  // 增量更新当前可见的每一行视觉态，避免 256 行整体重建（仅 N 次轻量
  // classList 切换 + checkbox.checked 赋值，不动其它 DOM）
  for (const a of visible) {
    applySelToRow(findAccountRow(a.id), S.selected.has(a.id));
  }
  syncSelAllCheckbox();
}

function toggleSel(id, checked) {
  if (checked) S.selected.add(id); else S.selected.delete(id);
  // 单行级更新：只动这一行的 class/checkbox，不重建表格
  applySelToRow(findAccountRow(id), checked);
  syncSelAllCheckbox();
}

let accountSelectionDrag = null;
let suppressAccountSelectionClick = false;

function accountIdFromRow(tr) {
  if (!tr || !tr.dataset) return null;
  const raw = tr.dataset.id;
  if (raw == null || raw === '') return null;
  const n = Number(raw);
  return Number.isSafeInteger(n) ? n : raw;
}

function accountSelectionRowFromTarget(target) {
  const row = target && target.closest ? target.closest('#accBody tr[data-id]') : null;
  return row && $('accBody') && $('accBody').contains(row) ? row : null;
}

function accountSelectionHandleFromTarget(target) {
  const handle = target && target.closest ? target.closest('td.sel-cell') : null;
  return handle && $('accBody') && $('accBody').contains(handle) ? handle : null;
}

function applyAccountSelectionDragToRow(row) {
  if (!accountSelectionDrag || !row) return;
  const id = accountIdFromRow(row);
  if (id == null) return;
  const key = String(id);
  if (accountSelectionDrag.seen.has(key)) return;
  accountSelectionDrag.seen.add(key);
  toggleSel(id, accountSelectionDrag.checked);
}

function startAccountSelectionDrag(e) {
  if (e.button != null && e.button !== 0) return;
  if (!accountSelectionHandleFromTarget(e.target)) return;

  const row = accountSelectionRowFromTarget(e.target);
  const id = accountIdFromRow(row);
  if (id == null) return;

  e.preventDefault();
  suppressAccountSelectionClick = true;

  accountSelectionDrag = {
    checked: !S.selected.has(id),
    pointerId: e.pointerId,
    seen: new Set(),
  };
  document.body.classList.add('account-selection-dragging');

  const cb = row.querySelector('input[type="checkbox"]');
  if (cb && cb.focus) {
    try { cb.focus({ preventScroll: true }); } catch (_) { cb.focus(); }
  }
  applyAccountSelectionDragToRow(row);

  document.addEventListener('pointermove', continueAccountSelectionDrag, { passive: false });
  document.addEventListener('pointerup', stopAccountSelectionDrag, true);
  document.addEventListener('pointercancel', stopAccountSelectionDrag, true);
}

function continueAccountSelectionDrag(e) {
  if (!accountSelectionDrag) return;
  if (e.pointerId !== accountSelectionDrag.pointerId) return;
  e.preventDefault();
  const target = document.elementFromPoint(e.clientX, e.clientY);
  applyAccountSelectionDragToRow(accountSelectionRowFromTarget(target));
}

function stopAccountSelectionDrag(e) {
  if (!accountSelectionDrag) return;
  if (e && e.pointerId !== accountSelectionDrag.pointerId) return;
  accountSelectionDrag = null;
  document.body.classList.remove('account-selection-dragging');
  document.removeEventListener('pointermove', continueAccountSelectionDrag);
  document.removeEventListener('pointerup', stopAccountSelectionDrag, true);
  document.removeEventListener('pointercancel', stopAccountSelectionDrag, true);
  setTimeout(() => { suppressAccountSelectionClick = false; }, 250);
}

function swallowAccountSelectionClick(e) {
  if (!suppressAccountSelectionClick) return;
  if (!accountSelectionHandleFromTarget(e.target)) return;
  e.preventDefault();
  e.stopPropagation();
  suppressAccountSelectionClick = false;
}

/**
 * 把字符串里的 CR/LF 与 ``----`` 序列剥离，避免它们污染按 ``----`` 分隔的
 * 一行导入串。
 * - ``\r`` / ``\n`` 出现在密码 / refresh_token 中时罕见但可能（导入时容错），
 *   留在复制串里会让回导入解析错位甚至变成多账号
 * - ``----`` 是字段分隔符；字段内含它就破坏导入语义
 *
 * 返回 ``[cleaned, dirty]``：dirty 为 true 表示真的清理过，调用方可
 * 用提示用户复制内容已被修正。
 */
function sanitizeImportField(s) {
  const raw = String(s || '');
  if (!raw) return [raw, false];
  let cleaned = raw.replace(/[\r\n]+/g, ' ');
  cleaned = cleaned.split('----').join('-­-­-­-');  // 软连字号占位，肉眼难辨但分隔符语义打破
  return [cleaned, cleaned !== raw];
}

/**
 * 用 ``navigator.clipboard`` 写剪贴板，HTTP 局域网 / 旧浏览器不可用时回退
 * 到 ``document.execCommand('copy')`` 兜底。失败显式 toast。
 *
 * ``opts.warningKey`` 不空时表示"复制成功但内容被修正过"，用 warning 类型 toast
 * 替代 success（让用户看见修正提醒）。
 */
function copyText(text, toastKey = 'toast_copied', opts = {}) {
  const value = String(text == null ? '' : text);
  const successToast = () => {
    if (opts.warningKey) toast(t(opts.warningKey), 'warning');
    else toast(t(toastKey), 'success');
  };
  const failToast = () => toast(t('toast_clip_fail'), 'error');

  // 路径 1：现代 Clipboard API（仅 secure context 可用）
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(value).then(successToast, () => {
      if (!_copyTextFallback(value)) failToast();
      else successToast();
    });
    return;
  }
  // 路径 2：execCommand 兜底（HTTP/局域网部署）
  if (_copyTextFallback(value)) successToast();
  else toast(t('toast_clip_fallback_failed'), 'error');
}

function _copyTextFallback(value) {
  // execCommand('copy') 已被 W3C 标记 deprecated，但所有现役桌面浏览器还在用；
  // 主路径用 navigator.clipboard，这里仅作 HTTP 部署的兜底。
  try {
    const ta = document.createElement('textarea');
    ta.value = value;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand && document.execCommand('copy');
    document.body.removeChild(ta);
    return !!ok;
  } catch {
    return false;
  }
}

/**
 * 构造账号一键复制串：
 *   普通账号       -> email----password
 *   OAuth2 账号    -> email----password----client_id----refresh_token
 *
 * 旧实现仅当 ``client_id && refresh_token`` 同时存在时才输出 4 段；只有其中
 * 一个时另一个被静默丢弃。新版"任一存在就用空字符串占位补足 4 段"，避免
 * 数据丢失，代价是回导入时遇到含空字段的 4 段需要识别为半成品。
 *
 * 同时 sanitize 字段内的换行 / ``----`` 序列，避免污染分隔结构（详见
 * ``sanitizeImportField``）。``dirty`` 表示是否做过实际修正，调用方
 * 可以用 warning toast 提示用户。
 *
 * 返回 ``{text, dirty}``。
 */
function buildAccountFullString(a) {
  const fields = [a.email || '', a.password || ''];
  if (a.client_id || a.refresh_token) {
    fields.push(a.client_id || '');
    fields.push(a.refresh_token || '');
  }
  let dirty = false;
  const cleaned = fields.map((s) => {
    const [c, d] = sanitizeImportField(s);
    if (d) dirty = true;
    return c;
  });
  return { text: cleaned.join('----'), dirty };
}

/**
 * 列表 /api/accounts 响应不再包含 refresh_token（节省体积、降低明文驻留）。
 * 「复制完整」按钮和需要 refresh_token 的场景，调用此函数补齐：
 * - 已经有 refresh_token / 不是 OAuth2 账号 → 直接返回原对象
 * - 只有 client_id 缺 refresh_token → 走 /api/accounts/{id} 拉一次完整数据，
 *   合并到列表里的对象（同 id 后续点击直接复用）
 *
 * 失败时返回原对象、不抛异常 —— 调用方拿到的就是"refresh_token 为空"的
 * 半成品串，与旧版任一字段缺失的退化行为一致，UX 不会比之前更差。
 */
async function ensureAccountRefreshToken(a) {
  if (!a) return a;
  if (a.refresh_token || !a.client_id) return a;
  try {
    const full = await api.get(`/api/accounts/${a.id}`);
    a.refresh_token = full.refresh_token || '';
    return a;
  } catch {
    return a;
  }
}

async function editRemark(id, oldVal) {
  const val = prompt(t('prompt_remark'), oldVal);
  if (val === null) return;
  await api.put(`/api/accounts/${id}/remark`, { remark: val });
  await loadAccounts();
  toast(t('toast_remark_saved'), 'success');
}

async function showCredentialsModal(account) {
  try {
    const a = await api.get(`/api/accounts/${account.id}`);
    $('credAccountId').value = a.id;
    $('credEmail').value = a.email || '';
    $('credPassword').value = a.password || '';
    $('credClientId').value = a.client_id || '';
    $('credRefreshToken').value = a.refresh_token || '';
    const tokenGroup = $('credCodeTokenGroup');
    if (tokenGroup) {
      tokenGroup.style.display = S.user && S.user.is_owner ? '' : 'none';
      const tokens = tokenMapForAccount(a);
      $('credTokenCursor').value = tokens.cursor || '';
      $('credTokenOpenai').value = tokens.openai || '';
    }
    $('credErr').textContent = '';
    openModal('credentialsModal');
    setTimeout(() => {
      try { $('credPassword').focus(); } catch (_) {}
    }, 50);
  } catch (e) {
    toast(t('toast_load_fail') + (e?.message || ''), 'error');
  }
}

async function saveCredentials() {
  const id = Number($('credAccountId').value || 0);
  if (!id) return;
  const body = {
    password: $('credPassword').value,
    client_id: $('credClientId').value.trim() || null,
    refresh_token: $('credRefreshToken').value.trim() || null,
  };
  const hasClient = !!body.client_id;
  const hasRefresh = !!body.refresh_token;
  const errEl = $('credErr');
  errEl.textContent = '';
  if (hasClient !== hasRefresh) {
    errEl.textContent = t('credentials_oauth_pair_required');
    return;
  }
  try {
    if (S.user && S.user.is_owner && $('credCodeTokenGroup').style.display !== 'none') {
      await api.put(`/api/accounts/${id}/access-tokens`, {
        access_tokens: {
          cursor: $('credTokenCursor').value.trim(),
          openai: $('credTokenOpenai').value.trim(),
        },
      });
    }
    await api.put(`/api/accounts/${id}/credentials`, body);
    closeModal('credentialsModal');
    await loadAccounts();
    toast(t('toast_credentials_saved'), 'success');
  } catch (e) {
    errEl.textContent = e?.message || t('toast_load_fail');
  }
}

async function deleteSingle(id) {
  if (!confirm(t('confirm_del_one'))) return;
  await api.post('/api/accounts/delete', { ids: [id] });
  await loadAccounts();
  toast(t('toast_del_ok'), 'success');
}

async function deleteSelected() {
  const ids = [...S.selected];
  if (!ids.length) { toast(t('toast_select_acc'), 'warning'); return; }
  if (!confirm(t('confirm_del_n', { n: ids.length }))) return;
  await api.post('/api/accounts/delete', { ids });
  await loadAccounts();
  toast(t('toast_del_ok'), 'success');
}

/**
 * 批量加入 / 移出接码白名单（仅站长）。
 * is_public=true → 加入；false → 移出。
 *
 * 服务端会做 username==CODE_OWNER_USERNAME 的二次校验，普通用户即使
 * 通过 DevTools 调出按钮也会被 403 拦下。
 */
async function batchSetPublic(isPublic) {
  if (!S.user || !S.user.is_owner) return;  // UI 兜底；正常情况下按钮已隐藏
  const ids = [...S.selected];
  if (!ids.length) { toast(t('toast_select_acc'), 'warning'); return; }
  const confirmKey = isPublic ? 'confirm_set_public_n' : 'confirm_unset_public_n';
  if (!confirm(t(confirmKey, { n: ids.length }))) return;
  const allowedCategories = isPublic ? choosePublicCategories() : null;
  if (isPublic && !allowedCategories) return;
  try {
    const r = await api.post('/api/accounts/set-public', {
      ids,
      is_public: !!isPublic,
      allowed_categories: allowedCategories || undefined,
    });
    const okKey = isPublic ? 'toast_set_public_ok' : 'toast_unset_public_ok';
    toast(t(okKey, { n: r.updated || 0 }), 'success');
    await loadPublicIds();
    // is_public=True 时后端会顺手给"尚无 token"的账号生成新凭证，刷新账号让 token 列更新
    if (isPublic) await loadAccounts();
    else renderAccounts();
    // 后端有新生成的 token 时弹一个含分享串的窗口
    if (isPublic && r.tokens && Object.keys(r.tokens).length > 0) {
      const lines = tokenLinesFromResponse(r.tokens);
      showTokenModal(lines, { fresh: true });
    }
  } catch (e) {
    toast(t('toast_load_fail') + (e?.message || ''), 'error');
  }
}

// ───────── Import ─────────
function showImportModal() {
  $('importText').value = '';
  const sel = $('importGroup');
  clear(sel);
  for (const g of S.groups) {
    const opt = el('option', {}, g.name);
    if (g.name === S.currentGroup && S.currentGroup !== '全部') opt.selected = true;
    sel.appendChild(opt);
  }
  openModal('importModal');
}

async function importFromClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    if (text) $('importText').value = text;
    else toast(t('toast_clip_empty'), 'warning');
  } catch { toast(t('toast_clip_fail'), 'error'); }
}

async function doImport() {
  const text = $('importText').value.trim();
  if (!text) { toast(t('toast_input_acc'), 'warning'); return; }
  const group = $('importGroup').value;
  const dedup = $('importDedup').checked;
  try {
    const r = await api.post('/api/accounts/import', { text, group, skip_duplicate: dedup });
    let msg = `OK: ${r.success} | FAIL: ${r.fail}`;
    if (typeof r.created === 'number' || typeof r.updated === 'number') {
      msg += ` | NEW: ${r.created || 0} | UPDATE: ${r.updated || 0}`;
    }
    if (r.skipped) msg += ` | SKIP: ${r.skipped}`;
    if (r.groups_created && r.groups_created.length) {
      msg += ` | ${t('toast_groups_created', { n: r.groups_created.length })}: ${r.groups_created.join(', ')}`;
    }
    toast(msg, r.success > 0 ? 'success' : 'warning');
    if (r.success > 0) {
      closeModal('importModal');
      await loadGroups();
      await loadAccounts();
    }
  } catch (e) { toast(t('toast_load_fail') + e.message, 'error'); }
}

// ───────── Export ─────────
/**
 * 根据范围下拉的当前选项更新提示文字 + 锁定 / 启用「按选中」选项。
 * 「按选中」只有在用户至少勾选了一个账号时才可选；否则文字降级提示。
 */
function refreshExportScopeHint() {
  const sel = $('exportScope');
  const hintEl = $('exportSelectedHint');
  const selectedCount = S.selected.size;
  const selectedOpt = sel.querySelector('option[value="selected"]');
  if (selectedOpt) {
    if (selectedCount > 0) {
      selectedOpt.disabled = false;
      selectedOpt.textContent = t('modal_export_selected_n', { n: selectedCount });
    } else {
      selectedOpt.disabled = true;
      selectedOpt.textContent = t('modal_export_selected_empty');
    }
  }
  if (sel.value === 'selected') {
    hintEl.style.display = '';
    hintEl.textContent = selectedCount > 0
      ? t('modal_export_selected_hint', { n: selectedCount })
      : t('modal_export_selected_empty');
  } else {
    hintEl.style.display = 'none';
    hintEl.textContent = '';
  }
}

function showExportModal() {
  $('exportPassword').value = '';
  $('exportErr').textContent = '';
  // 默认范围（按优先级）：勾选不空 → selected；否则当前分组非全部 → current；否则 all
  if (S.selected.size > 0) {
    $('exportScope').value = 'selected';
  } else if (S.currentGroup && S.currentGroup !== '全部') {
    $('exportScope').value = 'current';
  } else {
    $('exportScope').value = 'all';
  }
  $('exportSeparator').value = 'newline';
  $('exportIncludeGroup').checked = true;
  refreshExportScopeHint();
  openModal('exportModal');
  setTimeout(() => $('exportPassword').focus(), 60);
}

async function doExport() {
  const pwd = $('exportPassword').value;
  const errEl = $('exportErr');
  errEl.textContent = '';
  if (!pwd) {
    errEl.textContent = t('auth_err_password_required');
    return;
  }
  const scope = $('exportScope').value;
  const includeGroup = $('exportIncludeGroup').checked;
  const separator = $('exportSeparator').value;

  const payload = {
    password: pwd,
    include_group: includeGroup,
    separator,
  };
  if (scope === 'selected') {
    const ids = [...S.selected];
    if (!ids.length) {
      errEl.textContent = t('modal_export_selected_empty');
      return;
    }
    payload.ids = ids;
  } else if (scope === 'current' && S.currentGroup && S.currentGroup !== '全部') {
    payload.group = S.currentGroup;
  }
  // scope === 'all' 时既不传 ids 也不传 group → 后端走全部账号

  const btn = $('btnDoExport');
  btn.disabled = true;
  const oldText = btn.textContent;
  btn.textContent = '...';
  try {
    const r = await request('/api/accounts/export', {
      method: 'POST',
      body: JSON.stringify(payload),
      headers: { 'Content-Type': 'application/json' },
    });
    if (!r.ok) {
      const msg = await parseError(r);
      errEl.textContent = msg || t('toast_export_failed');
      return;
    }
    const blob = await r.blob();
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const url = URL.createObjectURL(blob);
    const a = el('a', { href: url, download: `accounts_export_${ts}.txt` });
    document.body.appendChild(a); a.click(); a.remove();
    // 浏览器需要一点时间发起下载请求；用 setTimeout 而不是立即 revoke。
    // 不 revoke 的话同一会话反复导出会让 blob URL 持续累积，浏览器不主动清理。
    setTimeout(() => {
      try { URL.revokeObjectURL(url); } catch { /* 老浏览器忽略 */ }
    }, 60_000);
    closeModal('exportModal');
    toast(t('toast_export_started'), 'success');
  } catch (e) {
    errEl.textContent = (e && e.message) || t('toast_export_failed');
  } finally {
    btn.disabled = false;
    btn.textContent = oldText;
  }
}

// ───────── Move group ─────────
function showMoveGroup() {
  const ids = [...S.selected];
  if (!ids.length) { toast(t('toast_select_acc'), 'warning'); return; }
  const sel = $('moveGroupSel'); clear(sel);
  for (const g of S.groups) sel.appendChild(el('option', {}, g.name));
  openModal('moveModal');
}

async function doMoveGroup() {
  const ids = [...S.selected];
  const group = $('moveGroupSel').value;
  for (const id of ids) await api.put(`/api/accounts/${id}/group`, { group });
  closeModal('moveModal');
  await loadAccounts();
  toast(`OK: ${ids.length} → "${group}"`, 'success');
}

// ───────── Batch Check ─────────
async function batchCheck() {
  let ids = [...S.selected];
  if (!ids.length) ids = S.accounts.map((a) => a.id);
  if (!ids.length) { toast(t('toast_no_acc'), 'warning'); return; }
  if (!confirm(t('confirm_check_n', { n: ids.length }))) return;
  openModal('batchCheckModal');
  const fill = $('bcProgressFill');
  const log = $('bcLog');
  const info = $('bcInfo');
  const status = $('bcStatus');
  const doneBtn = $('bcDoneBtn');
  fill.style.width = '0';
  clear(log);
  doneBtn.style.display = 'none';
  info.textContent = t('log_progress', { n: ids.length });

  await api.stream('/api/batch/check', { account_ids: ids }, (d) => {
    if (d.type === 'progress') {
      fill.style.width = (d.current / d.total * 100) + '%';
      status.textContent = `${d.current} / ${d.total}`;
      const cls = d.status === '正常' ? 'log-ok' : 'log-err';
      log.appendChild(el('div', { class: cls },
        `${d.current}. ${d.email} - ${d.status}${d.has_aws ? ' [AWS]' : ''}`));
      log.scrollTop = log.scrollHeight;
    } else if (d.type === 'done') {
      info.textContent = t('log_done', { s: d.success, f: d.fail });
      doneBtn.style.display = 'inline-block';
      loadAccounts();
    }
  });
}

// ───────── Email View ─────────
function viewEmails(accountId) {
  const acc = S.accounts.find((a) => a.id === accountId);
  if (!acc) return;
  S.emailAccount = acc;
  $('emailModalTitle').textContent = t('modal_email_title') + ' - ' + acc.email;
  $('emailFolder').value = 'inbox';
  $('ecSubject').textContent = t('email_select_hint');
  $('ecInfo').textContent = '';
  _setIframeContent(EMAIL_HEAD
    + `<div style="color:#8e8e93;padding:24px;text-align:center;font-size:13px">${t('email_select_hint')}</div>`
    + EMAIL_FOOT);
  $('btnReply').disabled = true;
  $('btnDelEmail').disabled = true;
  openModal('emailModal');
  loadEmails();
}

// 邮件列表请求计数器：用户连点几次刷新或快速切换文件夹时，慢的旧请求
// 返回后会覆盖掉新请求的结果（"先发后到"竞态）。每次开新请求自增此计数，
// 在 await 后 if 自增过就丢弃响应。
S._emailListReqId = 0;
// 上一次成功发出请求的时间戳，用于"前端节流"——避免用户连点刷新按钮把
// Microsoft Graph per-mailbox 限流（每分钟几十次就开始 429）撞穿，从而出现
// "刷几次后变暂无数据"的伪限流体验。
//
// 1500ms 取舍：
// - 与后端进程级 5s 邮件列表缓存形成两层节流：前端先压成至多 ~每 1.5s 一次
//   请求，命中后端缓存就完全不打 Graph
// - 用户日常操作不可感（连点 5 次≈合并成 1-2 次落地）
// - 即使后端缓存被旁路 / 失效，1.5s 间隔也远低于 Microsoft per-mailbox 的
//   滚动限速门槛
S._emailListLastFetchTs = 0;
const EMAIL_LIST_MIN_INTERVAL_MS = 1500;

async function loadEmails() {
  if (!S.emailAccount) return;
  const folder = $('emailFolder').value;
  const list = $('emailList');

  // 前端节流：连点 / 抖动场景下只让最后一次落到后端，避免把上游 Graph
  // 推到 429。仍然把请求计数 +1，让旧的 in-flight 请求落地后被丢弃。
  const now = Date.now();
  const sinceLast = now - S._emailListLastFetchTs;
  if (sinceLast < EMAIL_LIST_MIN_INTERVAL_MS) {
    const myReqId = ++S._emailListReqId;
    const myAccId = S.emailAccount.id;
    clearTimeout(S._emailListThrottleTimer);
    S._emailListThrottleTimer = setTimeout(() => {
      if (myReqId !== S._emailListReqId) return;
      if (!S.emailAccount || S.emailAccount.id !== myAccId) return;
      loadEmails();
    }, EMAIL_LIST_MIN_INTERVAL_MS - sinceLast);
    return;
  }
  S._emailListLastFetchTs = now;

  clear(list);
  list.appendChild(el('div', { class: 'empty-state' }, t('email_loading')));
  const myReqId = ++S._emailListReqId;
  const myAccId = S.emailAccount.id;
  try {
    const r = await api.get(`/api/accounts/${myAccId}/emails?folder=${folder}`);
    // 后发先至防御：若期间用户切换了账号 / 切换了文件夹再刷新，丢弃本次结果
    if (myReqId !== S._emailListReqId) return;
    if (!S.emailAccount || S.emailAccount.id !== myAccId) return;
    S.allEmails = r.emails || [];
    S.emails = [...S.allEmails];
    S.currentEmail = null;
    // 后端 200 但上游软失败：emails 空且 message 含错误描述时，渲染明确的错
    // 误条而不是误导性的"暂无数据"。Graph/Outlook 返回的 message 形如
    // "API 错误: 429 - ..." / "OAuth2 错误: ..." / "网络错误"。
    if (!S.allEmails.length && r && r.message && _isEmailListUpstreamError(r.message)) {
      clear(list);
      list.appendChild(el('div', {
        class: 'empty-state', style: 'color:var(--warning);white-space:pre-wrap;line-height:1.5'
      }, t('email_load_fail') + '\n' + r.message));
      return;
    }
    renderEmailList();
    // 旧版会在这里立刻预拉前 3 封 body —— 一次刷新等于 1(列表) + 3(预拉) =
    // 4 次 Graph 请求。用户连点几次刷新就轻松撞 per-mailbox 风控（Microsoft
    // 对单邮箱并发 + 高频 GET 会临时返回 429 / 限速），表象是"刷几次后变
    // 暂无数据"，被误以为是我们自家代码的限流。改成只在用户实际点开第 1
    // 封后再预拉下一封（见 selectEmail），单次刷新只发 1 个 API 请求。
  } catch (err) {
    if (myReqId !== S._emailListReqId) return;
    clear(list);
    const detail = _sanitizeUpstreamMsg((err && err.message) || '');
    list.appendChild(el('div', {
      class: 'empty-state',
      style: 'color:var(--danger);white-space:pre-wrap;line-height:1.5',
    }, detail ? t('email_load_fail') + '\n' + detail : t('email_load_fail')));
  }
}

// 邮件列表上游软失败的判定：response 200 但 message 描述了真实错误（来自
// Graph / Outlook REST / OAuth refresh 等环节）。命中关键字时不再静默把
// 空 list 渲染成"暂无数据"。
function _isEmailListUpstreamError(msg) {
  if (!msg) return false;
  const m = String(msg).toLowerCase();
  return /(429|503|502|throttl|too many|限流|错误|失败|err|oauth|invalid|unauth)/i.test(m);
}

// 把上游可能漏出来的 HTML 片段 / 长 body 净化成短文案：
// - 后端 GraphClient / web_app.get_emails 已分别做了一层净化；这是第三层兜底
// - 一旦未来后端回退或新走 IMAP 等路径直接把 HTML 塞进 message，前端也不会
//   把 <!DOCTYPE html> ... 之类的字符渲染到列表（截图里出现过的现象）
function _sanitizeUpstreamMsg(msg) {
  if (!msg) return '';
  let s = String(msg);
  // 剥 HTML 标签 + < / > 字符；条件注释 <!--[if ...]--> 也被吞掉
  s = s.replace(/<!--[\s\S]*?-->/g, ' ').replace(/<[^>]{0,200}>/g, ' ');
  s = s.replace(/[<>]/g, ' ');
  s = s.replace(/\s+/g, ' ').trim();
  if (s.length > 160) s = s.slice(0, 160) + '...';
  return s;
}

function filterEmailList() {
  const q = $('emailSearch').value.toLowerCase();
  S.emails = q
    ? S.allEmails.filter((e) =>
        (e.sender || '').toLowerCase().includes(q) ||
        (e.subject || '').toLowerCase().includes(q))
    : [...S.allEmails];
  renderEmailList();
}

function renderEmailList() {
  const list = $('emailList'); clear(list);
  if (!S.emails.length) {
    list.appendChild(el('div', { class: 'empty-state' }, t('empty')));
    return;
  }
  // 与 renderAccounts 同款：用 DocumentFragment 一次性挂入 N 条邮件项，
  // 避免逐条 appendChild 触发 N 次 reflow。邮件列表常规 ≤50 条但高频
  // 切换文件夹 / 搜索 / 选中态变更，累计的 reflow 与卡顿同样肉眼可感。
  const frag = document.createDocumentFragment();
  S.emails.forEach((e, i) => {
    const d = e.date ? new Date(e.date) : null;
    const ds = d ? `${d.getMonth() + 1}/${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}` : '';
    const unread = !e.is_read;
    const active = S.currentEmail === e;
    const item = el('div', {
      class: 'email-item' + (unread ? ' unread' : '') + (active ? ' active' : ''),
      onclick: () => selectEmail(i)
    });
    const sender = (unread ? '● ' : '') + (e.has_attachments ? '📎 ' : '') + (e.sender || '?');
    item.appendChild(el('div', { class: 'ei-sender' }, sender));
    item.appendChild(el('div', { class: 'ei-subject' }, e.subject || '(no subject)'));
    item.appendChild(el('div', { class: 'ei-date' }, ds));
    frag.appendChild(item);
  });
  list.appendChild(frag);
}

const filterEmailListDebounced = debounce(filterEmailList, 120);

const EMAIL_HEAD =
  '<!DOCTYPE html><html><head>'
  + '<base target="_blank"><meta charset="utf-8">'
  + '<meta name="viewport" content="width=device-width,initial-scale=1">'
  + '<style>'
  + 'html,body{margin:0;padding:0;min-height:100%}'
  + 'body{font-family:Segoe UI,Microsoft YaHei UI,sans-serif;'
  + 'font-size:13px;padding:12px;color:#1d1d1f;background:#fff;'
  + 'word-wrap:break-word;overflow-wrap:break-word;line-height:1.6}'
  + 'pre{white-space:pre-wrap;margin:0;font-family:inherit}'
  + 'img{max-width:100%;height:auto;border:0}'
  + 'a{color:#0078d4}'
  + 'table{max-width:100%;border-collapse:collapse}'
  + '</style>'
  + '</head><body>';

const EMAIL_FOOT = '</body></html>';

// 三层兜底渲染邮件正文：
//   1. 优先 document.open/write/close（同 origin、无网络、无 srcdoc 长度限制）
//   2. 失败 → Blob URL（绕过 srcdoc 大小限制）
//   3. 都失败 → srcdoc（最朴素的方式）
// iframe 必须有 sandbox="allow-same-origin"（但仍不带 allow-scripts）才能让前两种工作。
function _setIframeContent(html) {
  const iframe = $('ecBody');

  if (iframe._blobUrl) {
    try { URL.revokeObjectURL(iframe._blobUrl); } catch {}
    iframe._blobUrl = null;
  }

  // 1. document.write — 同步，最稳
  try {
    // 必须先把 src/srcdoc 清掉，否则 contentDocument 可能是异步加载状态
    iframe.removeAttribute('srcdoc');
    iframe.removeAttribute('src');
    const doc = iframe.contentDocument || iframe.contentWindow.document;
    if (doc) {
      doc.open();
      doc.write(html);
      doc.close();
      return;
    }
  } catch (err) {
    console.warn('[email] document.write 失败，回退 Blob URL:', err);
  }

  // 2. Blob URL
  try {
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    iframe._blobUrl = url;
    iframe.src = url;
    return;
  } catch (err) {
    console.warn('[email] Blob URL 失败，回退 srcdoc:', err);
  }

  // 3. srcdoc
  iframe.srcdoc = html;
}

function renderEmailBody(body, bodyType) {
  if (!body) {
    _setIframeContent(EMAIL_HEAD
      + `<div style="color:#8e8e93;padding:24px;text-align:center;font-size:13px">${t('email_body_empty')}</div>`
      + EMAIL_FOOT);
    return;
  }
  const isHtml = bodyType
    ? String(bodyType).toLowerCase() === 'html'
    : /<html|<body|<div|<a\s|<p\s|<br|<table/i.test(body);
  if (isHtml) {
    // 邮件本身是完整的 HTML 文档时直接用，避免重复 <html><body> 嵌套
    const looksLikeFullDoc = /<html[\s>]/i.test(body);
    const html = looksLikeFullDoc
      ? body  // 邮件自带完整文档结构
      : EMAIL_HEAD + body + EMAIL_FOOT;
    _setIframeContent(html);
  } else {
    const escaped = body
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    _setIframeContent(EMAIL_HEAD + `<pre>${escaped}</pre>` + EMAIL_FOOT);
  }
}

function renderEmailLoading() {
  _setIframeContent(EMAIL_HEAD
    + `<div style="color:#8e8e93;padding:24px;text-align:center">⏳ ${t('email_loading')}</div>`
    + EMAIL_FOOT);
}

function renderEmailError(msg) {
  const escaped = String(msg || '').replace(/&/g, '&amp;').replace(/</g, '&lt;');
  _setIframeContent(EMAIL_HEAD
    + '<div style="color:#c62828;padding:24px;font-size:13px">'
    + `<div style="margin-bottom:8px">⚠️ ${t('email_load_fail')}</div>`
    + `<div style="color:#8e8e93;font-family:Consolas,monospace;font-size:12px">${escaped}</div>`
    + '</div>'
    + EMAIL_FOOT);
}

async function selectEmail(idx) {
  const e = S.emails[idx];
  if (!e) return;
  S.currentEmail = e;
  $('ecSubject').textContent = e.subject || '(no subject)';
  const d = e.date ? new Date(e.date) : null;
  $('ecInfo').textContent = `${t('compose_from')}: ${e.sender || ''}\n${t('d_created')}: ${d ? d.toLocaleString() : ''}`;
  $('btnReply').disabled = false;
  $('btnDelEmail').disabled = false;

  // 缓存命中：直接渲染
  if (e._fullBody) {
    renderEmailBody(e._fullBody.body, e._fullBody.type);
    maybeMarkRead(e);
    // 命中也要继续预加载下一封，让顺序阅读体验持续顺滑
    prefetchEmailBody(idx + 1);
    prefetchEmailBody(idx + 2);
    return;
  }

  // 没缓存 → 显示加载中，异步拉完整正文
  renderEmailLoading();
  const account = S.emailAccount;
  if (!account || !e.uid) {
    renderEmailBody('', 'text');
    return;
  }
  const folder = $('emailFolder').value;
  try {
    const r = await api.get(
      `/api/accounts/${account.id}/emails/body?email_id=${encodeURIComponent(e.uid)}&folder=${folder}`
    );
    // 用户已经切到下一封 → 丢弃本次结果
    if (S.currentEmail !== e) return;
    console.log('[email body fetched]', {
      success: r && r.success,
      len: r && r.body ? r.body.length : 0,
      type: r && r.body_type,
      preview: r && r.body ? r.body.substring(0, 200) : '',
    });
    if (r && r.success) {
      e._fullBody = { body: r.body || '', type: r.body_type || 'text' };
      renderEmailBody(e._fullBody.body, e._fullBody.type);
    } else {
      renderEmailError(r && r.message ? r.message : t('email_load_fail'));
    }
  } catch (err) {
    if (S.currentEmail === e) {
      renderEmailError((err && err.message) || t('email_load_fail'));
    }
  }
  maybeMarkRead(e);
  // 后台预加载下 1-2 封，用户继续往下点时几乎瞬间显示
  prefetchEmailBody(idx + 1);
  prefetchEmailBody(idx + 2);
}

function maybeMarkRead(e) {
  if (e.is_read || !S.emailAccount) return;
  e.is_read = true;
  renderEmailList();
  api.post(`/api/accounts/${S.emailAccount.id}/emails/mark-read`, {
    email_id: e.uid, folder: $('emailFolder').value, is_read: true,
  }).catch(() => {});
}

// 后台静默预加载某封邮件的完整 body 到缓存。用户再切到该邮件时瞬间显示。
function prefetchEmailBody(idx) {
  const e = S.emails[idx];
  if (!e || e._fullBody || !e.uid || !S.emailAccount) return;
  if (e._prefetching) return;
  e._prefetching = true;
  const folder = $('emailFolder').value;
  const account = S.emailAccount;
  api.get(
    `/api/accounts/${account.id}/emails/body?email_id=${encodeURIComponent(e.uid)}&folder=${folder}`
  ).then((r) => {
    if (r && r.success) {
      e._fullBody = { body: r.body || '', type: r.body_type || 'text' };
    }
  }).catch(() => {}).finally(() => {
    e._prefetching = false;
  });
}

// ───────── Compose ─────────
function showCompose(replyTo, replySubject, replyBody) {
  if (!S.emailAccount) { toast(t('toast_select_acc'), 'warning'); return; }
  $('compFrom').value = S.emailAccount.email;
  $('compTo').value = replyTo || '';
  $('compCc').value = '';
  $('compSubject').value = replySubject || '';
  $('compBody').value = replyBody || '';
  $('compStatus').textContent = '';
  $('btnDoSend').disabled = false;
  $('btnDoSend').textContent = t('btn_send');
  $('composeTitle').textContent = replyTo ? t('btn_reply') : t('modal_compose_title');
  openModal('composeModal');
}

function replyEmail() {
  if (!S.currentEmail || !S.emailAccount) return;
  const sender = S.currentEmail.sender_email || S.currentEmail.sender || '';
  const m = sender.match(/<([^>]+)>/);
  const addr = m ? m[1] : (sender.includes('@') ? sender : '');
  const subj = S.currentEmail.subject || '';
  const prefix = subj.startsWith('Re:') ? '' : 'Re: ';
  const d = S.currentEmail.date ? new Date(S.currentEmail.date).toLocaleString() : '';
  const body = `\n\n\n-------- 原始邮件 --------\n发件人: ${S.currentEmail.sender || ''}\n时间: ${d}\n\n${S.currentEmail.body || ''}`;
  showCompose(addr, prefix + subj, body);
}

async function doSendEmail() {
  const to = $('compTo').value.trim();
  const subject = $('compSubject').value.trim();
  const body = $('compBody').value;
  const cc = $('compCc').value.trim() || null;
  if (!to) { toast(t('toast_input_to'), 'warning'); return; }
  if (!subject) { toast(t('toast_input_subj'), 'warning'); return; }
  $('btnDoSend').disabled = true;
  $('btnDoSend').textContent = '...';
  $('compStatus').textContent = '...';
  try {
    const r = await api.post(`/api/accounts/${S.emailAccount.id}/emails/send`, { to, subject, body, cc });
    if (r.success) { toast(t('toast_send_ok'), 'success'); closeModal('composeModal'); }
    else { toast(t('toast_send_fail') + ': ' + r.message, 'error'); $('compStatus').textContent = r.message || ''; }
  } catch { toast(t('toast_send_fail'), 'error'); }
  $('btnDoSend').disabled = false;
  $('btnDoSend').textContent = t('btn_send');
}

async function deleteCurrentEmail() {
  if (!S.currentEmail || !S.emailAccount) return;
  if (!confirm(t('confirm_del_email'))) return;
  const folder = $('emailFolder').value;
  const r = await api.post(`/api/accounts/${S.emailAccount.id}/emails/delete`, {
    email_id: S.currentEmail.uid, folder
  });
  if (r.success) { toast(t('toast_del_ok'), 'success'); loadEmails(); }
  else toast(t('toast_del_fail') + ': ' + r.message, 'error');
}

// ───────── Batch send ─────────
function showBatchSend() {
  const ids = [...S.selected];
  if (!ids.length) { toast(t('toast_select_acc'), 'warning'); return; }
  const accs = S.accounts.filter((a) => ids.includes(a.id));
  $('batchSendTitle').textContent = `${t('modal_batch_send_title')} (${accs.length})`;
  $('batchSendInfo').textContent = `${t('compose_from')}: ` + accs.slice(0, 3).map((a) => a.email).join(', ') + (accs.length > 3 ? '...' : '');
  $('bsTo').value = ''; $('bsSubject').value = ''; $('bsBody').value = '';
  $('bsProgress').style.display = 'none';
  $('bsLog').style.display = 'none';
  $('btnDoBatchSend').disabled = false;
  openModal('batchSendModal');
}

async function doBatchSend() {
  const ids = [...S.selected];
  const to = $('bsTo').value.trim();
  const subject = $('bsSubject').value.trim();
  const body = $('bsBody').value;
  if (!to) { toast(t('toast_input_to'), 'warning'); return; }
  if (!subject) { toast(t('toast_input_subj'), 'warning'); return; }
  if (!confirm(t('confirm_send_n', { n: ids.length }))) return;

  $('btnDoBatchSend').disabled = true;
  $('bsProgress').style.display = 'block';
  $('bsLog').style.display = 'block';
  clear($('bsLog'));
  $('bsProgressFill').style.width = '0';

  await api.stream('/api/batch/send', { account_ids: ids, to, subject, body }, (d) => {
    if (d.type === 'progress') {
      $('bsProgressFill').style.width = (d.current / d.total * 100) + '%';
      const cls = d.success ? 'log-ok' : 'log-err';
      const status = d.success ? '✓' : '✗ ' + d.message;
      $('bsLog').appendChild(el('div', { class: cls }, `${d.current}. ${d.email} - ${status}`));
      $('bsLog').scrollTop = 999999;
    } else if (d.type === 'done') {
      toast(t('log_send_done', { s: d.success, f: d.fail }), d.fail ? 'warning' : 'success');
      $('btnDoBatchSend').disabled = false;
    }
  });
}

// ───────── Detail ─────────
async function showDetail(id) {
  try {
    const a = await api.get(`/api/accounts/${id}`);
    S.detailAccount = a;
    const body = $('detailBody');
    clear(body);

    const section = (title, items) => {
      const wrap = el('div', { style: 'margin-bottom:16px' });
      wrap.appendChild(el('div', { style: 'font-size:14px;font-weight:600;margin-bottom:10px' }, title));
      const box = el('div', { style: 'background:var(--hover);border-radius:8px;padding:12px 16px' });
      for (const [k, v] of items) {
        const row = el('div', { style: 'display:flex;padding:6px 0;border-bottom:1px solid var(--border)' });
        row.appendChild(el('span', { style: 'width:100px;color:var(--text2);font-size:13px;flex-shrink:0' }, k));
        row.appendChild(el('span', { style: 'font-size:13px;word-break:break-all;flex:1' }, v || '-'));
        box.appendChild(row);
      }
      wrap.appendChild(box);
      return wrap;
    };

    body.appendChild(section(t('sec_basic'), [
      [t('d_email'), a.email], [t('d_password'), a.password], [t('d_group'), a.group],
      [t('d_status'), a.status], [t('d_type'), a.type]
    ]));
    body.appendChild(section(t('sec_server'), [
      [t('d_imap'), a.imap_server], [t('d_imap_port'), a.imap_port], [t('d_smtp'), a.smtp_server]
    ]));
    if (a.client_id) {
      body.appendChild(section(t('sec_oauth'), [
        [t('d_client_id'), a.client_id],
        [t('d_refresh_token'), (a.refresh_token || '').substring(0, 60) + '...']
      ]));
    }
    body.appendChild(section(t('sec_other'), [
      [t('d_created'), a.created_at], [t('d_last_check'), a.last_check],
      [t('d_aws'), a.has_aws_code ? t('d_yes') : t('d_no')], [t('d_remark'), a.remark]
    ]));
    openModal('detailModal');
  } catch { toast(t('toast_load_fail'), 'error'); }
}

function copyAccountInfo() {
  if (!S.detailAccount) return;
  const a = S.detailAccount;
  const lines = [
    `${t('d_email')}: ${a.email}`,
    `${t('d_password')}: ${a.password}`,
    `${t('d_group')}: ${a.group}`,
    `${t('d_status')}: ${a.status}`,
    `${t('d_type')}: ${a.type}`,
  ];
  // 旧版硬编码 ``Client ID`` / ``Refresh Token`` 英文，与 zh 界面格格不入；
  // 改走 i18n（i18n.js 中 ``d_client_id`` / ``d_refresh_token`` 已存在）
  if (a.client_id) lines.push(`${t('d_client_id')}: ${a.client_id}`);
  if (a.refresh_token) lines.push(`${t('d_refresh_token')}: ${a.refresh_token}`);
  if (a.remark) lines.push(`${t('d_remark')}: ${a.remark}`);
  copyText(lines.join('\n'), 'toast_copied');
}

// ───────── Views ─────────
function showTableView() {
  $('tableView').style.display = '';
  $('dashView').style.display = 'none';
  $('settingsView').style.display = 'none';
  $('helpView').style.display = 'none';
  $('actionBar').style.display = '';
  $('toolbarRight').style.display = '';
  $('pageTitle').textContent = S.currentGroup === '全部' ? t('page_title_default') : S.currentGroup;
  $('pageSub').textContent = t('page_sub_default');
  // 离开 Help 视图时关掉常驻 SSE
  if (typeof stopHelpPersistentLog === 'function') stopHelpPersistentLog();
}

function showView(view) {
  S.view = view;
  document.querySelectorAll('.nav-btn').forEach((b) => b.classList.remove('active'));
  document.querySelectorAll('.grp-item').forEach((b) => b.classList.remove('active'));
  const map = { dashboard: 'navDash', settings: 'navSettings', help: 'navHelp' };
  if (map[view]) $(map[view]).classList.add('active');
  $('tableView').style.display = 'none';
  $('dashView').style.display = view === 'dashboard' ? '' : 'none';
  $('settingsView').style.display = view === 'settings' ? '' : 'none';
  $('helpView').style.display = view === 'help' ? '' : 'none';
  $('actionBar').style.display = 'none';
  $('toolbarRight').style.display = 'none';

  if (view === 'dashboard') {
    $('pageTitle').textContent = t('page_title_dashboard');
    $('pageSub').textContent = t('page_sub_dashboard');
    pushPath('/dashboard');
    renderDashboard();
  } else if (view === 'settings') {
    $('pageTitle').textContent = t('page_title_settings');
    $('pageSub').textContent = t('page_sub_settings');
    pushPath('/settings');
    renderSettings();
  } else if (view === 'help') {
    $('pageTitle').textContent = t('page_title_help');
    $('pageSub').textContent = t('page_sub_help');
    pushPath('/help');
    renderHelp();
    startHelperPolling();
  } else {
    pushPath('/');
    // 离开 Help 页关掉常驻 SSE，省流量与服务端 SSE 桶
    if (typeof stopHelpPersistentLog === 'function') stopHelpPersistentLog();
  }
}

// ───────── Dashboard ─────────
async function renderDashboard() {
  const d = await api.get('/api/dashboard');
  const view = $('dashView'); clear(view);
  const colors = ['#0078d4', '#34c759', '#ff3b30', '#ff9500', '#af52de', '#5ac8fa', '#ff2d55'];

  const grid = el('div', { class: 'dash-grid' });
  const card = (cls, n, label) => {
    const c = el('div', { class: 'dash-card ' + cls });
    c.appendChild(el('div', { class: 'dc-n' }, String(n)));
    c.appendChild(el('div', { class: 'dc-l' }, label));
    return c;
  };
  grid.appendChild(card('c-blue', d.total, t('st_total')));
  grid.appendChild(card('c-green', d.statuses['正常'] || 0, t('st_normal')));
  grid.appendChild(card('c-red', d.statuses['异常'] || 0, t('st_abnormal')));
  grid.appendChild(card('c-yellow', d.statuses['未检测'] || 0, t('st_unchecked')));
  view.appendChild(grid);

  const bar = (label, value, max, color) => {
    const row = el('div', { class: 'dist-bar' });
    row.appendChild(el('span', { class: 'db-label' }, label));
    const wrap = el('div', { class: 'db-bar' });
    wrap.appendChild(el('div', {
      class: 'db-fill',
      style: `width:${(value / max * 100)}%;background:${color}`
    }));
    row.appendChild(wrap);
    row.appendChild(el('span', { class: 'db-val' }, String(value)));
    return row;
  };

  const groupSec = el('div', { class: 'dash-section' });
  groupSec.appendChild(el('h4', {}, t('st_groups')));
  const maxG = Math.max(...Object.values(d.groups), 1);
  Object.entries(d.groups).forEach(([k, v], i) => {
    groupSec.appendChild(bar(k, v, maxG, colors[i % colors.length]));
  });
  view.appendChild(groupSec);

  const statSec = el('div', { class: 'dash-section' });
  statSec.appendChild(el('h4', {}, t('st_status')));
  const maxS = Math.max(...Object.values(d.statuses), 1);
  Object.entries(d.statuses).forEach(([k, v]) => {
    const c = k === '正常' ? 'var(--success)' : k === '异常' ? 'var(--danger)' : 'var(--warning)';
    statSec.appendChild(bar(k, v, maxS, c));
  });
  view.appendChild(statSec);
}

// ───────── Settings ─────────
function renderSettings() {
  const view = $('settingsView'); clear(view);
  const card = (h, desc, inner) => {
    const c = el('div', { class: 'settings-card' });
    c.appendChild(el('h4', {}, h));
    c.appendChild(el('p', { class: 'sc-desc' }, desc));
    c.appendChild(inner);
    return c;
  };
  const row = (label, control) => {
    const r = el('div', { class: 'settings-row' });
    r.appendChild(el('label', {}, label));
    r.appendChild(control);
    return r;
  };
  const themeSel = el('select', { onchange: (e) => setTheme(e.target.value) });
  for (const v of ['cyber', 'dark', 'light']) {
    const o = el('option', { value: v }, t('theme_' + v));
    if (S.theme === v) o.selected = true;
    themeSel.appendChild(o);
  }
  view.appendChild(card(t('settings_theme'), t('settings_theme_desc'), row(t('settings_theme_label'), themeSel)));

  const langSel = el('select', { onchange: (e) => setLang(e.target.value) });
  for (const [v, label] of [['zh', '简体中文'], ['en', 'English']]) {
    const o = el('option', { value: v }, label);
    if (S.lang === v) o.selected = true;
    langSel.appendChild(o);
  }
  view.appendChild(card(t('settings_general'), t('settings_general_desc'), row(t('settings_lang'), langSel)));

  view.appendChild(card(t('settings_data'), t('settings_data_desc'),
    row(el('span', { style: 'color:var(--text2);font-size:12px' }, 'data/emails.db'),
        el('span'))));

  // 账户管理：当前用户名 + 修改密码
  const accInfo = el('div', { style: 'color:var(--text2);font-size:13px;margin-bottom:12px' },
    `${t('settings_current_user')}: ${S.user?.username || '-'}`);
  const oldPwd = el('input', { type: 'password', placeholder: t('settings_old_password'), maxlength: 128 });
  const newPwd = el('input', { type: 'password', placeholder: t('settings_new_password'), maxlength: 128 });
  const newPwd2 = el('input', { type: 'password', placeholder: t('settings_new_password2'), maxlength: 128 });
  const pwdErr = el('div', { style: 'font-size:12px;color:var(--danger);margin-top:6px;min-height:16px' });
  const pwdBtn = el('button', { class: 'btn btn-p', style: 'margin-top:8px',
    onclick: async () => {
      pwdErr.textContent = '';
      if (!oldPwd.value || !newPwd.value) { pwdErr.textContent = t('auth_err_password_required'); return; }
      if (newPwd.value.length < 6) { pwdErr.textContent = t('auth_err_password_short'); return; }
      if (newPwd.value !== newPwd2.value) { pwdErr.textContent = t('auth_err_password_mismatch'); return; }
      try {
        await api.post('/api/auth/change-password', {
          old_password: oldPwd.value, new_password: newPwd.value,
        });
        toast(t('toast_password_changed'), 'success');
        // 修改后强制重新登录
        S.user = null;
        showAuthModal('login');
      } catch (e) { pwdErr.textContent = e.message || t('auth_err_failed'); }
    } }, t('btn_change_password'));
  const pwdWrap = el('div', {}, [accInfo,
    el('div', { style: 'display:flex;flex-direction:column;gap:8px' }, [oldPwd, newPwd, newPwd2]),
    pwdErr, pwdBtn]);
  view.appendChild(card(t('settings_account'), t('settings_account_desc'), pwdWrap));
}

// ───────── Helper（邮箱助手 · xiaoxuan 专属） ─────────
//
// 设计要点：
// - renderHelp() 一次性渲染 4 个 Card：状态 / 操作 / token 列表 / 下载
// - startHelperPolling() 在进入 help 视图时启动；其它视图不轮询，省 RTT
// - SSE 实时日志只在「Helper 任务 Modal」展开期间订阅，关闭即断开
// - 所有 helper API 在 401/403 时静默隐藏 UI（用户不是 xiaoxuan），避免暴露
const HELPER_POLL_INTERVAL = 5000;
const HELPER_POLL_FAST = 1500;
let _helperPollTimer = null;
let _helperPollFastUntil = 0;
window.HELPER_STATUS = { loaded: false, online: false };

function helperEnabled() {
  return !!(S.user && S.user.is_owner);
}

/**
 * 统一拦截 helper API 响应，处理 stale_account_id 与 needs_helper_upgrade。
 *
 * - stale_account_id：账号已被删/不存在 → toast 提示 + 自动 loadAccounts
 *   刷新表格（与参考项目 cursor-manager 0.1.10 的修复行为一致）。
 * - needs_helper_upgrade：Helper 版本过低 → confirm 引导用户去下载页。
 */
function helperResponseGuard(r) {
  if (!r || typeof r !== 'object') return r;
  if (r.code === 'stale_account_id') {
    toast('账号不存在或已被删除，已自动刷新列表', 'warning');
    if (typeof loadAccounts === 'function') loadAccounts();
  }
  if (r.needs_helper_upgrade) {
    setTimeout(() => {
      if (confirm(
        `本地 Helper 版本过低 (v${r.current_version || '?'}) ，` +
        `该功能要求 v${r.min_version || '?'}+。\n现在去下载新版本吗？`,
      )) {
        if (S.user && S.user.is_owner) showView('help');
        loadHelperDownloadInfo();
      }
    }, 50);
  }
  return r;
}

function renderHelp() {
  const view = $('helpView'); clear(view);

  const grid = el('div', { class: 'help-grid' });
  // 状态卡（占满第一行）
  grid.appendChild(el('div', {
    class: 'help-card help-card-status', id: 'helpStatusCard',
  }, [
    el('h4', {}, t('help_card_status_title')),
    el('div', { id: 'helpStatusBody', class: 'help-status-body' },
       el('div', { class: 'help-spinner' }, '⏳')),
  ]));

  // 邮箱操作
  grid.appendChild(el('div', { class: 'help-card' }, [
    el('h4', {}, t('help_card_actions_title')),
    el('div', { id: 'helpActionsBody' }),
  ]));

  // Token 列表
  grid.appendChild(el('div', { class: 'help-card' }, [
    el('h4', {}, t('help_card_tokens_title')),
    el('div', { id: 'helpTokensBody' }, t('help_tokens_empty')),
  ]));

  // 下载 / 安装
  grid.appendChild(el('div', { class: 'help-card' }, [
    el('h4', {}, t('help_card_install_title')),
    el('div', { id: 'helpInstallBody' }, t('help_install_intro')),
  ]));

  // IMAP / 辅助邮箱 凭据配置（绑辅助邮箱时从 QQ IMAP 拉验证码用）
  grid.appendChild(el('div', { class: 'help-card' }, [
    el('h4', {}, t('help_card_imap_title')),
    el('div', { id: 'helpImapBody' }, t('help_imap_loading')),
  ]));

  // 实时日志（占满最后一行，常驻订阅）
  grid.appendChild(el('div', { class: 'help-card help-card-log' }, [
    el('h4', {}, [
      t('help_card_log_title'),
      el('button', {
        class: 'btn btn-o btn-tiny',
        style: 'margin-left:10px',
        onclick: () => clear($('helpPersistentLog')),
      }, t('help_log_clear')),
    ]),
    el('div', { id: 'helpPersistentLog', class: 'progress-log help-persistent-log' }),
  ]));

  view.appendChild(grid);

  // 触发首次渲染
  renderHelpStatus(window.HELPER_STATUS);
  renderHelpActions();
  loadHelperTokens();
  loadHelperDownloadInfo();
  loadHelperImapConfig();
  // 启动 / 复用常驻 SSE 订阅（用户在 Help 页期间一直在收日志）
  startHelpPersistentLog();
}

// ── IMAP / 辅助邮箱配置（绑辅助邮箱时从 QQ IMAP 拉验证码用） ─────

async function loadHelperImapConfig() {
  const body = $('helpImapBody');
  if (!body) return;
  try {
    const r = await api.get('/api/helper/imap-config', { timeoutMs: HELPER_IMAP_FETCH_TIMEOUT_MS });
    clear(body);
    body.appendChild(el('p', { class: 'help-imap-intro' }, t('help_imap_intro')));

    const mkField = (id, key, value, type = 'text', placeholder = '') => {
      const wrap = el('div', { class: 'help-imap-field' });
      wrap.appendChild(el('label', {}, t(key)));
      wrap.appendChild(el('input', {
        id, type, value: value || '', placeholder,
      }));
      return wrap;
    };

    body.appendChild(mkField('imapUser', 'help_imap_user', r.qq_imap_user,
                              'email', 'your@qq.com'));
    body.appendChild(mkField('imapPwd', 'help_imap_pwd',
      r.qq_imap_password_set ? '••••••••' : '',
      'password', t('help_imap_pwd_placeholder')));
    body.appendChild(mkField('imapHost', 'help_imap_host',
      r.qq_imap_host || 'imap.qq.com'));
    body.appendChild(mkField('imapPort', 'help_imap_port',
      String(r.qq_imap_port || 993), 'number'));
    body.appendChild(mkField('imapSuffix', 'help_imap_suffix',
      r.recovery_alias_suffix || '', 'text', 'example.com'));

    const errEl = el('div', { id: 'imapErr',
      style: 'font-size:12px;color:var(--danger);min-height:16px;margin-top:6px' });
    body.appendChild(errEl);

    body.appendChild(el('div', { class: 'help-btn-row' }, [
      el('button', { class: 'btn btn-p btn-tiny', onclick: saveHelperImapConfig },
         t('help_imap_save')),
      el('button', { class: 'btn btn-o btn-tiny', onclick: testHelperImapConfig },
         t('help_imap_test')),
    ]));
  } catch (e) {
    clear(body);
    body.appendChild(el('p', { class: 'help-status-hint' },
      t('toast_load_fail') + (e.message || '')));
  }
}

async function testHelperImapConfig() {
  const errEl = $('imapErr'); if (errEl) errEl.textContent = '';
  try {
    const r = await api.post('/api/helper/imap-config/test', {}, { timeoutMs: HELPER_IMAP_TEST_TIMEOUT_MS });
    if (r.success) {
      toast(r.message || t('toast_help_imap_test_ok'), 'success');
    } else if (errEl) {
      errEl.textContent = r.error || t('toast_load_fail');
    }
  } catch (e) {
    if (errEl) errEl.textContent = e.message || t('toast_load_fail');
  }
}

async function saveHelperImapConfig() {
  const errEl = $('imapErr'); if (errEl) errEl.textContent = '';
  const user = $('imapUser').value.trim();
  let pwd = $('imapPwd').value;
  const host = $('imapHost').value.trim();
  const port = parseInt($('imapPort').value, 10) || 993;
  const suffix = $('imapSuffix').value.trim();

  // 占位"••••••••" 表示用户没改密码 → 不传 password 字段（保留旧值）
  const body = { qq_imap_user: user, qq_imap_host: host,
                  qq_imap_port: port, recovery_alias_suffix: suffix };
  if (pwd && pwd !== '••••••••') body.qq_imap_password = pwd;

  try {
    const r = await api.put('/api/helper/imap-config', body, { timeoutMs: HELPER_IMAP_FETCH_TIMEOUT_MS });
    if (r.success) {
      toast(t('toast_help_imap_saved'), 'success');
      loadHelperImapConfig();
    } else if (errEl) {
      errEl.textContent = r.error || t('toast_load_fail');
    }
  } catch (e) {
    if (errEl) errEl.textContent = e.message || t('toast_load_fail');
  }
}

// ── Help 页常驻 SSE 日志（进入 Help 页就订阅，离开页面停止） ──

let _helpPersistentSrc = null;

function startHelpPersistentLog() {
  if (_helpPersistentSrc) {
    // 已经订阅 → 仅把已渲染的 logEl 刷新（dom 已被 renderHelp 重建）
    return;
  }
  try {
    _helpPersistentSrc = new EventSource('/api/helper/logs', { withCredentials: true });
    _helpPersistentSrc.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data && data.message) {
          appendPersistentHelpLog(data.message, data.level || 'info');
        }
      } catch { /* ignore */ }
    };
    _helpPersistentSrc.onerror = () => {
      // EventSource 会自动重连（按 retry: 5000）。出错时只在日志窗记一条
      // 警告，不主动关闭
      appendPersistentHelpLog('⚠ 日志流暂时断开，浏览器会自动重连…', 'warning');
    };
  } catch (e) {
    appendPersistentHelpLog('启动日志流失败：' + (e.message || ''), 'error');
  }
}

function stopHelpPersistentLog() {
  if (_helpPersistentSrc) {
    try { _helpPersistentSrc.close(); } catch { /* ignore */ }
    _helpPersistentSrc = null;
  }
}

function appendPersistentHelpLog(msg, level) {
  const logEl = $('helpPersistentLog');
  if (!logEl) return;
  // 控制最大行数：超过 500 行从顶部删，避免内存涨爆
  while (logEl.childNodes.length >= 500) {
    logEl.removeChild(logEl.firstChild);
  }
  const ts = new Date().toLocaleTimeString();
  const line = el('div', { class: 'log-line log-' + (level || 'info') },
    `[${ts}] ${String(msg)}`);
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

function renderHelpStatus(s) {
  const body = $('helpStatusBody');
  if (!body) return;
  clear(body);

  const dot = el('span', { class: 'help-dot ' + (s.online ? 'on' : 'off') }, '●');
  const label = el('strong', { class: 'help-status-label' },
    t(s.online ? 'help_status_online' : 'help_status_offline'));

  const headRow = el('div', { class: 'help-status-head' }, [dot, label]);
  if (s.online) {
    const sinceSec = s.last_seen ? Math.max(0, Math.floor(Date.now() / 1000) - s.last_seen) : 0;
    const meta = el('div', { class: 'help-status-meta' }, [
      el('span', {}, `${t('help_status_version')}: v${s.version || '?'}`),
      el('span', {}, `${t('help_status_platform')}: ${s.platform || '?'}`),
      el('span', {}, `${t('help_status_last_seen')}: ${t('help_status_seconds_ago', { n: sinceSec })}`),
      el('span', {}, `${t('help_status_helper_id')}: ${s.helper_id || ''}`),
    ]);
    body.appendChild(el('div', { class: 'help-status-row' }, [headRow, meta]));
    body.appendChild(el('p', { class: 'help-status-hint' }, t('help_status_online_hint')));
    // 版本不匹配警告
    if (s.version_ok === false) {
      body.appendChild(el('div', { class: 'help-version-warn' },
        t('help_status_version_mismatch', { current: s.version || '?', min: s.min_version || '?' })));
    }
    body.appendChild(el('div', { class: 'help-btn-row' }, [
      el('button', { class: 'btn btn-p', onclick: testHelperPing }, t('help_btn_test_ping')),
      el('button', { class: 'btn btn-o', onclick: refreshHelperStatus }, t('help_btn_refresh')),
      el('button', { class: 'btn btn-d', onclick: revokeHelper }, t('help_btn_revoke')),
    ]));
  } else {
    body.appendChild(headRow);
    body.appendChild(el('p', { class: 'help-status-hint' }, t('help_status_offline_hint')));
    body.appendChild(el('div', { class: 'help-btn-row' }, [
      el('button', { class: 'btn btn-p', onclick: launchHelper }, t('help_btn_launch')),
      el('button', { class: 'btn btn-o', onclick: refreshHelperStatus }, t('help_btn_refresh')),
    ]));
  }
  renderHelpActions();
}

function renderHelpActions() {
  const body = $('helpActionsBody');
  if (!body) return;
  clear(body);
  const online = !!(window.HELPER_STATUS && window.HELPER_STATUS.online);

  body.appendChild(el('p', { class: 'help-actions-hint' }, t('help_actions_intro')));

  // 4 个功能格子（点击 → 弹自己专属 Modal 或直接派任务）
  const grid = el('div', { class: 'help-action-grid' });
  const card = (icon, titleKey, descKey, onclick) => {
    const node = el('div', {
      class: 'help-action-card' + (online ? '' : ' disabled'),
      onclick: online ? onclick : () => toast(t('help_task_offline'), 'warning'),
    }, [
      el('div', { class: 'hac-icon' }, icon),
      el('div', { class: 'hac-text' }, [
        el('div', { class: 'hac-title' }, t(titleKey)),
        el('div', { class: 'hac-desc' }, t(descKey)),
      ]),
    ]);
    return node;
  };
  grid.appendChild(card('🔓', 'help_btn_open', 'help_btn_open_desc', showHelperAddModal));
  grid.appendChild(card('🔑', 'help_btn_get_token', 'help_btn_get_token_desc', showHelperGetTokenModal));
  grid.appendChild(card('🔒', 'help_btn_chpwd', 'help_btn_chpwd_desc', () => showHelperChpwdModal()));
  grid.appendChild(card('🔗', 'help_btn_bind', 'help_btn_bind_desc', () => showHelperBindModal()));
  body.appendChild(grid);

  body.appendChild(el('p', { class: 'help-actions-tip' }, t('help_actions_tip_row')));
}

async function loadHelperTokens() {
  const body = $('helpTokensBody');
  if (!body) return;
  try {
    const r = await api.get('/api/helper/tokens');
    if (!r.success || !r.tokens || r.tokens.length === 0) {
      clear(body);
      body.appendChild(el('p', { class: 'help-status-hint' }, t('help_tokens_empty')));
      return;
    }
    clear(body);
    const tbl = el('table', { class: 'tbl help-tokens-tbl' });
    const thead = el('thead', {}, el('tr', {}, [
      el('th', {}, t('help_tokens_label')),
      el('th', {}, t('help_tokens_token')),
      el('th', {}, t('help_tokens_created')),
      el('th', {}, t('help_tokens_last_used')),
      el('th', {}, t('help_tokens_platform')),
      el('th', {}, t('help_tokens_version')),
      el('th', { style: 'width:80px' }, t('help_tokens_op')),
    ]));
    tbl.appendChild(thead);
    const tbody = el('tbody');
    for (const item of r.tokens) {
      const created = item.created_at ? new Date(item.created_at * 1000).toLocaleString() : '-';
      const lastUsed = item.last_used_at ? new Date(item.last_used_at * 1000).toLocaleString() : '-';
      tbody.appendChild(el('tr', {}, [
        el('td', {}, item.label || '-'),
        el('td', { class: 'mono' }, item.token || '-'),
        el('td', {}, created),
        el('td', {}, lastUsed),
        el('td', {}, item.platform || '-'),
        el('td', {}, item.version || '-'),
        el('td', {},
          el('button', {
            class: 'btn btn-d btn-tiny',
            onclick: () => revokeHelperToken(item.token),
          }, t('help_tokens_revoke')),
        ),
      ]));
    }
    tbl.appendChild(tbody);
    body.appendChild(tbl);
  } catch (e) {
    clear(body);
    body.appendChild(el('p', { class: 'help-status-hint' },
      t('toast_load_fail') + (e.message || '')));
  }
}

async function loadHelperDownloadInfo() {
  const body = $('helpInstallBody');
  if (!body) return;
  try {
    const info = await api.get('/api/helper/download-info');
    clear(body);
    body.appendChild(el('p', { class: 'help-install-intro' }, t('help_install_intro')));
    if (info && info.exe) {
      const fmt = (bytes) => bytes ? (bytes / 1024 / 1024).toFixed(1) + ' MB' : '';
      const list = el('ul', { class: 'help-install-dl' }, [
        el('li', {}, el('a', { href: info.exe.url, download: '' },
          `${t('help_install_dl_exe')} (${fmt(info.exe.size)})`)),
        info.install_script && el('li', {}, el('a', {
          href: info.install_script.url, download: '',
        }, t('help_install_dl_install'))),
        info.uninstall_script && el('li', {}, el('a', {
          href: info.uninstall_script.url, download: '',
        }, t('help_install_dl_uninstall'))),
      ].filter(Boolean));
      body.appendChild(list);
    } else {
      body.appendChild(el('p', { class: 'help-install-missing' }, t('help_install_missing')));
    }
    const steps = el('ol', { class: 'help-install-steps' });
    ['help_install_step1', 'help_install_step2', 'help_install_step3', 'help_install_step4']
      .forEach((k) => steps.appendChild(el('li', {}, t(k))));
    body.appendChild(steps);
  } catch (e) {
    clear(body);
    body.appendChild(el('p', { class: 'help-status-hint' },
      t('toast_load_fail') + (e.message || '')));
  }
}

// helper toast 30s 防抖：网络抖动场景下 helper 会在 60s 心跳超时窗口内
// 反复 offline ↔ online 翻转。如果每次翻转都弹 toast，用户 2 分钟内可能
// 看到 4-6 次 toast 闪烁。这里用最近一次 toast 时间戳做截流，30s 内同方向
// 的状态变更不重复弹。
let _helperToastLastTs = 0;
let _helperToastLastDir = null;  // 'online' | 'offline'
const HELPER_TOAST_DEBOUNCE_MS = 30 * 1000;

function _toastHelperStatusTransition(online) {
  const now = Date.now();
  const dir = online ? 'online' : 'offline';
  // 同方向且 30s 内 → 静音
  if (_helperToastLastDir === dir && now - _helperToastLastTs < HELPER_TOAST_DEBOUNCE_MS) {
    return;
  }
  _helperToastLastTs = now;
  _helperToastLastDir = dir;
  if (online) toast(t('toast_help_online'), 'success');
  else toast(t('toast_help_offline'), 'warning');
}

async function refreshHelperStatus() {
  if (!helperEnabled()) return;
  try {
    const r = await api.get('/api/helper/status');
    const wasLoaded = window.HELPER_STATUS.loaded;
    const wasOnline = window.HELPER_STATUS.online;
    window.HELPER_STATUS = {
      loaded: true,
      online: !!r.online,
      helper_id: r.helper_id || null,
      version: r.version || null,
      platform: r.platform || null,
      last_seen: r.last_seen || null,
      min_version: r.min_helper_version || null,
      version_ok: r.online ? !!r.version_ok : true,
    };
    renderHelpStatus(window.HELPER_STATUS);
    if (wasOnline !== window.HELPER_STATUS.online) {
      loadHelperTokens();
      // 第一次加载（wasLoaded=false）不弹 toast，避免每次进 Help 页都弹一次
      if (wasLoaded) {
        _toastHelperStatusTransition(window.HELPER_STATUS.online);
      }
    }
  } catch (e) {
    if (e.status !== 401 && e.status !== 403 && e.status !== 404) {
      console.warn('[helper] status poll failed:', e);
    }
  }
}

function startHelperPolling() {
  if (!helperEnabled()) return;
  if (_helperPollTimer) return;
  const loop = async () => {
    if (!helperEnabled()) {
      _helperPollTimer = null;
      return;
    }
    await refreshHelperStatus();
    // 主表格视图也持续轮询：用户在表格里点行内 🔓 🔑 等按钮时需要 HELPER_STATUS
    // 区分快慢周期：用户在 Help 页 → 1.5-5s；其他页 → 15s（省 RTT）
    let interval = (Date.now() < _helperPollFastUntil)
      ? HELPER_POLL_FAST : HELPER_POLL_INTERVAL;
    if (S.view !== 'help') interval = Math.max(interval, 15000);
    _helperPollTimer = setTimeout(loop, interval);
  };
  loop();
}

async function launchHelper() {
  try {
    const r = await api.post('/api/helper/provision-token',
      { label: 'web-launch ' + new Date().toLocaleString() });
    if (!r.success || !r.token) {
      toast(t('toast_help_provision_fail') + (r.error || ''), 'error');
      return;
    }
    const token = r.token;
    const server = location.origin;
    const url = `emailhelper://connect?token=${encodeURIComponent(token)}&server=${encodeURIComponent(server)}`;
    // .exe 命令：用户拷出来到 cmd / PowerShell 跑（quote 处理跨 shell 复制粘贴稳）
    const exeCmd = `EmailHelper.exe --token ${token} --server ${server}`;
    const srcCmd = `python helper/main.py --no-tray --debug --token ${token} --server ${server}`;

    // 弹 Modal 显示 3 个方案的命令，让用户在 URL 协议未注册时也能手动启动
    $('helperLaunchUrl').value = url;
    $('helperLaunchExeCmd').value = exeCmd;
    $('helperLaunchSrcCmd').value = srcCmd;
    openModal('helperLaunchModal');

    _helperPollFastUntil = Date.now() + 30 * 1000;
    // 浏览器拉起协议（已注册的话会秒连；未注册的话 user 看到 modal 后能复制 .exe 命令兜底）
    window.location.href = url;
    setTimeout(() => loadHelperTokens(), 500);
  } catch (e) {
    toast(t('toast_help_provision_fail') + (e.message || ''), 'error');
  }
}

function _copyLaunchField(fieldId) {
  const el = $(fieldId);
  if (!el || !el.value) return;
  try {
    el.select();
    el.setSelectionRange(0, el.value.length);
    document.execCommand('copy');
    toast(t('toast_copied'), 'success');
  } catch {
    // 现代浏览器 fallback 到 navigator.clipboard
    if (navigator.clipboard) {
      navigator.clipboard.writeText(el.value).then(
        () => toast(t('toast_copied'), 'success'),
        () => toast(t('toast_clip_fail'), 'error'),
      );
    }
  }
}

async function revokeHelper() {
  if (!confirm('确认撤销当前 helper token 吗？\n（撤销后 Helper 会断开，下次需要重新绑定）')) return;
  try {
    const r = await api.post('/api/helper/revoke', {});
    if (r.success) {
      toast(t('toast_help_token_revoked'), 'success');
      _helperPollFastUntil = Date.now() + 5000;
      refreshHelperStatus();
      loadHelperTokens();
    } else {
      toast(t('toast_help_revoke_fail') + (r.error || ''), 'error');
    }
  } catch (e) {
    toast(t('toast_help_revoke_fail') + (e.message || ''), 'error');
  }
}

async function revokeHelperToken(token) {
  if (!confirm('撤销该 token？')) return;
  try {
    const r = await api.post('/api/helper/revoke', { token });
    if (r.success) {
      toast(t('toast_help_token_revoked'), 'success');
      loadHelperTokens();
      refreshHelperStatus();
    } else {
      toast(t('toast_help_revoke_fail') + (r.error || ''), 'error');
    }
  } catch (e) {
    toast(t('toast_help_revoke_fail') + (e.message || ''), 'error');
  }
}

// ── Helper 任务执行 Modal（带 SSE 实时日志） ─────────────────

let _helperLogSrc = null;
let _helperCurrentTaskId = null;
let _helperTaskStartTs = 0;
let _helperElapsedTimer = null;

function openHelperTaskModal(titleKey) {
  const titleEl = $('helperTaskTitle');
  const statusEl = $('helperTaskStatus');
  const logEl = $('helperTaskLog');
  const cancelBtn = $('helperTaskCancelTask');
  if (titleEl) titleEl.textContent = t(titleKey || 'help_task_title');
  if (statusEl) { statusEl.textContent = t('help_task_running'); statusEl.className = 'help-task-status running'; }
  if (logEl) clear(logEl);
  _helperCurrentTaskId = null;
  _helperTaskStartTs = Date.now();
  if (cancelBtn) { cancelBtn.style.display = 'none'; cancelBtn.disabled = false; }
  openModal('helperTaskModal');
  // 实时显示已运行时长
  if (_helperElapsedTimer) clearInterval(_helperElapsedTimer);
  _helperElapsedTimer = setInterval(() => {
    const elapsed = Math.floor((Date.now() - _helperTaskStartTs) / 1000);
    const elapsedEl = $('helperTaskElapsed');
    if (elapsedEl) elapsedEl.textContent = `⏱ ${elapsed}s`;
  }, 500);
  // 订阅 SSE
  try {
    if (_helperLogSrc) _helperLogSrc.close();
    _helperLogSrc = new EventSource('/api/helper/logs', { withCredentials: true });
    _helperLogSrc.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data && data.message) {
          appendHelperLog(data.message, data.level || 'info');
          // 服务端派单时会推 "task_id=..." 字符串；从中解析出 task_id 用于取消
          const m = /task_id=([a-zA-Z0-9_-]+)/.exec(data.message);
          if (m && !_helperCurrentTaskId) {
            _helperCurrentTaskId = m[1];
            const cb = $('helperTaskCancelTask');
            if (cb) cb.style.display = '';
          }
        }
      } catch { /* ignore */ }
    };
    _helperLogSrc.onerror = () => {
      appendHelperLog('日志流断开', 'warning');
      if (_helperLogSrc) { _helperLogSrc.close(); _helperLogSrc = null; }
    };
  } catch (e) {
    appendHelperLog('SSE 启动失败: ' + (e.message || ''), 'error');
  }
}

function closeHelperLogStream() {
  if (_helperLogSrc) {
    try { _helperLogSrc.close(); } catch { /* ignore */ }
    _helperLogSrc = null;
  }
  if (_helperElapsedTimer) { clearInterval(_helperElapsedTimer); _helperElapsedTimer = null; }
  _helperCurrentTaskId = null;
}

function appendHelperLog(msg, level) {
  const logEl = $('helperTaskLog');
  if (!logEl) return;
  const line = el('div', { class: 'log-line log-' + (level || 'info') }, String(msg));
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

function setHelperTaskDone(ok, msg) {
  const statusEl = $('helperTaskStatus');
  if (!statusEl) return;
  if (ok) {
    statusEl.textContent = t('help_task_success') + (msg ? `：${msg}` : '');
    statusEl.className = 'help-task-status success';
  } else {
    statusEl.textContent = t('help_task_failed') + (msg ? `：${msg}` : '');
    statusEl.className = 'help-task-status error';
  }
  // 任务结束后停 elapsed timer + 隐藏取消按钮
  if (_helperElapsedTimer) { clearInterval(_helperElapsedTimer); _helperElapsedTimer = null; }
  const cb = $('helperTaskCancelTask');
  if (cb) cb.style.display = 'none';
}

async function cancelHelperTask() {
  if (!_helperCurrentTaskId) return;
  const cb = $('helperTaskCancelTask');
  if (cb) cb.disabled = true;
  appendHelperLog(`▶ 请求取消任务 task_id=${_helperCurrentTaskId}...`, 'warning');
  try {
    await api.post('/api/helper/cancel-task', { task_id: _helperCurrentTaskId });
  } catch (e) {
    appendHelperLog('取消请求失败: ' + (e.message || ''), 'error');
  }
}

// ── 批量 Helper 操作 ───────────────────────────────────────────

let _helperBatchAbortController = null;

async function batchHelperOpen() {
  return _doBatchHelper('open_mailbox', 'help_btn_batch_open');
}

async function batchHelperGetToken() {
  return _doBatchHelper('get_ms_token', 'help_btn_batch_token');
}

async function batchHelperBindRecovery() {
  return _doBatchHelper('bind_recovery_email', 'help_btn_batch_bind');
}

async function _doBatchHelper(action, titleKey) {
  if (!window.HELPER_STATUS || !window.HELPER_STATUS.online) {
    toast(t('help_task_offline'), 'warning'); return;
  }
  const ids = Array.from(S.selected);
  if (ids.length === 0) { toast(t('toast_select_acc'), 'warning'); return; }
  if (!confirm(t('confirm_batch_helper', { n: ids.length, action: t(titleKey) }))) return;

  // 重置 Modal
  $('helperBatchTitle').textContent = t(titleKey);
  $('helperBatchInfo').textContent = t('help_batch_info', { n: ids.length });
  $('helperBatchFill').style.width = '0%';
  $('helperBatchStatus').textContent = '';
  clear($('helperBatchLog'));
  $('helperBatchAbort').style.display = '';
  $('helperBatchAbort').disabled = false;
  $('helperBatchDone').style.display = 'none';
  openModal('helperBatchModal');

  _helperBatchAbortController = new AbortController();
  let success = 0, fail = 0, completed = 0;
  try {
    await api.stream(
      '/api/helper/batch/mailbox',
      { action, account_ids: ids, timeout: 180 },
      (msg) => {
        if (msg.type === 'progress') {
          completed++;
          if (msg.success) success++; else fail++;
          $('helperBatchFill').style.width =
            `${((msg.current / msg.total) * 100).toFixed(1)}%`;
          $('helperBatchStatus').textContent =
            t('help_batch_progress', { current: msg.current, total: msg.total, ok: success, fail });
          const line = el('div', {
            class: 'log-line log-' + (msg.success ? 'info' : 'error'),
          }, `[${msg.current}/${msg.total}] ${msg.email}: ${msg.success ? '✅' : '❌ ' + (msg.error || '失败')}`);
          $('helperBatchLog').appendChild(line);
          $('helperBatchLog').scrollTop = $('helperBatchLog').scrollHeight;
        } else if (msg.type === 'done') {
          $('helperBatchStatus').textContent = t('help_batch_done', { ok: msg.success, fail: msg.fail });
          $('helperBatchAbort').style.display = 'none';
          $('helperBatchDone').style.display = '';
          if (msg.fail === 0) toast(t('help_batch_done', { ok: msg.success, fail: 0 }), 'success');
          else toast(t('help_batch_done', { ok: msg.success, fail: msg.fail }), 'warning');
          if (action === 'get_ms_token') loadAccounts();
        }
      },
    );
  } catch (e) {
    appendBatchHelperLog('批量执行异常: ' + (e.message || ''), 'error');
    $('helperBatchAbort').style.display = 'none';
    $('helperBatchDone').style.display = '';
  } finally {
    _helperBatchAbortController = null;
  }
}

function appendBatchHelperLog(msg, level) {
  const logEl = $('helperBatchLog');
  if (!logEl) return;
  const line = el('div', { class: 'log-line log-' + (level || 'info') }, String(msg));
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

function abortBatchHelper() {
  if (_helperBatchAbortController) {
    try { _helperBatchAbortController.abort(); } catch { /* ignore */ }
    appendBatchHelperLog('▶ 用户请求中止...', 'warning');
    $('helperBatchAbort').disabled = true;
  }
}

async function testHelperPing() {
  openHelperTaskModal('help_btn_test_ping');
  appendHelperLog('▶ 派发 ping 测试连通性...', 'info');
  try {
    const r = helperResponseGuard(await api.post('/api/helper/dispatch',
      { action: 'ping', params: {}, timeout: 10 }));
    appendHelperLog(JSON.stringify(r), r.success ? 'info' : 'error');
    setHelperTaskDone(r.success, r.error || '');
  } catch (e) {
    setHelperTaskDone(false, e.message || '');
  } finally {
    setTimeout(closeHelperLogStream, 1500);
  }
}

// ── 自动添加邮箱（手工模式，需要填 email + password 用于"新账号"） ──

function showHelperAddModal() {
  if (!window.HELPER_STATUS || !window.HELPER_STATUS.online) {
    toast(t('help_task_offline'), 'warning'); return;
  }
  $('helperAddEmail').value = '';
  $('helperAddPassword').value = '';
  $('helperAddErr').textContent = '';
  const sel = $('helperAddGroup'); clear(sel);
  for (const g of S.groups) sel.appendChild(el('option', {}, g.name));
  openModal('helperAddModal');
}

async function doHelperAdd() {
  const errEl = $('helperAddErr'); errEl.textContent = '';
  const email = $('helperAddEmail').value.trim();
  const pwd = $('helperAddPassword').value;
  const group = $('helperAddGroup').value;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errEl.textContent = t('help_task_email_invalid'); return;
  }
  if (!pwd) { errEl.textContent = '请填入邮箱密码'; return; }
  const btn = $('btnHelperDoAdd'); btn.disabled = true;
  closeModal('helperAddModal');
  openHelperTaskModal('help_btn_open');
  try {
    appendHelperLog(`▶ 1/2 请求服务器派发 "登录邮箱" → ${email}`, 'info');
    const r1 = helperResponseGuard(await api.post('/api/helper/mailbox/open',
      { email, email_password: pwd, timeout: 180 }));
    if (!r1.success) {
      appendHelperLog('open_mailbox 失败: ' + (r1.error || ''), 'error');
      setHelperTaskDone(false, r1.error || ''); return;
    }
    appendHelperLog('✓ 邮箱浏览器已打开', 'info');
    appendHelperLog('▶ 2/2 请求服务器派发 "OAuth2 + 落库"', 'info');
    const r2 = helperResponseGuard(await api.post('/api/helper/mailbox/get-token',
      { email, group, timeout: 180 }));
    if (r2.success) {
      const msg = (r2.updated ? t('toast_help_updated', { email: r2.email })
                              : t('toast_help_added', { email: r2.email }));
      setHelperTaskDone(true, msg);
      toast(msg, 'success');
      loadAccounts();
    } else {
      setHelperTaskDone(false, r2.error || '');
    }
  } catch (e) {
    setHelperTaskDone(false, e.message || '');
  } finally {
    btn.disabled = false;
    setTimeout(closeHelperLogStream, 2000);
  }
}

// ── 获取 Token：弹窗只问 email（针对未入库的邮箱；已入库走表格行按钮） ──

function showHelperGetTokenModal() {
  if (!window.HELPER_STATUS || !window.HELPER_STATUS.online) {
    toast(t('help_task_offline'), 'warning'); return;
  }
  const email = prompt('要获取 refresh_token 的邮箱地址（如果是表格里已有的账号，请直接点该行的 🔑 按钮）：', '');
  if (!email) return;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    toast(t('help_task_email_invalid'), 'error'); return;
  }
  openHelperTaskModal('help_btn_get_token');
  appendHelperLog(`▶ 请求服务器派发 "获取 refresh_token" → ${email}`, 'info');
  api.post('/api/helper/mailbox/get-token', { email, timeout: 180 })
    .then(helperResponseGuard)
    .then((r) => {
      if (r.success) {
        const msg = (r.updated ? t('toast_help_updated', { email: r.email })
                                : t('toast_help_added', { email: r.email }));
        setHelperTaskDone(true, msg);
        toast(msg, 'success');
        loadAccounts();
      } else {
        setHelperTaskDone(false, r.error || '');
      }
    })
    .catch((e) => setHelperTaskDone(false, e.message || ''))
    .finally(() => setTimeout(closeHelperLogStream, 2000));
}

// ── 改密 ──────────────────────────────────────────────────────

function showHelperChpwdModal(email) {
  if (!window.HELPER_STATUS || !window.HELPER_STATUS.online) {
    toast(t('help_task_offline'), 'warning'); return;
  }
  // Help 页面手工进入：让用户填 email + 旧密码；
  // 表格行进入（helperRowChpwd）已经预填 email 并设置 dataset.accountId
  if (!email && !$('helperChpwdEmail').value) {
    email = prompt('要改密的邮箱地址：', '');
    if (!email) return;
    $('helperChpwdEmail').value = email;
    $('helperChpwdEmail').readOnly = false;  // 手工模式：可改
    delete $('helperChpwdEmail').dataset.accountId;
  } else if (email) {
    $('helperChpwdEmail').value = email;
    $('helperChpwdEmail').readOnly = false;
    delete $('helperChpwdEmail').dataset.accountId;
  } else {
    // 表格行入口 helperRowChpwd 已设置好 dataset.accountId & 占位 oldPwd
    $('helperChpwdEmail').readOnly = true;
  }
  $('helperChpwdNew').value = '';
  $('helperChpwdErr').textContent = '';
  openModal('helperChangePwdModal');
}

async function doHelperChpwd() {
  const errEl = $('helperChpwdErr'); errEl.textContent = '';
  const accountId = $('helperChpwdEmail').dataset.accountId;
  const titleKey = $('helperChpwdEmail').dataset.titleKey || 'help_btn_chpwd';
  const email = $('helperChpwdEmail').value.trim();
  const oldPwd = $('helperChpwdOld').value;
  const newPwd = $('helperChpwdNew').value;
  if (!newPwd || newPwd.length < 8) {
    errEl.textContent = t('help_task_password_short'); return;
  }
  if (!accountId && !oldPwd) {
    errEl.textContent = '请填入当前密码'; return;
  }
  const btn = $('btnHelperDoChpwd'); btn.disabled = true;
  closeModal('helperChangePwdModal');
  // 行内入口（带 accountId）走 SSE 批量链路绕 Cloudflare 100s；
  // 手工模式仍走单条 POST（用户主动等，可接受偶发 524）
  if (accountId) {
    btn.disabled = false;
    return runHelperSingleSse(
      'change_email_password', Number(accountId),
      { new_password: newPwd }, titleKey,
      () => {
        toast(t('toast_help_change_pwd_ok'), 'success');
        loadAccounts();
      },
      { intro: `▶ 请求服务器派发 "修改密码" → ${email}（SSE）` },
    );
  }
  openHelperTaskModal(titleKey);
  try {
    appendHelperLog(`▶ 请求服务器派发 "修改密码" → ${email}`, 'info');
    const body = { email, email_password: oldPwd, new_password: newPwd, timeout: 300 };
    const r = helperResponseGuard(await api.post('/api/helper/mailbox/change-password', body));
    if (r.success) {
      if (r.db_update_failed) {
        // 改密在邮箱端成功了但 DB 没同步 —— 必须显眼提醒，否则下次登录用
        // 旧密码会风控锁号。这里不弹纯绿色 toast 误导用户。
        appendHelperLog(
          `⚠ 邮箱端密码已修改成功，但服务端写回 DB 失败：` +
          `${r.db_update_failed}。请到「账号」页面手工把该账号的密码字段` +
          `更新为新密码，否则下次自动登录会被 Outlook 风控拦下。`,
          'warning',
        );
        setHelperTaskDone(true, '⚠ DB 未同步，请手工修正账号密码');
        toast(
          'Helper 改密成功，但服务端 DB 未同步，请手工核对账号密码',
          'warning',
        );
      } else {
        setHelperTaskDone(true, '');
        toast(t('toast_help_change_pwd_ok'), 'success');
      }
    } else {
      setHelperTaskDone(false, r.error || '');
    }
  } catch (e) {
    setHelperTaskDone(false, e.message || '');
  } finally {
    btn.disabled = false;
    setTimeout(closeHelperLogStream, 2000);
  }
}

// ── 绑定辅助邮箱 ──────────────────────────────────────────────

function showHelperBindModal(email) {
  if (!window.HELPER_STATUS || !window.HELPER_STATUS.online) {
    toast(t('help_task_offline'), 'warning'); return;
  }
  if (!email && !$('helperBindEmail').value) {
    email = prompt('要绑定辅助邮箱的邮箱地址：', '');
    if (!email) return;
    $('helperBindEmail').value = email;
    $('helperBindEmail').readOnly = false;
    delete $('helperBindEmail').dataset.accountId;
  } else if (email) {
    $('helperBindEmail').value = email;
    $('helperBindEmail').readOnly = false;
    delete $('helperBindEmail').dataset.accountId;
  } else {
    $('helperBindEmail').readOnly = true;
  }
  $('helperBindSuffix').value = '';
  $('helperBindAlias').value = '';
  $('helperBindErr').textContent = '';
  openModal('helperBindRecoveryModal');
}

async function doHelperBind() {
  const errEl = $('helperBindErr'); errEl.textContent = '';
  const accountId = $('helperBindEmail').dataset.accountId;
  const titleKey = $('helperBindEmail').dataset.titleKey || 'help_btn_bind';
  const email = $('helperBindEmail').value.trim();
  const aliasSuffix = $('helperBindSuffix').value.trim();
  const aliasEmail = $('helperBindAlias').value.trim();
  const btn = $('btnHelperDoBind'); btn.disabled = true;
  closeModal('helperBindRecoveryModal');
  // 行内入口（带 accountId）走 SSE 批量链路；手工模式 fallback POST
  if (accountId) {
    btn.disabled = false;
    const extras = {};
    if (aliasSuffix) extras.alias_suffix = aliasSuffix;
    if (aliasEmail) extras.alias_email = aliasEmail;
    return runHelperSingleSse(
      'bind_recovery_email', Number(accountId),
      extras, titleKey,
      () => toast(t('toast_help_bind_ok'), 'success'),
      { intro: `▶ 请求服务器派发 "绑定辅助邮箱" → ${email}（SSE）` },
    );
  }
  openHelperTaskModal(titleKey);
  try {
    appendHelperLog(`▶ 请求服务器派发 "绑定辅助邮箱" → ${email}`, 'info');
    const body = {
      email,
      alias_suffix: aliasSuffix || null,
      alias_email: aliasEmail || null,
      timeout: 300,
    };
    const r = helperResponseGuard(await api.post('/api/helper/mailbox/bind-recovery', body));
    if (r.success) {
      setHelperTaskDone(true, '');
      toast(t('toast_help_bind_ok'), 'success');
    } else {
      setHelperTaskDone(false, r.error || '');
    }
  } catch (e) {
    setHelperTaskDone(false, e.message || '');
  } finally {
    btn.disabled = false;
    setTimeout(closeHelperLogStream, 2000);
  }
}

// ───────── Theme & Lang ─────────
const THEME_ORDER = ['cyber', 'light', 'dark'];
const THEME_ICON = { cyber: '🌐', light: '☀️', dark: '🌙' };
const toggleTheme = () => {
  const i = THEME_ORDER.indexOf(S.theme);
  setTheme(THEME_ORDER[(i + 1) % THEME_ORDER.length] || 'cyber');
};
function setTheme(theme) {
  if (!THEME_ORDER.includes(theme)) theme = 'cyber';
  S.theme = theme;
  document.body.dataset.theme = theme;
  const btn = $('themeBtn');
  if (btn) {
    btn.textContent = THEME_ICON[theme];
    btn.title = (window.I18N && window.I18N.t)
      ? (window.I18N.t('theme_btn_title') + ' · ' + window.I18N.t('theme_' + theme))
      : '';
  }
  if (S.ready) api.put('/api/settings', { key: 'theme', value: theme }).catch(() => {});
  if (S.view === 'settings') renderSettings();
}

const toggleLang = () => setLang(S.lang === 'zh' ? 'en' : 'zh');
function setLang(lang) {
  S.lang = lang;
  $('langBtn').textContent = lang === 'zh' ? '中/EN' : 'EN/中';
  if (window.I18N) {
    window.I18N.setLang(lang);
    window.I18N.applyToDom();
  }
  if (S.ready) api.put('/api/settings', { key: 'language', value: lang }).catch(() => {});
  if (S.view === 'settings') renderSettings();
  else if (S.view === 'dashboard') renderDashboard();
  else if (S.view === 'help') renderHelp();
  else { showTableView(); renderAccounts(); }
}

// ───────── Wiring (事件委托，无 inline 处理) ─────────
$('navAll').addEventListener('click', () => selectGroup('全部'));
$('navDash').addEventListener('click', () => showView('dashboard'));
$('navSettings').addEventListener('click', () => showView('settings'));
$('navHelp').addEventListener('click', () => showView('help'));
$('btnHelperDoAdd').addEventListener('click', doHelperAdd);
$('btnHelperDoChpwd').addEventListener('click', doHelperChpwd);
$('btnHelperDoBind').addEventListener('click', doHelperBind);
$('helperTaskClose').addEventListener('click', closeHelperLogStream);
$('helperTaskCancelBtn').addEventListener('click', closeHelperLogStream);
$('helperTaskCancelTask').addEventListener('click', cancelHelperTask);
$('btnBatchHelperOpen').addEventListener('click', batchHelperOpen);
$('btnBatchHelperToken').addEventListener('click', batchHelperGetToken);
$('btnBatchHelperBind').addEventListener('click', batchHelperBindRecovery);
$('helperBatchAbort').addEventListener('click', abortBatchHelper);
$('btnCopyLaunchUrl').addEventListener('click', () => _copyLaunchField('helperLaunchUrl'));
$('btnCopyLaunchExe').addEventListener('click', () => _copyLaunchField('helperLaunchExeCmd'));
$('btnCopyLaunchSrc').addEventListener('click', () => _copyLaunchField('helperLaunchSrcCmd'));
$('themeBtn').addEventListener('click', toggleTheme);
$('langBtn').addEventListener('click', toggleLang);
$('addGroupBtn').addEventListener('click', addGroup);
$('searchInp').addEventListener('input', filterAccountsDebounced);
$('selAll').addEventListener('change', (e) => toggleSelAll(e.target.checked));
$('accBody').addEventListener('pointerdown', startAccountSelectionDrag);
$('accBody').addEventListener('click', swallowAccountSelectionClick, true);
$('btnImport').addEventListener('click', showImportModal);
$('btnExport').addEventListener('click', showExportModal);
$('btnDoExport').addEventListener('click', doExport);
$('exportPassword').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') doExport();
});
$('exportScope').addEventListener('change', refreshExportScopeHint);
$('btnMove').addEventListener('click', showMoveGroup);
$('btnBatchCheck').addEventListener('click', batchCheck);
$('btnBatchSend').addEventListener('click', showBatchSend);
$('btnSetPublic').addEventListener('click', () => batchSetPublic(true));
$('btnUnsetPublic').addEventListener('click', () => batchSetPublic(false));
{
  const requireTokenToggle = document.getElementById('codeRequireTokenToggle');
  if (requireTokenToggle) {
    requireTokenToggle.addEventListener('change', (e) => {
      setCodeReceiverRequireToken(e.target.checked);
    });
  }
}
{
  // 批量改凭证按钮 / 弹窗一键复制（用块级作用域避免污染顶层 const）
  const rotateBtn = document.getElementById('btnRotateTokens');
  if (rotateBtn) rotateBtn.addEventListener('click', batchRotateTokens);
  const copyAll = document.getElementById('btnCopyTokens');
  if (copyAll) {
    copyAll.addEventListener('click', () => {
      const ta = document.getElementById('tokenList');
      if (!ta || !ta.value) return;
      copyText(ta.value, 'toast_copied');
    });
  }
}
$('btnDelete').addEventListener('click', deleteSelected);
$('btnImportClipboard').addEventListener('click', importFromClipboard);
$('btnDoImport').addEventListener('click', doImport);
$('btnSaveCredentials').addEventListener('click', saveCredentials);
$('btnRefreshEmails').addEventListener('click', () => {
  // UI 兜底：点击瞬间禁用 1.5s，与 EMAIL_LIST_MIN_INTERVAL_MS 对齐。
  // 即使浏览器扩展 / 用户疯狂点击，DOM 层也只能每 1.5s 触发一次 loadEmails。
  const btn = $('btnRefreshEmails');
  if (btn.disabled) return;
  btn.disabled = true;
  setTimeout(() => { btn.disabled = false; }, EMAIL_LIST_MIN_INTERVAL_MS);
  loadEmails();
});
$('emailFolder').addEventListener('change', loadEmails);
$('emailSearch').addEventListener('input', filterEmailListDebounced);
$('btnCompose').addEventListener('click', () => showCompose());
$('btnReply').addEventListener('click', replyEmail);
$('btnDelEmail').addEventListener('click', deleteCurrentEmail);
$('btnDoSend').addEventListener('click', doSendEmail);
$('btnDoBatchSend').addEventListener('click', doBatchSend);
$('btnDoMove').addEventListener('click', doMoveGroup);
$('btnCopyDetail').addEventListener('click', copyAccountInfo);

// ───────── 移动端侧边栏抽屉 ─────────
// 只在 ≤768px 生效；桌面端 CSS 自动忽略 .open 类
(() => {
  const sidebar = $('sidebar');
  const toggle = $('sbToggle');
  const backdrop = $('sbBackdrop');
  if (!sidebar || !toggle || !backdrop) return;

  const mq = window.matchMedia('(max-width: 768px)');

  function setOpen(open) {
    sidebar.classList.toggle('open', open);
    toggle.classList.toggle('open', open);
    backdrop.classList.toggle('show', open);
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    // 打开时锁定 body 滚动，关闭时恢复
    document.body.style.overflow = open ? 'hidden' : '';
  }
  function closeOnMobile() {
    if (mq.matches) setOpen(false);
  }

  toggle.addEventListener('click', () => setOpen(!sidebar.classList.contains('open')));
  backdrop.addEventListener('click', () => setOpen(false));

  // 点击侧边栏内的导航项或分组项后自动收起（不影响分组的右键菜单按钮 ⋯）
  sidebar.addEventListener('click', (e) => {
    if (e.target.closest('.grp-ctx')) return;
    if (e.target.closest('.sb-sec-h button')) return;
    if (e.target.closest('.nav-btn, .grp-item, .sb-logout-btn')) closeOnMobile();
  });

  // 键盘 ESC 关闭
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && sidebar.classList.contains('open')) setOpen(false);
  });

  // 从移动端切回桌面端时，清理状态
  const handleMq = (e) => { if (!e.matches) setOpen(false); };
  if (mq.addEventListener) mq.addEventListener('change', handleMq);
  else if (mq.addListener) mq.addListener(handleMq); // 旧 Safari 兼容
})();

// ───────── Init ─────────
async function init() {
  try {
    // 1) 必须先 loadMe 拿 is_owner — applyOwnerVisibility 与 loadPublicIds 都
    //    依赖 S.user.is_owner，否则站长按钮 / 接码列在登录后不会自动显现
    await loadMe();
    applyOwnerVisibility();
    updateUserDisplay();

    // 2) settings / groups / accounts(+publicIds) 之间互不依赖，全部并行：
    //    远程网络下每个请求 30-100ms，串行 → 并行能省 ~2 个 RTT。
    //    accounts 列表的渲染依赖 i18n 已就绪（按钮文案 / 占位符），所以等
    //    settings 拿到之后再切语言、再 loadAccounts；groups 与之同期发起。
    const [, settingsResult] = await Promise.allSettled([
      loadGroups(),
      api.get('/api/settings'),
    ]);

    const settings = settingsResult.status === 'fulfilled'
      ? settingsResult.value : { theme: 'cyber', language: 'zh' };
    const savedTheme = settings.theme;
    S.theme = THEME_ORDER.includes(savedTheme) ? savedTheme : 'cyber';
    S.lang = settings.language || 'zh';
    S.codeReceiverRequireToken = settings.code_receiver_require_token !== '0';
    updateCodeRequireTokenToggle();
    document.body.dataset.theme = S.theme;
    const themeBtnInit = $('themeBtn');
    if (themeBtnInit) themeBtnInit.textContent = THEME_ICON[S.theme];
    $('langBtn').textContent = S.lang === 'zh' ? '中/EN' : 'EN/中';
    if (window.I18N) {
      window.I18N.setLang(S.lang);
      window.I18N.applyToDom();
    }
    await loadAccounts();
    S.ready = true;
    // xiaoxuan 登录后立即启动 helper 状态轮询（不需要进 Help 页才启动），
    // 这样主表格视图也能拿到 window.HELPER_STATUS.online 来 gate 行内按钮
    if (helperEnabled()) startHelperPolling();
  } catch (err) {
    if (err && err.status === 401) return;
    toast(t('toast_load_fail') + (err?.message || ''), 'error');
  }
}

// 启动：先看是否已登录；未登录则展示登录框
(async () => {
  // 先取注册开关 + 版本号
  try {
    const r = await fetch('/api/health', { credentials: 'include' });
    const j = await r.json();
    S.registerEnabled = !!j.register_enabled;
    const v = String(j.version || '').trim();
    if (v) {
      const tag = document.getElementById('app-version');
      if (tag) {
        // 'dev' 是 fallback 占位符（环境变量没设 + 拿不到 git SHA），直接
        // 显示为 'dev' 而不是 'vdev' 这种看起来像 bug 的拼接。git short SHA
        // 才加 'v' 前缀，让"v0e8c1f3a" 这种语义清晰
        if (v === 'dev') {
          tag.textContent = 'dev';
          tag.title = '本地 / 未部署版本（APP_VERSION 未设置且不在 git 仓库内）';
        } else {
          tag.textContent = 'v' + v;
          tag.title = '后端版本号 / 最近一次部署的 git commit short SHA';
        }
      }
    }
  } catch { /* ignore */ }

  const initialPath = window.location.pathname;

  if (await loadMe()) {
    showMain();
    await init();
    applyPath(initialPath);
    return;
  }

  // 未登录：根据 URL 决定登录还是注册模式
  const mode = (initialPath === '/register' && S.registerEnabled) ? 'register' : 'login';
  showAuthModal(mode);
})();

})();
