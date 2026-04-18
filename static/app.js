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
  theme: 'light', lang: 'zh', view: 'table', searchText: '',
  emailAccount: null, emails: [], allEmails: [], currentEmail: null,
  detailAccount: null,
  user: null,
  registerEnabled: true,
  authMode: 'login',
  ready: false,
  // 全部邮箱总数 + 各分组邮箱数（来自 /api/dashboard）
  counts: { total: 0, byGroup: {} },
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
  else if (path === '/oauth') showView('oauth');
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
async function request(url, options = {}) {
  const opts = { credentials: 'include', headers: {}, ...options };
  // 统一带上 cookie；显式声明，便于跨端口/HTTPS 一致
  opts.credentials = 'include';
  if (opts.body && !(opts.body instanceof FormData)) {
    opts.headers['Content-Type'] = 'application/json';
    if (typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);
  }
  const r = await fetch(url, opts);
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

// 解析后端错误 detail（JSON / 文本），便于在 toast 中展示
async function parseError(r) {
  try {
    const j = await r.clone().json();
    if (typeof j.detail === 'string') return j.detail;
    if (Array.isArray(j.detail)) return j.detail.map((d) => d.msg).join('; ');
    return JSON.stringify(j);
  } catch {
    try { return await r.text(); } catch { return r.statusText; }
  }
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
  get: (u) => request(u).then(readJson),
  post: (u, d) => request(u, { method: 'POST', body: d }).then(readJson),
  put: (u, d) => request(u, { method: 'PUT', body: d }).then(readJson),
  del: (u) => request(u, { method: 'DELETE' }).then(readJson),
  stream: async (u, d, onData) => {
    const r = await request(u, { method: 'POST', body: d });
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
  S.ready = false;
  showAuthModal('login');
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
  S.accounts = await api.get(url);
  S.selected.clear();
  $('selAll').checked = false;
  renderAccounts();
  // 顺带刷新侧边栏计数（账号变更时数字会跟着动）
  loadCounts();
}

function filterAccounts() {
  S.searchText = $('searchInp').value.toLowerCase();
  renderAccounts();
}

function filteredAccounts() {
  return S.searchText
    ? S.accounts.filter((a) =>
        (a.email || '').toLowerCase().includes(S.searchText) ||
        (a.remark || '').toLowerCase().includes(S.searchText))
    : S.accounts;
}

function renderAccounts() {
  const list = filteredAccounts();
  $('recCnt').textContent = t('record_count', { n: list.length });
  const tb = $('accBody');
  clear(tb);

  if (!list.length) {
    tb.appendChild(el('tr', {}, el('td', {
      colspan: 10,
      style: 'text-align:center;padding:40px;color:var(--text3)'
    }, t('empty'))));
    return;
  }

  list.forEach((a, i) => {
    const tr = el('tr', { class: S.selected.has(a.id) ? 'selected' : '', dataset: { id: a.id } });

    const cb = el('input', { type: 'checkbox' });
    cb.checked = S.selected.has(a.id);
    cb.addEventListener('change', () => toggleSel(a.id, cb.checked));
    tr.appendChild(el('td', {}, cb));
    tr.appendChild(el('td', {}, String(i + 1)));

    const emailCell = el('div', { class: 'email-cell' });
    const emailText = el('span', {
      class: 'email-t',
      title: a.email,
      onclick: () => showDetail(a.id),
    }, a.email);
    emailCell.appendChild(emailText);
    emailCell.appendChild(el('button', {
      class: 'email-copy',
      title: t('btn_copy'),
      onclick: (e) => { e.stopPropagation(); copyText(a.email); },
    }, t('btn_copy')));
    tr.appendChild(el('td', {}, emailCell));

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
      onclick: () => copyText(a.password)
    }, t('btn_copy')));
    tr.appendChild(el('td', {}, pwdCell));

    tr.appendChild(el('td', {}, a.group || ''));

    const statusCls = a.status === '正常' ? 'badge-ok' : a.status === '异常' ? 'badge-err' : 'badge-unk';
    tr.appendChild(el('td', {}, el('span', { class: 'badge ' + statusCls }, a.status)));
    tr.appendChild(el('td', {}, a.type || ''));
    tr.appendChild(el('td', {}, a.has_aws_code
      ? el('span', { style: 'color:var(--success)' }, t('d_yes')) : '-'));

    const tdRemark = el('td', { title: a.remark || '', ondblclick: () => editRemark(a.id, a.remark || '') });
    if (a.remark) tdRemark.textContent = a.remark;
    else tdRemark.appendChild(el('span', { style: 'color:var(--text3);font-size:11px' }, t('remark_double_click')));
    tr.appendChild(tdRemark);

    const ops = el('div', { class: 'op-btns' });
    ops.appendChild(el('button', { onclick: () => viewEmails(a.id) }, t('btn_view')));
    ops.appendChild(el('button', { onclick: () => showDetail(a.id) }, t('btn_detail')));
    ops.appendChild(el('button', { class: 'danger', onclick: () => deleteSingle(a.id) }, t('btn_del')));
    tr.appendChild(el('td', {}, ops));

    tb.appendChild(tr);
  });
}

function toggleSelAll(checked) {
  if (checked) filteredAccounts().forEach((a) => S.selected.add(a.id));
  else S.selected.clear();
  renderAccounts();
}

function toggleSel(id, checked) {
  if (checked) S.selected.add(id); else S.selected.delete(id);
  renderAccounts();
}

function copyText(text) {
  navigator.clipboard.writeText(text || '').then(() => toast(t('toast_copied'), 'success'));
}

async function editRemark(id, oldVal) {
  const val = prompt(t('prompt_remark'), oldVal);
  if (val === null) return;
  await api.put(`/api/accounts/${id}/remark`, { remark: val });
  await loadAccounts();
  toast(t('toast_remark_saved'), 'success');
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
function showExportModal() {
  $('exportPassword').value = '';
  $('exportErr').textContent = '';
  // 默认范围：当前如果不在"全部"，默认导出当前分组；否则全部
  $('exportScope').value = (S.currentGroup && S.currentGroup !== '全部') ? 'current' : 'all';
  $('exportSeparator').value = 'newline';
  $('exportIncludeGroup').checked = true;
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
  const groupParam = (scope === 'current' && S.currentGroup && S.currentGroup !== '全部')
    ? S.currentGroup : null;

  const btn = $('btnDoExport');
  btn.disabled = true;
  const oldText = btn.textContent;
  btn.textContent = '...';
  try {
    const r = await request('/api/accounts/export', {
      method: 'POST',
      body: JSON.stringify({
        password: pwd,
        group: groupParam,
        include_group: includeGroup,
        separator,
      }),
      headers: { 'Content-Type': 'application/json' },
    });
    if (!r.ok) {
      const msg = await parseError(r);
      errEl.textContent = msg || t('toast_export_failed');
      return;
    }
    const blob = await r.blob();
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const a = el('a', {
      href: URL.createObjectURL(blob),
      download: `accounts_export_${ts}.txt`,
    });
    document.body.appendChild(a); a.click(); a.remove();
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
  $('ecBody').srcdoc = '&nbsp;';
  $('btnReply').disabled = true;
  $('btnDelEmail').disabled = true;
  openModal('emailModal');
  loadEmails();
}

async function loadEmails() {
  if (!S.emailAccount) return;
  const folder = $('emailFolder').value;
  const list = $('emailList');
  clear(list);
  list.appendChild(el('div', { class: 'empty-state' }, t('email_loading')));
  try {
    const r = await api.get(`/api/accounts/${S.emailAccount.id}/emails?folder=${folder}`);
    S.allEmails = r.emails || [];
    S.emails = [...S.allEmails];
    S.currentEmail = null;
    renderEmailList();
  } catch {
    clear(list);
    list.appendChild(el('div', { class: 'empty-state', style: 'color:var(--danger)' }, t('email_load_fail')));
  }
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
    list.appendChild(item);
  });
}

function renderEmailBody(body, bodyType) {
  // 在 sandbox iframe 中渲染邮件正文，杜绝 XSS；自动按 body_type 处理 html/text。
  const head = '<base target="_blank"><meta charset="utf-8">'
    + '<style>body{font-family:Segoe UI,Microsoft YaHei UI,sans-serif;'
    + 'font-size:13px;padding:12px;margin:0;color:#1d1d1f;background:#fff;'
    + 'word-wrap:break-word;overflow-wrap:break-word}'
    + 'pre{white-space:pre-wrap;margin:0;font-family:inherit}'
    + 'img{max-width:100%;height:auto}</style>';
  const iframe = $('ecBody');
  if (!body) {
    iframe.srcdoc = head + `<div style="color:#8e8e93;padding:16px;text-align:center">${t('email_body_empty')}</div>`;
    return;
  }
  // 显式 body_type 优先；缺省时回退到内容启发式判断
  const isHtml = bodyType
    ? bodyType === 'html'
    : /<html|<body|<div|<a\s|<p\s|<br/i.test(body);
  if (isHtml) {
    iframe.srcdoc = head + body;
  } else {
    const escaped = body
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    iframe.srcdoc = head + `<pre>${escaped}</pre>`;
  }
}

async function selectEmail(idx) {
  const e = S.emails[idx];
  if (!e) return;
  S.currentEmail = e;
  $('ecSubject').textContent = e.subject || '(no subject)';
  const d = e.date ? new Date(e.date) : null;
  $('ecInfo').textContent = `${t('compose_from')}: ${e.sender || ''}\n${t('d_created')}: ${d ? d.toLocaleString() : ''}`;

  // 1. 立即用列表里的 body 渲染（即使是空）
  renderEmailBody(e.body || '', e.body_type);

  $('btnReply').disabled = false;
  $('btnDelEmail').disabled = false;

  // 2. 列表 body 为空时，再异步去拿完整正文（按需拉取）
  const account = S.emailAccount;
  if (account && (!e.body || e.body.length < 50) && e.uid) {
    try {
      $('ecBody').srcdoc = '<base target="_blank"><meta charset="utf-8">'
        + `<div style="color:#8e8e93;padding:16px;text-align:center">${t('email_loading')}</div>`;
      const folder = $('emailFolder').value;
      const r = await api.get(
        `/api/accounts/${account.id}/emails/body?email_id=${encodeURIComponent(e.uid)}&folder=${folder}`
      );
      // 用户可能同时切到了别的邮件
      if (S.currentEmail !== e) return;
      if (r && r.success && r.body) {
        e.body = r.body;
        e.body_type = r.body_type || 'text';
        renderEmailBody(e.body, e.body_type);
      } else {
        renderEmailBody(e.body || '', e.body_type);
      }
    } catch (err) {
      if (S.currentEmail === e) {
        renderEmailBody(e.body || '', e.body_type);
      }
    }
  }

  if (!e.is_read) {
    e.is_read = true;
    renderEmailList();
    api.post(`/api/accounts/${S.emailAccount.id}/emails/mark-read`, {
      email_id: e.uid, folder: $('emailFolder').value, is_read: true
    }).catch(() => {});
  } else { renderEmailList(); }
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
  if (a.client_id) lines.push(`Client ID: ${a.client_id}`);
  if (a.refresh_token) lines.push(`Refresh Token: ${a.refresh_token}`);
  if (a.remark) lines.push(`${t('d_remark')}: ${a.remark}`);
  navigator.clipboard.writeText(lines.join('\n')).then(() => toast(t('toast_copied'), 'success'));
}

// ───────── Views ─────────
function showTableView() {
  $('tableView').style.display = '';
  $('dashView').style.display = 'none';
  $('settingsView').style.display = 'none';
  $('oauthView').style.display = 'none';
  $('actionBar').style.display = '';
  $('toolbarRight').style.display = '';
  $('pageTitle').textContent = S.currentGroup === '全部' ? t('page_title_default') : S.currentGroup;
  $('pageSub').textContent = t('page_sub_default');
}

function showView(view) {
  S.view = view;
  document.querySelectorAll('.nav-btn').forEach((b) => b.classList.remove('active'));
  document.querySelectorAll('.grp-item').forEach((b) => b.classList.remove('active'));
  const map = { dashboard: 'navDash', settings: 'navSettings', oauth: 'navOauth' };
  if (map[view]) $(map[view]).classList.add('active');
  $('tableView').style.display = 'none';
  $('dashView').style.display = view === 'dashboard' ? '' : 'none';
  $('settingsView').style.display = view === 'settings' ? '' : 'none';
  $('oauthView').style.display = view === 'oauth' ? '' : 'none';
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
  } else if (view === 'oauth') {
    $('pageTitle').textContent = t('page_title_oauth');
    $('pageSub').textContent = t('page_sub_oauth');
    pushPath('/oauth');
    renderOAuth();
  } else {
    pushPath('/');
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
  for (const v of ['light', 'dark']) {
    const o = el('option', { value: v }, t(v === 'light' ? 'theme_light' : 'theme_dark'));
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

// ───────── OAuth ─────────
function renderOAuth() {
  const view = $('oauthView'); clear(view);
  const card = el('div', { class: 'oauth-card' });
  card.appendChild(el('h4', {}, t('oauth_title')));
  card.appendChild(el('p', {}, t('oauth_intro')));
  const ol = el('ol', { class: 'oauth-steps' });
  ['oauth_step1', 'oauth_step2', 'oauth_step3', 'oauth_step4']
    .forEach((k) => ol.appendChild(el('li', {}, t(k))));
  card.appendChild(ol);

  const grpRow = el('div', { class: 'form-group', style: 'margin-top:16px' });
  grpRow.appendChild(el('label', {}, t('oauth_import_to')));
  const grpSel = el('select', { id: 'oauthGroup' });
  for (const g of S.groups) grpSel.appendChild(el('option', {}, g.name));
  grpRow.appendChild(grpSel);
  card.appendChild(grpRow);

  const startBtn = el('button', { class: 'btn btn-p', onclick: startOAuth }, t('oauth_start'));
  card.appendChild(el('div', { style: 'display:flex;gap:10px;margin-bottom:16px' }, startBtn));

  const urlGroup = el('div', { class: 'form-group' });
  urlGroup.appendChild(el('label', {}, t('oauth_paste')));
  urlGroup.appendChild(el('input', { id: 'oauthUrl', placeholder: 'https://localhost/?code=...' }));
  card.appendChild(urlGroup);

  const submitBtn = el('button', {
    class: 'btn btn-s', id: 'oauthSubmitBtn', onclick: submitOAuth
  }, t('oauth_submit'));
  card.appendChild(submitBtn);
  card.appendChild(el('div', { id: 'oauthResult', style: 'margin-top:12px;font-size:13px' }));
  view.appendChild(card);
}

async function startOAuth() {
  const r = await api.get('/api/oauth2/auth-url');
  window.open(r.url, '_blank');
  toast(t('toast_oauth_opened'), 'info');
}

async function submitOAuth() {
  const url = $('oauthUrl').value.trim();
  if (!url) { toast(t('oauth_paste'), 'warning'); return; }
  const group = $('oauthGroup').value;
  const btn = $('oauthSubmitBtn');
  const result = $('oauthResult');
  btn.disabled = true;
  result.textContent = '...';
  try {
    const r = await api.post('/api/oauth2/exchange', { redirect_url: url, group });
    if (r.success) {
      clear(result);
      result.appendChild(el('span', { style: 'color:var(--success)' }, `✅ ${t('toast_oauth_ok')}: ${r.email}`));
      await loadAccounts();
      toast(t('toast_oauth_ok'), 'success');
    } else {
      clear(result);
      result.appendChild(el('span', { style: 'color:var(--danger)' }, `❌ ${r.error}`));
    }
  } catch (e) {
    clear(result);
    result.appendChild(el('span', { style: 'color:var(--danger)' }, '❌ ' + (e.message || '')));
  }
  btn.disabled = false;
}

// ───────── Theme & Lang ─────────
const toggleTheme = () => setTheme(S.theme === 'light' ? 'dark' : 'light');
function setTheme(theme) {
  S.theme = theme;
  document.body.dataset.theme = theme;
  $('themeBtn').textContent = theme === 'dark' ? '🌙' : '☀️';
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
  else if (S.view === 'oauth') renderOAuth();
  else { showTableView(); renderAccounts(); }
}

// ───────── Wiring (事件委托，无 inline 处理) ─────────
$('navAll').addEventListener('click', () => selectGroup('全部'));
$('navDash').addEventListener('click', () => showView('dashboard'));
$('navSettings').addEventListener('click', () => showView('settings'));
$('navOauth').addEventListener('click', () => showView('oauth'));
$('themeBtn').addEventListener('click', toggleTheme);
$('langBtn').addEventListener('click', toggleLang);
$('addGroupBtn').addEventListener('click', addGroup);
$('searchInp').addEventListener('input', filterAccounts);
$('selAll').addEventListener('change', (e) => toggleSelAll(e.target.checked));
$('btnImport').addEventListener('click', showImportModal);
$('btnExport').addEventListener('click', showExportModal);
$('btnDoExport').addEventListener('click', doExport);
$('exportPassword').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') doExport();
});
$('btnMove').addEventListener('click', showMoveGroup);
$('btnBatchCheck').addEventListener('click', batchCheck);
$('btnBatchSend').addEventListener('click', showBatchSend);
$('btnDelete').addEventListener('click', deleteSelected);
$('btnImportClipboard').addEventListener('click', importFromClipboard);
$('btnDoImport').addEventListener('click', doImport);
$('btnRefreshEmails').addEventListener('click', loadEmails);
$('emailFolder').addEventListener('change', loadEmails);
$('emailSearch').addEventListener('input', filterEmailList);
$('btnCompose').addEventListener('click', () => showCompose());
$('btnReply').addEventListener('click', replyEmail);
$('btnDelEmail').addEventListener('click', deleteCurrentEmail);
$('btnDoSend').addEventListener('click', doSendEmail);
$('btnDoBatchSend').addEventListener('click', doBatchSend);
$('btnDoMove').addEventListener('click', doMoveGroup);
$('btnCopyDetail').addEventListener('click', copyAccountInfo);

// ───────── Init ─────────
async function init() {
  try {
    const settings = await api.get('/api/settings');
    S.theme = settings.theme || 'light';
    S.lang = settings.language || 'zh';
    document.body.dataset.theme = S.theme;
    $('themeBtn').textContent = S.theme === 'dark' ? '🌙' : '☀️';
    $('langBtn').textContent = S.lang === 'zh' ? '中/EN' : 'EN/中';
    if (window.I18N) {
      window.I18N.setLang(S.lang);
      window.I18N.applyToDom();
    }
    updateUserDisplay();
    await loadGroups();
    await loadAccounts();
    S.ready = true;
  } catch (err) {
    if (err && err.status === 401) return;
    toast(t('toast_load_fail') + (err?.message || ''), 'error');
  }
}

// 启动：先看是否已登录；未登录则展示登录框
(async () => {
  // 先取注册开关
  try {
    const r = await fetch('/api/health', { credentials: 'include' });
    const j = await r.json();
    S.registerEnabled = !!j.register_enabled;
  } catch { /* ignore */ }

  const initialPath = window.location.pathname;

  try {
    const r = await fetch('/api/auth/me', { credentials: 'include' });
    if (r.ok) {
      const data = await r.json();
      S.user = { username: data.username };
      showMain();
      await init();
      // 根据 URL 切换初始视图
      applyPath(initialPath);
      return;
    }
  } catch { /* ignore */ }
  // 未登录：根据 URL 决定登录还是注册模式
  const mode = (initialPath === '/register' && S.registerEnabled) ? 'register' : 'login';
  showAuthModal(mode);
})();

})();
