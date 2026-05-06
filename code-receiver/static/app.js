/* eslint-disable no-var */
(function () {
  'use strict';

  var form = document.getElementById('lookup-form');
  var inputEl = document.getElementById('input-credential');
  var btn = document.getElementById('submit-btn');
  var resultEl = document.getElementById('result');
  var themeBtn = document.getElementById('theme-toggle');

  /* ── Cloudflare Turnstile（可选）─ 服务端 /api/config 决定是否启用 ── */
  var TURNSTILE = { enabled: false, sitekey: '', widgetId: null };

  function loadTurnstileScript() {
    return new Promise(function (resolve, reject) {
      if (window.turnstile) return resolve();
      var s = document.createElement('script');
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      s.async = true;
      s.defer = true;
      s.onload = function () { resolve(); };
      s.onerror = function () { reject(new Error('turnstile script load fail')); };
      document.head.appendChild(s);
    });
  }

  function renderTurnstile() {
    if (!TURNSTILE.enabled || !TURNSTILE.sitekey) return;
    var slot = document.getElementById('turnstile-slot');
    if (!slot) return;
    slot.removeAttribute('hidden');
    loadTurnstileScript().then(function () {
      try {
        TURNSTILE.widgetId = window.turnstile.render(slot, {
          sitekey: TURNSTILE.sitekey,
          theme: 'auto',
          appearance: 'always',
        });
      } catch (e) {
        // 渲染失败时也不阻断查询，仅在 console 提示——后端会返回 403 被拦
        // eslint-disable-next-line no-console
        console.warn('turnstile render failed', e);
      }
    }).catch(function () {});
  }

  function readTurnstileToken() {
    if (!TURNSTILE.enabled) return '';
    if (window.turnstile && TURNSTILE.widgetId !== null) {
      try { return window.turnstile.getResponse(TURNSTILE.widgetId) || ''; }
      catch (_) { return ''; }
    }
    return '';
  }

  function resetTurnstileToken() {
    if (window.turnstile && TURNSTILE.widgetId !== null) {
      try { window.turnstile.reset(TURNSTILE.widgetId); } catch (_) {}
    }
  }

  function bootstrapConfig() {
    fetch('/api/config', { credentials: 'omit' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (cfg) {
        if (!cfg || !cfg.turnstile || !cfg.turnstile.enabled) return;
        TURNSTILE.enabled = true;
        TURNSTILE.sitekey = String(cfg.turnstile.sitekey || '');
        if (TURNSTILE.sitekey) renderTurnstile();
      })
      .catch(function () { /* 静默：未启用 / 网络错都按未启用处理 */ });
  }

  /* ── 三主题切换：cyber → light → dark → cyber ── */
  var THEME_ORDER = ['cyber', 'light', 'dark'];
  var THEME_ICON = { cyber: '🌐', light: '☀️', dark: '🌙' };
  var THEME_LABEL = { cyber: '赛博朋克', light: '浅色', dark: '深色' };
  var THEME_KEY = 'cr_theme';

  function applyTheme(name) {
    if (THEME_ORDER.indexOf(name) === -1) name = 'cyber';
    document.body.setAttribute('data-theme', name);
    if (themeBtn) {
      themeBtn.textContent = THEME_ICON[name];
      themeBtn.title = '主题：' + THEME_LABEL[name] + '（点击切换）';
      themeBtn.setAttribute('aria-label', themeBtn.title);
    }
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', name === 'light' ? '#f5f5f7' : (name === 'dark' ? '#0d1117' : '#0a0e17'));
    try { localStorage.setItem(THEME_KEY, name); } catch (_) {}
  }
  (function initTheme() {
    var saved = null;
    try { saved = localStorage.getItem(THEME_KEY); } catch (_) {}
    applyTheme(saved || 'cyber');
  })();
  if (themeBtn) {
    themeBtn.addEventListener('click', function () {
      var cur = document.body.getAttribute('data-theme') || 'cyber';
      var idx = THEME_ORDER.indexOf(cur);
      applyTheme(THEME_ORDER[(idx + 1) % THEME_ORDER.length]);
    });
  }

  /** 从原始 sender 中抽取 user@host 形式（去掉 "Name <addr>" 包装）。 */
  function pickAddr(s) {
    if (!s) return '';
    var m = /<([^>]+)>/.exec(String(s));
    return m ? m[1] : String(s).trim();
  }

  /**
   * 仅允许 http(s) 协议的 URL 通过；阻挡 javascript: / data: / vbscript: 等
   * 可能被注入的 magic-link，防止后端被攻破或邮件提取规则被恶意构造时
   * 触发存储型 XSS（点击链接执行任意 JS）。
   */
  function safeHttpUrl(s) {
    if (typeof s !== 'string' || !s) return '';
    var trimmed = s.trim();
    if (!/^https?:\/\//i.test(trimmed)) return '';
    return trimmed;
  }

  function copyToClipboard(text) {
    if (
      typeof navigator !== 'undefined' &&
      navigator.clipboard &&
      typeof navigator.clipboard.writeText === 'function' &&
      window.isSecureContext !== false
    ) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      try {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        ta.setSelectionRange(0, text.length);
        var ok = document.execCommand && document.execCommand('copy');
        document.body.removeChild(ta);
        ok ? resolve() : reject(new Error('execCommand copy failed'));
      } catch (e) {
        reject(e);
      }
    });
  }

  /** SVG icon 工厂：避免每次手写 inline SVG。 */
  function svgIcon(viewBox, paths, opts) {
    opts = opts || {};
    var ns = 'http://www.w3.org/2000/svg';
    var s = document.createElementNS(ns, 'svg');
    s.setAttribute('viewBox', viewBox);
    s.setAttribute('width', String(opts.size || 18));
    s.setAttribute('height', String(opts.size || 18));
    s.setAttribute('fill', 'none');
    s.setAttribute('stroke', 'currentColor');
    s.setAttribute('stroke-width', String(opts.stroke || 2));
    s.setAttribute('stroke-linecap', 'round');
    s.setAttribute('stroke-linejoin', 'round');
    s.setAttribute('aria-hidden', 'true');
    paths.forEach(function (p) {
      var [tag, attrs] = p;
      var el = document.createElementNS(ns, tag);
      Object.keys(attrs).forEach(function (k) { el.setAttribute(k, attrs[k]); });
      s.appendChild(el);
    });
    return s;
  }

  /** 时间格式化：把后端返回的 ISO / Date 字符串转成更易读的 "YYYY-MM-DD HH:mm"。 */
  function formatDate(s) {
    if (!s) return '';
    try {
      var d = new Date(s);
      if (isNaN(d.getTime())) return String(s);
      var pad = function (n) { return n < 10 ? '0' + n : '' + n; };
      return (
        d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
        ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes())
      );
    } catch (_) {
      return String(s);
    }
  }

  function renderEmpty(title, desc) {
    resultEl.replaceChildren();
    var wrap = document.createElement('div');
    wrap.className = 'empty';

    var iconBox = document.createElement('div');
    iconBox.className = 'empty-icon';
    iconBox.appendChild(svgIcon('0 0 24 24', [
      ['rect', { x: '3', y: '5', width: '18', height: '14', rx: '2' }],
      ['polyline', { points: '3,7 12,13 21,7' }],
    ], { size: 28, stroke: 1.6 }));
    wrap.appendChild(iconBox);

    var t = document.createElement('p');
    t.className = 'empty-title';
    t.textContent = title || '暂无匹配邮件';
    wrap.appendChild(t);

    var sub = document.createElement('p');
    sub.className = 'empty-desc';
    sub.textContent = desc || '若验证邮件还在路上，请几秒后重试';
    wrap.appendChild(sub);

    resultEl.appendChild(wrap);
  }

  function renderLoading() {
    resultEl.replaceChildren();
    var wrap = document.createElement('div');
    wrap.className = 'loading';

    for (var i = 0; i < 3; i++) {
      var dot = document.createElement('span');
      dot.className = 'loading-dot';
      wrap.appendChild(dot);
    }
    var t = document.createElement('span');
    t.className = 'loading-text';
    t.textContent = '正在拉取最新邮件…';
    wrap.appendChild(t);
    resultEl.appendChild(wrap);
  }

  function renderError(msg, extra) {
    resultEl.replaceChildren();
    var box = document.createElement('div');
    box.className = 'error-card';
    box.appendChild(svgIcon('0 0 24 24', [
      ['circle', { cx: '12', cy: '12', r: '10' }],
      ['line', { x1: '12', y1: '8', x2: '12', y2: '12' }],
      ['line', { x1: '12', y1: '16', x2: '12.01', y2: '16' }],
    ], { size: 18, stroke: 2 }));
    box.firstChild.classList.add('error-icon');

    var p = document.createElement('div');
    p.style.flex = '1 1 auto';
    var t = document.createElement('div');
    t.style.fontWeight = '600';
    t.textContent = msg || '请求失败';
    p.appendChild(t);
    if (extra) {
      var s = document.createElement('div');
      s.style.fontSize = '13px';
      s.style.opacity = '0.8';
      s.style.marginTop = '4px';
      s.textContent = extra;
      p.appendChild(s);
    }
    box.appendChild(p);
    resultEl.appendChild(box);
  }

  function renderResult(data) {
    resultEl.replaceChildren();
    var card = document.createElement('section');
    card.className = 'card';

    /* 元数据 */
    var meta = document.createElement('dl');
    meta.className = 'card-meta';

    function addRow(label, value) {
      if (!value) return;
      var dt = document.createElement('dt');
      dt.textContent = label;
      var dd = document.createElement('dd');
      var strong = document.createElement('strong');
      strong.textContent = String(value);
      dd.appendChild(strong);
      meta.appendChild(dt);
      meta.appendChild(dd);
    }

    addRow('来自', pickAddr(data.sender) || data.sender);
    addRow('主题', data.subject);
    addRow('时间', formatDate(data.received_at));
    if (meta.children.length > 0) card.appendChild(meta);

    /* 验证码 */
    if (data.code) {
      var codeBox = document.createElement('div');
      codeBox.className = 'code-box';

      var info = document.createElement('div');
      info.className = 'code-info';
      var lbl = document.createElement('span');
      lbl.className = 'code-label';
      lbl.textContent = 'Verification Code';
      var val = document.createElement('div');
      val.className = 'code-value';
      val.textContent = data.code;
      info.appendChild(lbl);
      info.appendChild(val);

      var cp = document.createElement('button');
      cp.type = 'button';
      cp.className = 'copy-btn';
      cp.appendChild(svgIcon('0 0 24 24', [
        ['rect', { x: '9', y: '9', width: '13', height: '13', rx: '2' }],
        ['path', { d: 'M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1' }],
      ], { size: 14, stroke: 2 }));
      var cpText = document.createElement('span');
      cpText.textContent = '复制';
      cp.appendChild(cpText);

      cp.addEventListener('click', function () {
        copyToClipboard(data.code).then(
          function () {
            cp.classList.add('is-copied');
            cpText.textContent = '已复制';
            setTimeout(function () {
              cp.classList.remove('is-copied');
              cpText.textContent = '复制';
            }, 1500);
          },
          function () {
            cpText.textContent = '复制失败';
            setTimeout(function () { cpText.textContent = '复制'; }, 1500);
          }
        );
      });

      codeBox.appendChild(info);
      codeBox.appendChild(cp);
      card.appendChild(codeBox);
    }

    /* 链接 */
    var safeLink = safeHttpUrl(data.link);
    if (safeLink) {
      var linkBox = document.createElement('div');
      linkBox.className = 'link-box';
      var icon = svgIcon('0 0 24 24', [
        ['path', { d: 'M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71' }],
        ['path', { d: 'M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71' }],
      ], { size: 16, stroke: 2 });
      icon.classList.add('link-icon');
      linkBox.appendChild(icon);

      var a = document.createElement('a');
      a.href = safeLink;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = safeLink;
      linkBox.appendChild(a);

      card.appendChild(linkBox);
    }

    /* 预览 */
    if (data.preview) {
      var pv = document.createElement('div');
      pv.className = 'preview';
      pv.textContent = data.preview;
      card.appendChild(pv);
    }

    resultEl.appendChild(card);
  }

  function setLoading(v) {
    btn.disabled = !!v;
    if (v) btn.classList.add('is-loading');
    else btn.classList.remove('is-loading');
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    var input = (inputEl.value || '').trim();
    var category =
      (document.querySelector('input[name="category"]:checked') || {}).value ||
      'openai';

    if (!input) {
      renderError('请填写邮箱', '请输入已加入接码白名单的邮箱地址');
      inputEl.focus();
      return;
    }
    // 与后端 LookupRequest field_validator 对齐：byo（邮箱----密码 / OAuth）
    // 路径已下线，前端先做一次轻量提示，避免无意义请求消耗限流配额。
    if (input.indexOf('----') !== -1) {
      renderError('仅支持邮箱地址', '请只输入邮箱，不要附带密码或 OAuth 凭据');
      inputEl.focus();
      return;
    }

    // Turnstile 启用时需要 token；未渲染好或用户未通过校验时给出提示并刷新挑战
    var cfToken = readTurnstileToken();
    if (TURNSTILE.enabled && !cfToken) {
      renderError('请先完成人机校验', '若挑战未显示，请刷新页面');
      resetTurnstileToken();
      return;
    }

    setLoading(true);
    renderLoading();

    var resp;
    try {
      resp = await fetch('/api/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          input: input,
          category: category,
          cf_token: cfToken || undefined,
        }),
        credentials: 'omit',
      });
    } catch (err) {
      setLoading(false);
      renderError('网络异常', String(err && err.message ? err.message : err));
      resetTurnstileToken();
      return;
    }
    setLoading(false);
    // Turnstile token 是一次性的，无论成功失败都重置以备下一次
    resetTurnstileToken();

    var body = {};
    try {
      body = await resp.json();
    } catch (_) {
      renderError('返回格式异常', 'HTTP ' + resp.status);
      return;
    }

    if (!resp.ok) {
      var msg =
        (body && (body.error || body.detail || body.message)) ||
        '请求失败 (HTTP ' + resp.status + ')';
      var retryAfter = body && body.retry_after;
      renderError(msg, retryAfter ? '约 ' + retryAfter + 's 后再试' : '');
      return;
    }

    if (body && body.found === false) {
      renderEmpty(body.reason || '暂无匹配邮件', '若邮件还在路上，请稍后再试');
      return;
    }

    if (!body || (!body.code && !body.link)) {
      renderEmpty('未提取到验证码', '邮箱已到货，但未匹配到该分类的内容');
      return;
    }

    renderResult(body);
  });

  // 首屏占位
  renderEmpty('准备就绪', '输入已加入接码白名单的邮箱后点击"查询"即可');

  // 启动期：从 /api/config 异步拉取是否启用 Turnstile（启用则注入挑战 widget）
  bootstrapConfig();
})();
