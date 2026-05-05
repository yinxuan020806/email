(function () {
  'use strict';

  const form = document.getElementById('lookup-form');
  const inputEl = document.getElementById('input-credential');
  const btn = document.getElementById('submit-btn');
  const resultEl = document.getElementById('result');

  function escapeText(s) {
    return (s == null ? '' : String(s));
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
        if (ok) {
          resolve();
        } else {
          reject(new Error('execCommand copy failed'));
        }
      } catch (e) {
        reject(e);
      }
    });
  }

  function renderEmpty(msg) {
    resultEl.replaceChildren();
    const wrap = document.createElement('div');
    wrap.className = 'empty';
    wrap.innerHTML =
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"' +
      ' stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18"' +
      ' height="14" rx="2"></rect><polyline points="3,7 12,13 21,7"></polyline></svg>';
    const t = document.createElement('p');
    t.style.fontSize = '15px';
    t.textContent = msg || '暂无邮件';
    wrap.appendChild(t);
    const sub = document.createElement('p');
    sub.style.fontSize = '12px';
    sub.textContent = '没有找到邮件，可能尚未送达，请稍后再试';
    wrap.appendChild(sub);
    resultEl.appendChild(wrap);
  }

  function renderError(msg) {
    resultEl.replaceChildren();
    const box = document.createElement('div');
    box.className = 'error-card';
    box.textContent = msg || '请求失败';
    resultEl.appendChild(box);
  }

  function renderResult(data) {
    resultEl.replaceChildren();
    const card = document.createElement('div');
    card.className = 'card';

    const meta = document.createElement('div');
    meta.className = 'meta';
    const senderLine = document.createElement('div');
    senderLine.innerHTML = '来自：';
    const senderStrong = document.createElement('strong');
    senderStrong.textContent = escapeText(data.sender) || '(未知)';
    senderLine.appendChild(senderStrong);
    meta.appendChild(senderLine);

    if (data.subject) {
      const sub = document.createElement('div');
      sub.textContent = '主题：' + data.subject;
      meta.appendChild(sub);
    }
    if (data.received_at) {
      const t = document.createElement('div');
      t.textContent = '时间：' + data.received_at;
      meta.appendChild(t);
    }
    card.appendChild(meta);

    if (data.code) {
      const codeBox = document.createElement('div');
      codeBox.className = 'code-box';
      const left = document.createElement('div');
      const lbl = document.createElement('div');
      lbl.className = 'label';
      lbl.textContent = '验证码';
      const val = document.createElement('div');
      val.className = 'code-value';
      val.textContent = data.code;
      left.appendChild(lbl);
      left.appendChild(val);
      const cp = document.createElement('button');
      cp.type = 'button';
      cp.className = 'copy-btn';
      cp.textContent = '复制';
      cp.addEventListener('click', function () {
        copyToClipboard(data.code).then(
          function () {
            cp.textContent = '已复制';
            setTimeout(function () {
              cp.textContent = '复制';
            }, 1500);
          },
          function () {
            cp.textContent = '复制失败';
            setTimeout(function () {
              cp.textContent = '复制';
            }, 1500);
          }
        );
      });
      codeBox.appendChild(left);
      codeBox.appendChild(cp);
      card.appendChild(codeBox);
    }

    if (data.link) {
      const linkBox = document.createElement('div');
      linkBox.className = 'link-box';
      const a = document.createElement('a');
      a.href = data.link;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = data.link;
      linkBox.appendChild(a);
      card.appendChild(linkBox);
    }

    if (data.preview) {
      const pv = document.createElement('div');
      pv.className = 'preview';
      pv.textContent = data.preview;
      card.appendChild(pv);
    }

    resultEl.appendChild(card);
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    const input = (inputEl.value || '').trim();
    const category =
      (document.querySelector('input[name="category"]:checked') || {}).value ||
      'openai';
    if (!input) {
      renderError('请填写邮箱或邮箱----密码');
      return;
    }
    btn.disabled = true;
    resultEl.replaceChildren();
    const loading = document.createElement('div');
    loading.className = 'empty';
    loading.textContent = '正在拉取邮件…';
    resultEl.appendChild(loading);

    let resp;
    try {
      resp = await fetch('/api/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: input, category: category }),
        credentials: 'omit',
      });
    } catch (err) {
      btn.disabled = false;
      renderError('网络异常：' + err);
      return;
    }
    btn.disabled = false;

    let body = {};
    try {
      body = await resp.json();
    } catch (_) {
      renderError('返回格式异常 (HTTP ' + resp.status + ')');
      return;
    }

    if (!resp.ok) {
      const msg =
        (body && (body.error || body.detail || body.message)) ||
        '请求失败 (HTTP ' + resp.status + ')';
      const retryAfter = body && body.retry_after;
      renderError(retryAfter ? msg + '（约 ' + retryAfter + 's 后再试）' : msg);
      return;
    }

    if (body && body.found === false) {
      renderEmpty(body.reason || '暂无匹配邮件');
      return;
    }

    if (!body || (!body.code && !body.link)) {
      renderEmpty('未提取到验证码或登录链接');
      return;
    }
    renderResult(body);
  });

  renderEmpty('暂无邮件');
})();
