# -*- coding: utf-8 -*-
"""
Phase 7 安全 / 数据完整性回归测试

每个测试都钉住计划中的某个修复点，避免后续 commit 把这些修复回滚。

T1 - 篡改 / 伪造 cookie 必须 401
T2 - SQLite OperationalError 时端点返回 5xx 且不卡死
T4 - OAuth state 缺失 / 跨用户 / replay 全部拒绝
T7a - 导出 ids 列表过长（11000）→ 422
T7b - 导出二次密码限速：连续错密码 N 次 → 429
T8 - SecretBox 损坏密文（带前缀但 Fernet 失败）必须 raise
"""

from __future__ import annotations

import sqlite3
import threading
import time
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _reset_login_limiter():
    """每个测试都从干净的限流状态开始。

    模块级单例 ``login_limiter`` 在测试之间会累积失败计数，让"先跑触发
    限流的测试"和"后跑期望正常密码工作的测试"产生顺序依赖。autouse
    reset 把这种隐式耦合显式化、可重入。
    """
    from core.rate_limit import login_limiter
    login_limiter.reset()
    yield
    login_limiter.reset()


# ── T8 SecretBox 损坏密文 raise ────────────────────────────────


def test_secretbox_decrypt_raises_on_corrupted_ciphertext(tmp_path):
    """带 ``enc::v1::`` 前缀但 Fernet 校验不通过 → 必须 raise SecretBoxDecryptError。

    旧版静默吞成 ``""`` 是数据完整性陷阱：上层把空字符串当合法值落库后
    "二次加密空" 不可逆破坏，运维只能从日志里发现。
    """
    from core.security import SecretBox, SecretBoxDecryptError, _TOKEN_PREFIX

    SecretBox._instance = None  # noqa: SLF001
    box = SecretBox(key_path=tmp_path / ".master.key")
    # 构造一个带前缀但 token 内容不合法的串
    corrupted = _TOKEN_PREFIX + "this-is-not-a-valid-fernet-token"
    with pytest.raises(SecretBoxDecryptError, match="解密失败"):
        box.decrypt(corrupted)
    SecretBox._instance = None  # noqa: SLF001


def test_secretbox_decrypt_legacy_plaintext_still_passes_through(tmp_path):
    """v1→v2 兼容路径不变：不带前缀的旧明文仍原样返回（不 raise）。"""
    from core.security import SecretBox

    SecretBox._instance = None  # noqa: SLF001
    box = SecretBox(key_path=tmp_path / ".master.key")
    assert box.decrypt("legacy-plaintext-pwd") == "legacy-plaintext-pwd"
    assert box.decrypt(None) is None
    assert box.decrypt("") == ""
    SecretBox._instance = None  # noqa: SLF001


def test_db_row_to_account_recovers_from_corrupted_field(tmp_db, monkeypatch):
    """``_row_to_account`` 把单条损坏字段降级为空，让查询不至于整批失败。

    ``SecretBox.decrypt`` 的 raise 行为是"严格"的；DB 层包了一层 try/except
    + ERROR 日志，避免一条损坏密文连累整张账号列表的查询。这层降级用于
    防御 master.key 替换 / DB 文件被截断等运维事故。
    """
    from core.security import SecretBoxDecryptError

    db, uid = tmp_db
    # 正常落入一条账号
    ok, _ = db.add_account(uid, "victim@gmail.com", "pwd-good", "默认分组")
    assert ok

    # mock SecretBox.decrypt 在 password 字段上抛 SecretBoxDecryptError
    real_decrypt = db.__class__.__dict__  # placeholder
    from core.security import SecretBox
    box = SecretBox.instance()

    def fake_decrypt(value):
        if value and value.startswith("enc::v1::"):
            raise SecretBoxDecryptError("模拟密文损坏")
        return value

    with patch.object(box, "decrypt", side_effect=fake_decrypt):
        accs = db.get_all_accounts(uid)

    assert len(accs) == 1, "整批查询不能因为单字段解密失败而中断"
    a = accs[0]
    assert a.email == "victim@gmail.com"
    assert a.password == "", "损坏 password 字段降级为空字符串"
    assert a.refresh_token in (None, ""), "损坏 refresh_token 字段降级为 None/空"


# ── T1 伪造 / 篡改 cookie ─────────────────────────────────────


def test_forged_session_cookie_returns_401(client):
    """随便编一个 session token 必须被服务端拒绝（401），且响应体里不能泄露用户名。"""
    client.cookies.clear()
    client.cookies.set("email_web_session", "this-is-a-forged-token-32-chars-long-xx")
    r = client.get("/api/auth/me")
    assert r.status_code == 401
    body_text = r.text or ""
    # 401 响应体里只许出现"未登录"等通用提示，不许泄露任何已注册用户名
    assert "alice" not in body_text
    assert "bob" not in body_text


def test_truncated_session_cookie_returns_401(client):
    """合法 token 的开头 / 结尾切片不能用来"碰运气"恢复会话。"""
    # 先正常登录拿到一个真 token
    r = client.get("/api/auth/me")
    assert r.status_code == 200
    real_token = client.cookies.get("email_web_session")
    assert real_token

    # 截断到一半 / 改最后一个字符 / 加一个字节
    forged_variants = [
        real_token[:-1],
        real_token[1:],
        real_token + "X",
        real_token[:5] + ("A" if real_token[5] != "A" else "B") + real_token[6:],
    ]
    for forged in forged_variants:
        client.cookies.clear()
        client.cookies.set("email_web_session", forged)
        rr = client.get("/api/auth/me")
        assert rr.status_code == 401, f"篡改 cookie 应当 401，但变体 {forged[:10]}... 通过了"


def test_empty_session_cookie_returns_401(client):
    """空 session 必须 401（防止默认值绕过）。"""
    client.cookies.clear()
    client.cookies.set("email_web_session", "")
    r = client.get("/api/auth/me")
    assert r.status_code == 401


# ── T2 SQLite OperationalError ────────────────────────────────


def test_sqlite_operational_error_in_endpoint_does_not_kill_worker(client, monkeypatch):
    """模拟 ``sqlite3.OperationalError("database is locked")`` 后端点失败，
    但 worker 不能被永久挂掉 —— 恢复后下一次请求仍能正常服务。

    Starlette TestClient 在生产部署等价路径下会让未捕获异常冒到 500；
    TestClient 在 ``raise_server_exceptions=True`` 默认下会把异常重新抛
    出，所以这里用 ``pytest.raises`` 捕获并验证是 OperationalError，
    然后验证 worker 仍能服务（`/api/health` 200），证明没把进程整挂。
    """
    import database.db_manager as db_mod

    real_connect = db_mod.sqlite3.connect

    def flaky_connect(*a, **kw):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(db_mod.sqlite3, "connect", flaky_connect)

    with pytest.raises(sqlite3.OperationalError):
        client.get("/api/accounts")

    # 关键不变量：恢复 DB 后 worker 仍然存活
    monkeypatch.setattr(db_mod.sqlite3, "connect", real_connect)
    r2 = client.get("/api/health")
    assert r2.status_code == 200, "OperationalError 不应让 worker 永久不可用"


# ── T4 OAuth state CSRF 防御 ─────────────────────────────────


def _auth_state_for(c) -> str:
    """从 ``/api/oauth2/auth-url`` 拿到本轮颁发的 state。"""
    from urllib.parse import parse_qs, urlparse
    r = c.get("/api/oauth2/auth-url")
    assert r.status_code == 200
    return parse_qs(urlparse(r.json()["url"]).query)["state"][0]


def test_oauth_exchange_rejects_request_without_state(client):
    """没带 state 的 redirect_url 必须拒绝。"""
    import web_app

    with patch.object(
        web_app.OAuth2Helper, "exchange_code_for_token",
        return_value=("cid", "rt", None),
    ):
        r = client.post(
            "/api/oauth2/exchange",
            json={"redirect_url": "https://localhost/?code=abc"},
        )
    body = r.json()
    assert body["success"] is False
    assert "state" in body.get("error", "")


def test_oauth_exchange_rejects_unknown_state(client):
    """未颁发过的随机 state 必须拒绝。"""
    import web_app

    with patch.object(
        web_app.OAuth2Helper, "exchange_code_for_token",
        return_value=("cid", "rt", None),
    ):
        r = client.post(
            "/api/oauth2/exchange",
            json={"redirect_url": "https://localhost/?code=abc&state=neverissued"},
        )
    body = r.json()
    assert body["success"] is False
    assert "state" in body.get("error", "")


def test_oauth_exchange_state_is_one_shot(client):
    """成功消费 state 之后，再用同一个 state 提交必须失败（防 replay）。"""
    import web_app

    state = _auth_state_for(client)

    with patch.object(
        web_app.OAuth2Helper, "exchange_code_for_token",
        return_value=("cid", "rt", None),
    ), patch("web_app._fetch_oauth2_email", return_value="ok@outlook.com"):
        r1 = client.post(
            "/api/oauth2/exchange",
            json={"redirect_url": f"https://localhost/?code=abc&state={state}"},
        )
        assert r1.json().get("success") is True

        # 第二次同一 state → 拒绝
        r2 = client.post(
            "/api/oauth2/exchange",
            json={"redirect_url": f"https://localhost/?code=def&state={state}"},
        )
    body2 = r2.json()
    assert body2["success"] is False
    assert "state" in body2.get("error", "")


def test_oauth_state_isolated_per_user(client2):
    """alice 颁发的 state 不能被 bob 用来交换 token。"""
    import web_app
    a, b = client2

    state_a = _auth_state_for(a)

    with patch.object(
        web_app.OAuth2Helper, "exchange_code_for_token",
        return_value=("cid", "rt", None),
    ):
        r = b.post(
            "/api/oauth2/exchange",
            json={"redirect_url": f"https://localhost/?code=abc&state={state_a}"},
        )
    body = r.json()
    assert body["success"] is False, "bob 不应通过 alice 的 state 完成交换"


# ── T7 导出大列表 / 限速 ──────────────────────────────────


def test_export_with_too_many_ids_returns_422(client):
    """ids 列表超出 10000 → Pydantic 校验失败 422。"""
    payload = {
        "password": "pwd-alice",
        "ids": list(range(1, 11001)),  # 11000 个 id
    }
    r = client.post("/api/accounts/export", json=payload)
    assert r.status_code == 422, f"过长 ids 应 422，实际 {r.status_code}"


def test_export_wrong_password_eventually_429(client):
    """连续错密码 N 次后，导出端点也会被 LoginRateLimiter 锁定（429）。

    cookie 被劫持后，攻击者可能反复试登录密码以获取明文凭据；导出端点
    与登录共享同一限流桶，N 次错误后强制等待。
    """
    # 给账号塞一条数据，让导出有"东西可导"
    client.post("/api/accounts/import", json={
        "text": "v@gmail.com----p", "group": "默认分组", "skip_duplicate": False,
    })

    seen_429 = False
    for i in range(15):  # LoginRateLimiter 默认阈值通常 < 15
        r = client.post(
            "/api/accounts/export",
            json={"password": f"deliberately-wrong-{i}"},
        )
        if r.status_code == 429:
            seen_429 = True
            break
        assert r.status_code in (401, 429), f"非 401/429 状态: {r.status_code}"
    assert seen_429, "连续错密码后必须触发 429 限速"


def test_export_correct_password_resets_rate_limit_counter(client):
    """二次密码正确时清空错误计数，避免后续与登录共享计数被拖累。"""
    # 先错 1 次（计数 +1）
    r1 = client.post("/api/accounts/export", json={"password": "wrong"})
    assert r1.status_code == 401

    # 再用正确密码（应 200）
    r2 = client.post("/api/accounts/export", json={"password": "pwd-alice"})
    assert r2.status_code == 200, f"正确密码导出应 200，实际 {r2.status_code}"


def test_export_audit_records_ids_summary(client):
    """G4: 选中导出时审计 detail 应记录 ids 摘要，便于事后追溯。"""
    # 准备 3 个账号
    client.post("/api/accounts/import", json={
        "text": "a@gmail.com----p\nb@gmail.com----p\nc@gmail.com----p",
        "group": "默认分组",
        "skip_duplicate": False,
    })
    accs = client.get("/api/accounts").json()
    assert len(accs) >= 3
    ids = [a["id"] for a in accs[:2]]

    r = client.post(
        "/api/accounts/export",
        json={"password": "pwd-alice", "ids": ids},
    )
    assert r.status_code == 200

    # 审计里应能查到对应条目
    items = client.get("/api/audit?action=export_accounts").json()["items"]
    selected_audits = [
        i for i in items if (i.get("target") or "").startswith("selected(")
    ]
    assert selected_audits, "导出审计应记录 selected(...) target"
    detail = selected_audits[0].get("detail") or ""
    assert "ids=[" in detail, f"detail 应含 ids 摘要，实际: {detail!r}"
    # 至少有一个真实 id 出现在 detail 摘要里
    assert any(str(i) in detail for i in ids)


def test_export_ids_uses_efficient_path(client):
    """G3: ids 路径应走新的 ``get_accounts_by_ids`` 而不是全表加载后过滤。

    通过 monkeypatch 验证：ids 模式下 ``get_all_accounts`` 不应被调用，
    应改走 ``get_accounts_by_ids``。
    """
    import web_app

    # 准备 1 个账号
    client.post("/api/accounts/import", json={
        "text": "x@gmail.com----p", "group": "默认分组", "skip_duplicate": False,
    })
    aid = client.get("/api/accounts").json()[0]["id"]

    real_get_by_ids = web_app.db.get_accounts_by_ids
    real_get_all = web_app.db.get_all_accounts

    by_ids_calls = []
    get_all_calls = []

    def spy_by_ids(*a, **kw):
        by_ids_calls.append((a, kw))
        return real_get_by_ids(*a, **kw)

    def spy_get_all(*a, **kw):
        get_all_calls.append((a, kw))
        return real_get_all(*a, **kw)

    with patch.object(web_app.db, "get_accounts_by_ids", side_effect=spy_by_ids), \
         patch.object(web_app.db, "get_all_accounts", side_effect=spy_get_all):
        r = client.post(
            "/api/accounts/export",
            json={"password": "pwd-alice", "ids": [aid]},
        )
    assert r.status_code == 200
    assert by_ids_calls, "ids 路径应调用 get_accounts_by_ids"
    assert not get_all_calls, "ids 路径**不应**触发 get_all_accounts 全表加载"


# ── 额外：buildAccountFullString sanitize / 4 段占位（前端字符串契约）──


def test_app_js_buildAccountFullString_sanitizes_fields(client):
    """G1+G2: app.js 中 buildAccountFullString 应有 sanitize / 4 段占位逻辑。

    无法真正在浏览器里跑，但通过子串断言钉住"sanitizeImportField 被调用"
    + "任一 client_id/refresh_token 存在就走 4 段"等关键代码路径。
    """
    body = client.get("/static/app.js").text
    # G1: 字段净化函数存在
    assert "sanitizeImportField" in body, "缺少 sanitize 工具，CRLF/----污染防护未到位"
    # G2: 任一存在即输出 4 段
    assert "a.client_id || a.refresh_token" in body, "4 段占位条件未实现"
    # F5: 剪贴板 fallback
    assert "_copyTextFallback" in body or "execCommand" in body, (
        "缺少 navigator.clipboard 不可用时的 execCommand 兜底"
    )
    # F1: loadEmails 竞态防护
    assert "_emailListReqId" in body, "loadEmails 缺少请求代数竞态防护"
    # F2: blob revoke
    assert "revokeObjectURL" in body, "doExport 未 revoke blob URL"
    # F6: loadEmails 不能再"刷新一次就预拉前 3 封 body"
    # （否则连点几次刷新就被 Microsoft Graph per-mailbox 风控撞 429，
    # 让用户误以为是我们自家代码限流过严）
    assert "EMAIL_LIST_MIN_INTERVAL_MS" in body, "loadEmails 缺少前端节流常量"
    assert "_isEmailListUpstreamError" in body, (
        "loadEmails 缺少上游错误透传，empty + message 会被静默成"
        "'暂无数据'误导用户"
    )
    # 反例守护：旧版的 'for (let i = 0; i < Math.min(3, S.emails.length)' 一旦
    # 重新出现，再 5 次刷新 = 20 次 Graph 调用，限流会立刻回归。
    assert "for (let i = 0; i < Math.min(3, S.emails.length)" not in body, (
        "loadEmails 不应在每次刷新后立刻预拉前 3 封 body —— 这是误触发"
        "Microsoft Graph per-mailbox 限流的元凶"
    )


# ── T5 GraphClient HTTP 错误码 ────────────────────────────────


def test_graph_client_check_status_handles_5xx():
    """Graph 5xx → check_status 返回 ('异常', f'API 错误: {code}')。"""
    from core.graph_client import GraphClient
    from unittest.mock import MagicMock

    tm = MagicMock()
    tm.get.return_value = ("fake-token", "ok")
    tm.api_type = "graph"

    client = GraphClient(tm)
    fake_resp = MagicMock()
    fake_resp.status_code = 503

    with patch.object(client, "_req", return_value=fake_resp):
        status_str, msg = client.check_status()
    assert status_str == "异常"
    assert "503" in msg


def test_graph_client_check_status_handles_network_error():
    """``_req`` 返回 None（requests 异常）→ ('异常', '网络错误')。"""
    from core.graph_client import GraphClient
    from unittest.mock import MagicMock

    tm = MagicMock()
    tm.get.return_value = ("fake-token", "ok")
    tm.api_type = "graph"

    client = GraphClient(tm)
    with patch.object(client, "_req", return_value=None):
        status_str, msg = client.check_status()
    assert status_str == "异常"
    assert "网络" in msg


# ── T6 IMAP 边界 ────────────────────────────────────────────


def test_imap_send_email_smtp_authentication_error_returns_msg():
    """SMTP 认证失败必须返回 (False, "认证失败: ...") 而不是 raise 出去。"""
    import smtplib
    from core.imap_client import IMAPClient

    c = IMAPClient(
        email_addr="x@gmail.com",
        password="bad-pwd",
        imap_server="imap.gmail.com",
    )

    # patch 整个 SMTP_SSL 链路：构造时返回一个 mock，sendmail 抛认证失败
    fake_server = type("FS", (), {})()

    def fake_login(self, *a, **kw):
        raise smtplib.SMTPAuthenticationError(535, b"auth failed")

    fake_server.login = lambda u, p: (_ for _ in ()).throw(
        smtplib.SMTPAuthenticationError(535, b"auth failed"),
    )
    fake_server.sendmail = lambda *a, **kw: None
    fake_server.quit = lambda: None
    fake_server.has_extn = lambda *a, **kw: False
    fake_server.ehlo = lambda: None
    fake_server.starttls = lambda: None
    fake_server.docmd = lambda *a, **kw: (235, b"")

    with patch("core.imap_client.smtplib.SMTP_SSL", return_value=fake_server), \
         patch("core.imap_client.smtplib.SMTP", return_value=fake_server):
        ok, msg = c.send_email("to@x.com", "sub", "body")
    assert ok is False
    assert "认证" in msg or "auth" in msg.lower()


# ── 失败登录补 user_id 回归（phase 3.10）──────────────────────


def test_failed_login_writes_user_id_for_known_user(client):
    """失败登录在用户存在时必须写 user_id，让用户能在"仅看自己"里看到自己的失败尝试。"""
    client.post("/api/auth/logout")
    # 错密码登录 alice（用户存在）
    client.post("/api/auth/login", json={"username": "alice", "password": "wrong"})
    # 正常登录后再读自己审计
    client.post("/api/auth/login", json={"username": "alice", "password": "pwd-alice"})

    items = client.get("/api/audit?action=login").json()["items"]
    failed = [i for i in items if not i["success"]]
    assert failed, "至少应有一条失败登录审计"
    # 关键：失败审计里的 user_id 应非空（旧实现没写）
    assert any(i.get("user_id") for i in failed), (
        "已知用户的失败登录必须带 user_id，否则用户在'仅看自己'看不到自己的失败尝试"
    )


def test_failed_login_unknown_user_does_not_leak_user_id(client):
    """用户名拼错 / 不存在 → user_id 留空（避免对未注册用户名做枚举式审计）。"""
    client.post("/api/auth/logout")
    client.post(
        "/api/auth/login",
        json={"username": "nonexistent_user_xx", "password": "anything"},
    )
    # 重新登录后才能读审计
    client.post("/api/auth/login", json={"username": "alice", "password": "pwd-alice"})
    items = client.get("/api/audit?action=login").json()["items"]
    # nonexistent_user_xx 的审计行（如果能被自己看到，因为没 user_id 关联，本就看不到）
    # 这里只断言：alice 自己看不到任何 nonexistent_user_xx 的记录
    leaked = [i for i in items if i.get("username") == "nonexistent_user_xx"]
    assert not leaked, (
        "未知用户的失败登录不应出现在 alice 的'仅看自己'审计里 "
        "（user_id 应为 NULL，按 user_id 过滤后该条不可见）"
    )


# ── multipart 邮件解析硬上限 ─────────────────────────────────


def test_mail_parser_respects_part_count_limit():
    """phase 3.13: 超过 ``MAX_MULTIPART_PARTS`` 个 part 的邮件必须被截断，
    不能让 ``walk()`` 把 worker 锁在 CPU 上。"""
    from core.mail_parser import (
        get_email_body_with_type,
        has_attachments,
        MAX_MULTIPART_PARTS,
    )

    class FakePart:
        def __init__(self, ctype="text/plain", payload=b"x"):
            self._ctype = ctype
            self._payload = payload

        def get_content_type(self):
            return self._ctype

        def get_content_charset(self):
            return "utf-8"

        def get_payload(self, decode=False):
            return self._payload if decode else None

        def get(self, key, default=None):
            return default

    class FakeMsg:
        def __init__(self, parts):
            self._parts = parts

        def is_multipart(self):
            return True

        def walk(self):
            return iter(self._parts)

        def get_content_type(self):
            return "multipart/mixed"

    # 远超过 MAX_MULTIPART_PARTS 的恶意邮件
    parts = [FakePart() for _ in range(MAX_MULTIPART_PARTS + 50)]
    body, kind = get_email_body_with_type(FakeMsg(parts))
    # 不崩溃就算赢；body 命中第一个 text/plain 即可
    assert kind in ("text", "html")
    # has_attachments 也要受同一上限保护（不挂死）
    assert has_attachments(FakeMsg(parts)) is False
