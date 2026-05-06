# -*- coding: utf-8 -*-
"""FastAPI 端点回归测试（多用户隔离版）。"""

from __future__ import annotations


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["auth_required"] is True
    assert body["register_enabled"] is True


def test_export_route_not_shadowed_by_int_param(client):
    """/api/accounts/export 不能被 /{account_id} 路由吞掉。

    自 v3.1 起 GET 已禁用（要求 POST + 二次密码），但路由本身必须存在，
    否则会被 /{account_id} 把 'export' 当成整数解析失败返回 422。
    """
    r = client.get("/api/accounts/export")
    # 405 = 路由命中但方法不允许（正确）；422 = 被吞了（错）
    assert r.status_code == 405


def test_get_nonexistent_account_returns_404(client):
    r = client.get("/api/accounts/99999")
    assert r.status_code == 404


def test_update_nonexistent_account_returns_404(client):
    r = client.put("/api/accounts/99999/group", json={"group": "X"})
    assert r.status_code == 404
    r = client.put("/api/accounts/99999/remark", json={"remark": "x"})
    assert r.status_code == 404


def test_delete_nonexistent_group_returns_404(client):
    r = client.delete("/api/groups/notexist")
    assert r.status_code == 404


def test_rename_nonexistent_group_returns_404(client):
    r = client.put("/api/groups/notexist", json={"new_name": "x"})
    assert r.status_code == 404


def test_default_group_protected(client):
    assert client.delete("/api/groups/默认分组").status_code == 400
    assert client.put("/api/groups/默认分组", json={"new_name": "x"}).status_code == 400


def test_blank_group_name_rejected(client):
    r = client.post("/api/groups", json={"name": "   "})
    assert r.status_code == 422


def test_settings_whitelist_enforced(client):
    r = client.put("/api/settings", json={"key": "hack", "value": "1"})
    assert r.status_code == 400


def test_invalid_folder_rejected(client):
    client.post("/api/accounts/import", json={
        "text": "u@gmail.com----p", "group": "默认分组", "skip_duplicate": False
    })
    aid = client.get("/api/accounts").json()[0]["id"]
    r = client.get(f"/api/accounts/{aid}/emails?folder=hack")
    assert r.status_code == 422


def test_limit_out_of_range_rejected(client):
    client.post("/api/accounts/import", json={
        "text": "u@gmail.com----p", "group": "默认分组", "skip_duplicate": False
    })
    aid = client.get("/api/accounts").json()[0]["id"]
    r = client.get(f"/api/accounts/{aid}/emails?limit=99999")
    assert r.status_code == 422


def test_import_creates_group_automatically(client):
    r = client.post("/api/accounts/import", json={
        "text": "auto@gmail.com----p", "group": "新分组Z", "skip_duplicate": False,
    })
    assert r.status_code == 200
    assert r.json()["success"] == 1

    groups = [g["name"] for g in client.get("/api/groups").json()]
    assert "新分组Z" in groups


def test_batch_delete_returns_actual_count(client):
    r = client.post("/api/accounts/import", json={
        "text": "a@g.com----p\nb@g.com----p", "group": "默认分组", "skip_duplicate": False,
    })
    assert r.status_code == 200
    ids = [a["id"] for a in client.get("/api/accounts").json()]

    r = client.post("/api/accounts/delete", json={"ids": ids + [99999]})
    assert r.status_code == 200
    assert r.json() == {"deleted": len(ids), "requested": len(ids) + 1}


def test_dashboard_counts(client):
    client.post("/api/accounts/import", json={
        "text": "a@g.com----p\nb@g.com----p\nc@g.com----p",
        "group": "默认分组", "skip_duplicate": False,
    })
    d = client.get("/api/dashboard").json()
    assert d["total"] == 3
    assert d["statuses"]["未检测"] == 3


def test_password_returned_decrypted(client):
    client.post("/api/accounts/import", json={
        "text": "x@g.com----myplain", "group": "默认分组", "skip_duplicate": False,
    })
    a = client.get("/api/accounts").json()[0]
    assert a["password"] == "myplain"


def test_data_dir_env_var(tmp_path, monkeypatch):
    """EMAIL_DATA_DIR 应能控制数据库与主密钥的位置。"""
    import sys
    from core import security
    security.SecretBox._instance = None  # noqa: SLF001

    custom_dir = tmp_path / "custom"
    monkeypatch.setenv("EMAIL_DATA_DIR", str(custom_dir))
    monkeypatch.chdir(tmp_path)
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager", "core.")):
            sys.modules.pop(m, None)

    from database.db_manager import DatabaseManager  # noqa: WPS433
    db = DatabaseManager()
    assert (custom_dir / "emails.db").exists()
    assert (custom_dir / ".master.key").exists()

    security.SecretBox._instance = None  # noqa: SLF001


# ── Auth ─────────────────────────────────────────────────────────


def test_unauthenticated_requests_rejected(tmp_path, monkeypatch):
    """未登录访问受保护接口应 401，且不区分 GET/POST/PUT/DELETE。"""
    import sys
    from core import security
    security.SecretBox._instance = None  # noqa: SLF001
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager", "core.")):
            sys.modules.pop(m, None)

    from fastapi.testclient import TestClient
    import web_app

    with TestClient(web_app.app) as c:
        # 未登录：受保护接口 401
        assert c.get("/api/accounts").status_code == 401
        assert c.get("/api/groups").status_code == 401
        assert c.get("/api/settings").status_code == 401
        assert c.get("/api/dashboard").status_code == 401
        assert c.get("/api/auth/me").status_code == 401
        # 公开接口可访问
        assert c.get("/api/health").status_code == 200

    security.SecretBox._instance = None  # noqa: SLF001


def test_register_login_logout_flow(client):
    """登录态由 cookie 维护：注销后不应再被识别为已登录。"""
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json() == {"username": "alice"}

    # 注销后 cookie 失效
    assert client.post("/api/auth/logout").status_code == 200
    # TestClient 自带 cookie jar，注销后 cookie 已被清，应当 401
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/accounts").status_code == 401

    # 重新登录应成功
    r = client.post("/api/auth/login", json={"username": "alice", "password": "pwd-alice"})
    assert r.status_code == 200
    assert client.get("/api/auth/me").status_code == 200


def test_register_validates_fields(client):
    # 用户名太短
    r = client.post("/api/auth/register", json={"username": "ab", "password": "abcdef"})
    assert r.status_code == 400
    # 密码太短
    r = client.post("/api/auth/register", json={"username": "valid", "password": "123"})
    assert r.status_code == 400
    # 用户名含非法字符
    r = client.post("/api/auth/register", json={"username": "中文名", "password": "abcdef"})
    assert r.status_code == 400


def test_register_duplicate_rejected(client):
    """alice 已存在（来自 fixture），不能再注册同名。"""
    r = client.post("/api/auth/register", json={"username": "alice", "password": "anything"})
    assert r.status_code == 409


def test_login_wrong_password_rejected(client):
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"username": "alice", "password": "wrong"})
    assert r.status_code == 401


def test_login_username_case_insensitive(client):
    """注册时统一小写存储，登录支持任意大小写。"""
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"username": "ALICE", "password": "pwd-alice"})
    assert r.status_code == 200


def test_change_password_requires_old(client):
    r = client.post(
        "/api/auth/change-password",
        json={"old_password": "wrong", "new_password": "abcdef-new"},
    )
    assert r.status_code == 400

    r = client.post(
        "/api/auth/change-password",
        json={"old_password": "pwd-alice", "new_password": "abcdef-new"},
    )
    assert r.status_code == 200
    # 修改密码后会清当前 cookie
    assert client.get("/api/auth/me").status_code == 401
    # 旧密码不能再用
    r = client.post("/api/auth/login", json={"username": "alice", "password": "pwd-alice"})
    assert r.status_code == 401
    # 新密码可登录
    r = client.post("/api/auth/login", json={"username": "alice", "password": "abcdef-new"})
    assert r.status_code == 200


# ── 数据隔离 ─────────────────────────────────────────────────────


def test_two_users_data_isolated(client2):
    """两个登录用户互不可见对方的账号、分组、仪表盘。"""
    a, b = client2

    a.post("/api/accounts/import", json={
        "text": "a1@g.com----p\na2@g.com----p", "group": "默认分组", "skip_duplicate": False,
    })
    b.post("/api/accounts/import", json={
        "text": "b1@g.com----p", "group": "默认分组", "skip_duplicate": False,
    })

    a_emails = sorted(x["email"] for x in a.get("/api/accounts").json())
    b_emails = sorted(x["email"] for x in b.get("/api/accounts").json())
    assert a_emails == ["a1@g.com", "a2@g.com"]
    assert b_emails == ["b1@g.com"]

    assert a.get("/api/dashboard").json()["total"] == 2
    assert b.get("/api/dashboard").json()["total"] == 1


def test_groups_isolated_between_users(client2):
    """同名分组分别归属，互不影响；删除/重命名不会牵连对方。"""
    a, b = client2
    a.post("/api/groups", json={"name": "Common"})
    b.post("/api/groups", json={"name": "Common"})
    assert "Common" in [g["name"] for g in a.get("/api/groups").json()]
    assert "Common" in [g["name"] for g in b.get("/api/groups").json()]

    # alice 删除自己的 Common，不影响 bob
    assert a.delete("/api/groups/Common").status_code == 200
    assert "Common" not in [g["name"] for g in a.get("/api/groups").json()]
    assert "Common" in [g["name"] for g in b.get("/api/groups").json()]


def test_user_cannot_read_other_users_account_by_id(client2):
    """alice 拿到自己的 account_id 后，bob 直接 GET 不能读到。"""
    a, b = client2
    a.post("/api/accounts/import", json={
        "text": "secret@g.com----top", "group": "默认分组", "skip_duplicate": False,
    })
    aid = a.get("/api/accounts").json()[0]["id"]
    assert a.get(f"/api/accounts/{aid}").status_code == 200
    assert b.get(f"/api/accounts/{aid}").status_code == 404
    # 改/删也都不行
    assert b.put(f"/api/accounts/{aid}/remark", json={"remark": "x"}).status_code == 404
    assert b.post("/api/accounts/delete", json={"ids": [aid]}).json()["deleted"] == 0
    # alice 仍然可以读到
    assert a.get(f"/api/accounts/{aid}").status_code == 200


def test_settings_isolated_between_users(client2):
    a, b = client2
    a.put("/api/settings", json={"key": "theme", "value": "dark"})
    b.put("/api/settings", json={"key": "theme", "value": "light"})
    assert a.get("/api/settings").json()["theme"] == "dark"
    assert b.get("/api/settings").json()["theme"] == "light"


# ── TRUST_PROXY / _is_https / _client_ip 行为 ────────────────────────


def _make_request(headers: dict, peer: str = "10.0.0.1", scheme: str = "http"):
    """构造 starlette Request 用于直接调用 _client_ip / _is_https。"""
    from starlette.requests import Request
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/health",
        "scheme": scheme,
        "client": (peer, 12345),
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "query_string": b"",
        "root_path": "",
        "server": ("testserver", 80),
    }
    return Request(scope)


def test_client_ip_ignores_proxy_headers_when_trust_off(client, monkeypatch):
    """TRUST_PROXY=False 时绝不能信任 X-Forwarded-* / X-Real-IP / CF-Connecting-IP。"""
    import web_app
    monkeypatch.setattr(web_app, "TRUST_PROXY", False)

    ip = web_app._client_ip(_make_request({  # noqa: SLF001
        "x-forwarded-for": "9.9.9.9",
        "x-real-ip": "8.8.8.8",
        "cf-connecting-ip": "1.2.3.4",
    }))
    assert ip == "10.0.0.1", "TRUST_PROXY=False 必须只用 client.host"


def test_client_ip_trusts_cloudflare_when_trust_on(client, monkeypatch):
    """TRUST_PROXY=True 时优先取 CF-Connecting-IP > X-Forwarded-For > X-Real-IP。"""
    import web_app
    monkeypatch.setattr(web_app, "TRUST_PROXY", True)

    # CF 优先
    ip = web_app._client_ip(_make_request({  # noqa: SLF001
        "cf-connecting-ip": "1.2.3.4",
        "x-forwarded-for": "9.9.9.9",
        "x-real-ip": "8.8.8.8",
    }))
    assert ip == "1.2.3.4"

    # 退回 XFF 首段
    ip = web_app._client_ip(_make_request({  # noqa: SLF001
        "x-forwarded-for": "9.9.9.9, 5.5.5.5",
        "x-real-ip": "8.8.8.8",
    }))
    assert ip == "9.9.9.9"


def test_is_https_ignores_proxy_proto_when_trust_off(client, monkeypatch):
    """TRUST_PROXY=False 时 X-Forwarded-Proto: https 不能让 _is_https 返回 True。"""
    import web_app
    monkeypatch.setattr(web_app, "TRUST_PROXY", False)
    assert web_app._is_https(  # noqa: SLF001
        _make_request({"x-forwarded-proto": "https"}, scheme="http")
    ) is False
    # 直接 HTTPS 始终为 True
    assert web_app._is_https(_make_request({}, scheme="https")) is True  # noqa: SLF001


def test_is_https_uses_proxy_proto_when_trust_on(client, monkeypatch):
    import web_app
    monkeypatch.setattr(web_app, "TRUST_PROXY", True)
    assert web_app._is_https(  # noqa: SLF001
        _make_request({"x-forwarded-proto": "https"}, scheme="http")
    ) is True


# ── change_password 必须踢光所有会话 ───────────────────────────


def test_change_password_revokes_all_sessions(client2):
    """alice 改密后，**alice 的所有 session**（含其它端持有的有效 cookie）都失效。

    这里通过登录两个独立 client（共享 alice 账号）模拟"两个浏览器同时登录"的场景：
    - 一台用 alice 登录后改密 → 第二台仍持旧 cookie，但访问 /api/auth/me 必须 401。
    """
    from fastapi.testclient import TestClient
    import web_app
    a, _ = client2

    # 第二个 alice 端：同一份 EMAIL_DATA_DIR，登录拿到独立 cookie
    other = TestClient(web_app.app)
    r = other.post("/api/auth/login", json={"username": "alice", "password": "pwd-alice"})
    assert r.status_code == 200
    assert other.get("/api/auth/me").status_code == 200

    # alice 在第一个端改密
    r = a.post(
        "/api/auth/change-password",
        json={"old_password": "pwd-alice", "new_password": "abcdef-new"},
    )
    assert r.status_code == 200

    # 第二个端的 cookie 必须立即失效
    assert other.get("/api/auth/me").status_code == 401

    # 第一个端也已经失效（自己也得重新登录）
    assert a.get("/api/auth/me").status_code == 401

    # 旧密码不能用，新密码可用
    r = other.post("/api/auth/login", json={"username": "alice", "password": "pwd-alice"})
    assert r.status_code == 401
    r = other.post("/api/auth/login", json={"username": "alice", "password": "abcdef-new"})
    assert r.status_code == 200


# ── BatchSendRequest 收件人数量限制 ───────────────────────────


def test_batch_send_recipient_limit_enforced(client, monkeypatch):
    """to 字段超过 MAX_RECIPIENTS_PER_SEND 个收件人 → 422。"""
    import web_app
    monkeypatch.setattr(web_app, "MAX_RECIPIENTS_PER_SEND", 3)

    too_many = ",".join(f"u{i}@example.com" for i in range(5))
    r = client.post(
        "/api/batch/send",
        json={"account_ids": [1], "to": too_many, "subject": "s", "body": "b"},
    )
    assert r.status_code == 422
    assert "收件人" in r.text


def test_send_email_recipient_limit_enforced(client, monkeypatch):
    import web_app
    monkeypatch.setattr(web_app, "MAX_RECIPIENTS_PER_SEND", 2)
    too_many = "a@x.com,b@x.com,c@x.com"
    r = client.post(
        "/api/accounts/99999/emails/send",  # 即使账号不存在也是先校验请求体
        json={"to": too_many, "subject": "s", "body": "b"},
    )
    assert r.status_code == 422


def test_send_email_dedup_recipients(client):
    """重复的收件人地址只算一次（大小写不敏感），所以下面 5 个去重后 2 个，没超 50。"""
    r = client.post(
        "/api/accounts/99999/emails/send",
        json={"to": "a@x.com,A@X.com,a@x.COM,b@x.com,B@x.com", "subject": "s", "body": "b"},
    )
    # 校验通过后命中"账号不存在"
    assert r.status_code == 404


def test_send_email_blank_recipients_rejected(client):
    r = client.post(
        "/api/accounts/99999/emails/send",
        json={"to": "  , ; ", "subject": "s", "body": "b"},
    )
    assert r.status_code == 422


def test_send_email_rejects_crlf_injection(client):
    """收件人字段含 CRLF 必须被拒，防 SMTP 头注入跳板。"""
    bad_to = "victim@example.com\r\nBcc: hidden@attacker.com"
    r = client.post(
        "/api/accounts/99999/emails/send",
        json={"to": bad_to, "subject": "s", "body": "b"},
    )
    assert r.status_code == 422
    assert "非法换行" in r.text or "换行" in r.text


# ── 账号邮箱标准化：不同大小写不重复 ──


def test_account_email_normalized_lowercase_on_import(client):
    """import 同一邮箱不同大小写应会被按同一账号处理。

    预期：同名不同 case 的第二次 import，在 ``skip_duplicate=True`` 下被
    skipped；同时返回列表里只看到一个小写化后的账号。
    """
    r = client.post("/api/accounts/import", json={
        "text": "User@Example.com----pwd1",
        "group": "默认分组", "skip_duplicate": True,
    })
    assert r.status_code == 200
    assert r.json()["success"] == 1

    # 再传一份全大写，期望被去重
    r = client.post("/api/accounts/import", json={
        "text": "USER@EXAMPLE.COM----pwd2",
        "group": "默认分组", "skip_duplicate": True,
    })
    assert r.status_code == 200
    assert r.json()["skipped"] == 1
    assert r.json()["success"] == 0

    accs = client.get("/api/accounts").json()
    assert len(accs) == 1
    assert accs[0]["email"] == "user@example.com"


# ── cookie set / clear 属性对齐 ──


def test_logout_clear_cookie_attributes_match_set(client):
    """注销时下发的 Set-Cookie（清空 cookie）必须带与登录时一致的属性集。

    某些浏览器（Safari / 部分 Chrome）若 set 与 clear 的属性不一致会拒绝清除，
    导致用户登出后再访问 /api/auth/me 仍是登录态（cookie 没真删）。
    """
    # 登录后查看登录时的 Set-Cookie
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"username": "alice", "password": "pwd-alice"})
    assert r.status_code == 200
    set_cookie_login = r.headers.get("set-cookie", "").lower()
    assert "path=/" in set_cookie_login
    assert "samesite=lax" in set_cookie_login
    assert "httponly" in set_cookie_login

    # 然后 logout，验证 clear 时也带同样的属性集（path / samesite / httponly）
    r2 = client.post("/api/auth/logout")
    assert r2.status_code == 200
    set_cookie_clear = r2.headers.get("set-cookie", "").lower()
    assert "path=/" in set_cookie_clear, "clear cookie 必须也带 Path=/"
    assert "samesite=lax" in set_cookie_clear, "clear cookie 必须也带 SameSite=lax"
    assert "httponly" in set_cookie_clear, "clear cookie 必须也带 HttpOnly"


# ── _INDEX_CACHE 并发安全冒烟 ──


def test_send_one_sync_exception_message_truncated(client, monkeypatch):
    """``_send_one_sync`` 应当截断异常 message，避免敏感堆栈泄漏给前端。

    我们模拟 `client.send_email` 抛出含特别长 / 包含敏感字符的异常，
    验证返回的 message 被截到合理长度 + 不含原始堆栈细节。
    """
    import web_app
    from core.email_client import EmailClient

    # 准备账号
    client.post("/api/accounts/import", json={
        "text": "victim@gmail.com----some-password-aaaaaaa",
        "group": "默认分组", "skip_duplicate": False,
    })
    aid = client.get("/api/accounts").json()[0]["id"]
    me = client.get("/api/auth/me").json()
    # alice 的 user_id —— TestClient 已登录 alice
    user = web_app.db.get_user_by_username(me["username"])
    owner_id = user["id"]

    # mock send_email 抛超长异常
    long_secret = "S" + "x" * 500 + "/etc/passwd:ROOT_TOKEN=abc"

    def boom(self, *a, **kw):
        raise RuntimeError(long_secret)

    monkeypatch.setattr(EmailClient, "send_email", boom, raising=True)

    r = web_app._send_one_sync(owner_id, aid, "to@example.com", "s", "b")  # noqa: SLF001
    assert r["success"] is False
    msg = r["message"]
    # 长度受限（exc body 截到 160 字符 + 前缀）
    assert len(msg) <= 220, f"异常消息未截断: len={len(msg)} content={msg[:300]}"
    # 类名带在前缀里，便于运维定位
    assert "RuntimeError" in msg
    # 原始 secret 大部分不应该被透传（验证截断真的生效）
    assert long_secret not in msg


def test_cleanup_old_code_query_log_direct(tmp_db):
    """验证 cleanup_old_code_query_log 真的能删除超期记录。"""
    db, owner_id = tmp_db
    from datetime import datetime, timedelta

    # 写入一条 35 天前的旧日志 + 一条今天的新日志
    db.add_code_query_log(
        ip_hash="ip-old", email_hash="email-old",
        category="cursor", success=True, source="public",
    )
    db.add_code_query_log(
        ip_hash="ip-new", email_hash="email-new",
        category="cursor", success=True, source="public",
    )
    # 强制把第一条记录的 ts 改成 35 天前
    old_ts = (datetime.now() - timedelta(days=35)).isoformat(sep=" ", timespec="seconds")
    with db._connect() as conn:  # noqa: SLF001
        conn.execute(
            "UPDATE code_query_log SET ts = ? WHERE ip_hash = 'ip-old'", (old_ts,),
        )
        cnt_before = conn.execute("SELECT COUNT(*) FROM code_query_log").fetchone()[0]
    assert cnt_before == 2

    n = db.cleanup_old_code_query_log(retention_days=30)
    assert n == 1, f"应清除 1 条 35 天前的日志，实际清了 {n} 条"

    with db._connect() as conn:  # noqa: SLF001
        rows = conn.execute(
            "SELECT ip_hash FROM code_query_log",
        ).fetchall()
    remaining = {r[0] for r in rows}
    assert remaining == {"ip-new"}


def test_serve_index_concurrent_access_safe(client):
    """两个线程并发访问 / 应当都能拿到完整 HTML（无中间态）。

    锁内 `cached_html` 局部变量再返回，杜绝 `_INDEX_CACHE["html"]` 在
    update 中被读到 None 的可能。
    """
    import threading
    results: list = []

    def worker():
        r = client.get("/")
        results.append((r.status_code, "<html" in r.text.lower(), len(r.text)))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert len(results) == 8
    for status_code, has_html, length in results:
        assert status_code == 200
        assert has_html, "并发请求拿到非 HTML 响应"
        assert length > 100, "并发请求拿到截断的响应"
