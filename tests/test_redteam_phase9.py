# -*- coding: utf-8 -*-
"""Phase 9 红队视角(防爬取/盗号/撞库/信息泄露)修复回归测试。

每个测试钉住一项本轮加上的安全硬化，避免未来 commit 把它们悄悄回滚。

覆盖修复点：
- R1 ``/api/auth/me`` 不再向非 owner 返回真实 ``code_owner_username``
- R2 管理端 ``/docs`` ``/redoc`` ``/openapi.json`` 全部关闭
- R3 自定义 422 处理器：不回显请求 body / 不泄露密码原值
- R4 MIN_PASSWORD_LEN ≥ 8（旧短密码用户登录仍可，注册/改密强制）
- R5 登录纯 IP 维度限流：分布式撞库(同 IP + 不同 username 横扫)被锁定
- R8 ``_gc_pending_oauth``: 全局 GC 删除过期 state/cred bucket
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


# ── R1 /api/auth/me 不向非 owner 泄露 code_owner_username ─────────


def test_me_hides_code_owner_username_for_non_owner(client):
    """alice 不是站长 → ``code_owner_username`` 必须为空字符串。

    旧版无差别返回真实站长用户名，让任何注册用户登录后能拿到 → 针对性
    撞库目标。本次修复让该字段对非 owner 永远是 ""。
    """
    r = client.get("/api/auth/me")
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "alice"
    assert body["is_owner"] is False
    # 字段还在（前端兼容），但内容是空字符串
    assert "code_owner_username" in body
    assert body["code_owner_username"] == "", (
        f"非 owner 不应能拿到真实站长用户名，实际: {body['code_owner_username']!r}"
    )


def test_me_returns_real_owner_username_for_owner(tmp_path, monkeypatch):
    """站长本人登录时 ``code_owner_username`` 仍返回真实值（前端"加入接码"
    按钮等业务逻辑依赖该字段）。"""
    import sys
    from core import security
    security.SecretBox._instance = None  # noqa: SLF001
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CODE_OWNER_USERNAME", "owner_user")
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager", "core.")):
            sys.modules.pop(m, None)

    from fastapi.testclient import TestClient
    import web_app  # noqa: WPS433

    with TestClient(web_app.app) as c:
        r = c.post(
            "/api/auth/register",
            json={"username": "owner_user", "password": "owner-pwd-1"},
        )
        assert r.status_code == 200
        r = c.get("/api/auth/me")
        body = r.json()
        assert body["username"] == "owner_user"
        assert body["is_owner"] is True
        assert body["code_owner_username"] == "owner_user"

    security.SecretBox._instance = None  # noqa: SLF001


# ── R2 管理端 docs / redoc / openapi.json 关闭 ─────────────────────


def test_docs_routes_disabled(client):
    """``/docs`` ``/redoc`` ``/openapi.json`` 应一律 404。

    暴露 Swagger UI = 给攻击者一份"撞库爆破地图"（API 路由 / 参数 / 校验
    规则全展示）。接码前台早就关了，管理端补齐。
    """
    for path in ("/docs", "/redoc", "/openapi.json"):
        r = client.get(path)
        assert r.status_code == 404, (
            f"{path} 必须 404，实际 {r.status_code}（Swagger UI 暴露 API schema）"
        )


# ── R3 自定义 422 处理器：不回显请求 body ─────────────────────────


def test_validation_error_does_not_echo_password(client):
    """422 响应不能回显用户输入的密码 / 凭据原值。

    构造一个超长 password 触发 Pydantic ``Field(max_length=256)`` 校验失败，
    验证响应里没有把这串密码原样吐回来。
    """
    secret_password = "S" * 300  # 超过 max_length=256
    r = client.post(
        "/api/auth/login",
        json={"username": "alice", "password": secret_password},
    )
    assert r.status_code == 422
    body_text = r.text
    # 默认 Pydantic 422 处理器会把 input 字段（即 password 原值）放进 detail
    assert secret_password not in body_text, (
        "422 响应不应回显用户输入的密码 — 默认 Pydantic 处理器会泄露！"
    )
    # 但最低限度的字段名 + 错误原因应该有，便于客户端排错
    body = r.json()
    assert "errors" in body
    assert any("password" in e.get("loc", []) for e in body["errors"])


def test_validation_error_does_not_echo_oauth_redirect(client):
    """OAuth exchange 422 不能回显 redirect_url 中可能含的 code/state 等敏感参数。"""
    # 构造一个超长 redirect_url
    secret = "VERY_SECRET_AUTH_CODE_" + "x" * 5000
    r = client.post(
        "/api/oauth2/exchange",
        json={"redirect_url": secret},  # > max_length=4096
    )
    assert r.status_code == 422
    assert secret not in r.text, (
        "OAuth redirect_url 不应被回显 — 包含 authorization code 是高敏字段"
    )


def test_validation_error_response_shape_minimal(client):
    """422 响应只保留 detail + errors[{loc, msg}]，不含 input/url 等。"""
    r = client.post(
        "/api/auth/register",
        json={"username": "x" * 100, "password": "abc"},  # 用户名超长 + 密码太短
    )
    assert r.status_code == 422
    body = r.json()
    assert body.get("detail") == "请求参数校验失败"
    for err in body.get("errors", []):
        # 只允许 loc + msg 两个键
        assert set(err.keys()) <= {"loc", "msg"}, (
            f"422 错误条目含意外字段（可能泄露原值）: {err}"
        )


# ── R4 MIN_PASSWORD_LEN ≥ 8 ───────────────────────────────────────


def test_min_password_length_is_8():
    """MIN_PASSWORD_LEN 不能再降到 < 8（防低强度密码暴破）。"""
    from core.auth import MIN_PASSWORD_LEN
    assert MIN_PASSWORD_LEN >= 8, (
        f"MIN_PASSWORD_LEN={MIN_PASSWORD_LEN} 太低 — 6/7 位密码 PBKDF2 200k "
        f"在 GPU 算力下可被暴破。"
    )


def test_register_rejects_password_under_8_chars(client):
    """7 字符密码必须被注册接口拒绝（旧版 6 位允许，本次提升）。"""
    client.post("/api/auth/logout")
    r = client.post(
        "/api/auth/register",
        json={"username": "newuser", "password": "abc1234"},  # 7 字符
    )
    assert r.status_code == 400
    assert "至少" in r.text or "长度" in r.text


def test_register_accepts_8_char_password(client):
    """8 字符密码正常通过（边界值）。"""
    client.post("/api/auth/logout")
    r = client.post(
        "/api/auth/register",
        json={"username": "newuser2", "password": "abc12345"},  # 8 字符
    )
    assert r.status_code == 200


def test_change_password_also_enforces_min_length(client):
    """改密接口也强制 ≥ 8 位（不能让用户从 8 位降级到 6 位）。"""
    r = client.post(
        "/api/auth/change-password",
        json={"old_password": "pwd-alice", "new_password": "abc123"},  # 6 字符
    )
    assert r.status_code == 400


# ── R5 登录纯 IP 限流（防分布式撞库）─────────────────────────────


def test_ip_login_limiter_blocks_after_horizontal_scan(tmp_path, monkeypatch):
    """同 IP + 不同 username 横扫超过 IP 阈值 → 第 N+1 次直接 429。

    这是分布式撞库的关键防御：``login_limiter`` 的 (username, ip) 双键
    挡不住"轮换 username 同 IP"的横扫，``ip_login_limiter`` 的纯 IP
    维度桶兜底拦下。
    """
    import sys
    from core import security
    from core.rate_limit import (
        IP_LOGIN_LIMITER_KEY,
        ip_login_limiter,
        login_limiter,
    )
    security.SecretBox._instance = None  # noqa: SLF001
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager", "core.")):
            sys.modules.pop(m, None)

    # 重新导入 + reset 两个 limiter（避免与其他测试共享状态）
    from core.rate_limit import (  # noqa: WPS433
        ip_login_limiter as fresh_ip_limiter,
        login_limiter as fresh_login_limiter,
    )
    fresh_ip_limiter.reset()
    fresh_login_limiter.reset()

    from fastapi.testclient import TestClient
    import web_app  # noqa: WPS433

    with TestClient(web_app.app) as c:
        # 注册一个真实用户（不需要,但确保 IP 桶清零）
        c.post(
            "/api/auth/register",
            json={"username": "victim", "password": "pwd-victim"},
        )
        c.post("/api/auth/logout")

        seen_429 = False
        # IP 桶阈值=50；轮换 60 个 username 各试一次密码错误，必然触发
        # IP 桶锁定（单 (username,ip) 桶每个都只 1 次失败，触不到 username 桶阈值）
        # 60 留 10 次缓冲避免边界条件偶发跳过
        for i in range(60):
            r = c.post(
                "/api/auth/login",
                json={"username": f"randomuser_{i}", "password": "wrong"},
            )
            if r.status_code == 429:
                seen_429 = True
                assert "Retry-After" in r.headers
                break
            assert r.status_code in (401, 429), (
                f"非 401/429: {r.status_code}, body={r.text[:100]}"
            )
        assert seen_429, (
            "横扫 60 个 username 后必须触发 IP 维度限流锁定 — 否则分布式撞库无防御"
        )

    fresh_ip_limiter.reset()
    fresh_login_limiter.reset()
    security.SecretBox._instance = None  # noqa: SLF001


def test_ip_login_limiter_clears_on_success(tmp_path, monkeypatch):
    """登录成功时清空当前 IP 的失败计数 — 偶尔输错密码后成功登录的合法
    用户不会因 IP 桶残留计数被未来误锁。"""
    import sys
    from core import security
    security.SecretBox._instance = None  # noqa: SLF001
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager", "core.")):
            sys.modules.pop(m, None)

    from core.rate_limit import (  # noqa: WPS433
        IP_LOGIN_LIMITER_KEY,
        ip_login_limiter,
        login_limiter,
    )
    ip_login_limiter.reset()
    login_limiter.reset()

    from fastapi.testclient import TestClient
    import web_app  # noqa: WPS433

    with TestClient(web_app.app) as c:
        c.post(
            "/api/auth/register",
            json={"username": "alice", "password": "pwd-alice"},
        )
        c.post("/api/auth/logout")

        # 错 3 次（< login_limiter.max_fails=5，避免双键桶锁定让正确密码登录不上）
        # 此时 IP 桶累计 3，username-ip 双键桶也累计 3
        for _ in range(3):
            r = c.post(
                "/api/auth/login",
                json={"username": "alice", "password": "wrong"},
            )
            assert r.status_code == 401

        # 正确密码登录成功（双键桶 3 < 5 阈值，不会被锁定）
        r = c.post(
            "/api/auth/login",
            json={"username": "alice", "password": "pwd-alice"},
        )
        assert r.status_code == 200

        # IP 桶应清零
        remaining = ip_login_limiter.remaining_attempts(
            IP_LOGIN_LIMITER_KEY, "testclient",
        )
        assert remaining == ip_login_limiter.max_fails, (
            f"登录成功后 IP 桶应清零，剩余 {remaining}（期望 {ip_login_limiter.max_fails}）"
        )

    ip_login_limiter.reset()
    login_limiter.reset()
    security.SecretBox._instance = None  # noqa: SLF001


def test_ip_login_limiter_independent_from_username_bucket():
    """``ip_login_limiter`` 与 ``login_limiter`` 是完全独立的桶。"""
    from core.rate_limit import (
        IP_LOGIN_LIMITER_KEY,
        ip_login_limiter,
        login_limiter,
    )
    ip_login_limiter.reset()
    login_limiter.reset()

    # 在 (username, ip) 桶里制造失败
    for _ in range(3):
        login_limiter.record_failure("alice", "1.2.3.4")

    # IP 桶应仍干净
    remaining = ip_login_limiter.remaining_attempts(
        IP_LOGIN_LIMITER_KEY, "1.2.3.4",
    )
    assert remaining == ip_login_limiter.max_fails, (
        f"ip_login_limiter 不应被 login_limiter 拖累，剩余 {remaining}"
    )

    ip_login_limiter.reset()
    login_limiter.reset()


# ── R8 OAuth 暂存桶 GC ────────────────────────────────────────────


def test_gc_pending_oauth_drops_expired_state_buckets(client):
    """``_gc_pending_oauth`` 应清空已过期的 state buckets + 整体清掉空桶。"""
    import time
    import web_app

    # 直接操作模块级 dict 注入"已过期"项
    with web_app._pending_oauth_states_lock:  # noqa: SLF001
        web_app._pending_oauth_states.clear()  # noqa: SLF001
        web_app._pending_oauth_states[9001] = [  # noqa: SLF001
            ("expired_state_a", time.monotonic() - 100),  # 已过期
            ("expired_state_b", time.monotonic() - 50),   # 已过期
        ]
        web_app._pending_oauth_states[9002] = [  # noqa: SLF001
            ("fresh_state", time.monotonic() + 999),  # 仍有效
        ]

    states_dropped, _ = web_app._gc_pending_oauth()  # noqa: SLF001
    assert states_dropped == 2, f"应清掉 2 个过期 state，实际 {states_dropped}"

    with web_app._pending_oauth_states_lock:  # noqa: SLF001
        # 9001 整桶清空 → 应被 pop
        assert 9001 not in web_app._pending_oauth_states  # noqa: SLF001
        # 9002 仍保留
        assert 9002 in web_app._pending_oauth_states  # noqa: SLF001
        bucket = web_app._pending_oauth_states[9002]  # noqa: SLF001
        assert len(bucket) == 1
        assert bucket[0][0] == "fresh_state"

    # 清理
    with web_app._pending_oauth_states_lock:  # noqa: SLF001
        web_app._pending_oauth_states.clear()  # noqa: SLF001


def test_gc_pending_oauth_drops_expired_credentials(client):
    """``_gc_pending_oauth`` 同步清掉过期的 _pending_oauth（refresh_token 暂存）。"""
    import time
    import web_app

    with web_app._pending_oauth_lock:  # noqa: SLF001
        web_app._pending_oauth.clear()  # noqa: SLF001
        web_app._pending_oauth[8001] = (  # noqa: SLF001
            "cid", "rt_expired", "g", time.monotonic() - 1,  # 已过期
        )
        web_app._pending_oauth[8002] = (  # noqa: SLF001
            "cid", "rt_fresh", "g", time.monotonic() + 999,  # 仍有效
        )

    _, creds_dropped = web_app._gc_pending_oauth()  # noqa: SLF001
    assert creds_dropped == 1

    with web_app._pending_oauth_lock:  # noqa: SLF001
        assert 8001 not in web_app._pending_oauth  # noqa: SLF001
        assert 8002 in web_app._pending_oauth  # noqa: SLF001
        web_app._pending_oauth.clear()  # noqa: SLF001


def test_gc_pending_oauth_safe_on_empty_state(client):
    """空 dict 上调用不应抛异常，返回 (0, 0)。"""
    import web_app
    with web_app._pending_oauth_states_lock:  # noqa: SLF001
        web_app._pending_oauth_states.clear()  # noqa: SLF001
    with web_app._pending_oauth_lock:  # noqa: SLF001
        web_app._pending_oauth.clear()  # noqa: SLF001

    states_dropped, creds_dropped = web_app._gc_pending_oauth()  # noqa: SLF001
    assert states_dropped == 0
    assert creds_dropped == 0
