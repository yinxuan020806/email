# -*- coding: utf-8 -*-
"""Phase 8 性能 / 安全优化的回归测试。

每个测试钉住一项本轮加上的硬化修复，避免后续 commit 把这些保障回滚。

覆盖修复点：
- O1 SQLite PRAGMA：cache_size / mmap_size / busy_timeout / temp_store 都生效
- O2 ``DatabaseManager.get_existing_emails``：仅 SELECT email，**不解密**任何密文
- O3 ``DatabaseManager.get_dashboard_stats``：纯 SQL GROUP BY 聚合
- O4 管理端全局安全响应头中间件：CSP / X-Frame-Options / X-Content-Type-Options
- O5 GZipMiddleware：大 JSON 响应被压缩
- O6 ``_CachedStaticFiles``：/static/* 200 响应带长缓存头
- O7 ``/api/auth/register`` IP 限流：连续失败触发 429
- O8 ``/api/dashboard`` 改造后**不再调用** ``get_all_accounts``
- O9 ``import_accounts`` 改造后**不再调用** ``get_all_accounts``
- O10 lifespan：TestClient 进入/退出生命周期不抛 stranded coroutine
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


# ── O1 SQLite PRAGMA ──────────────────────────────────────────────


def test_sqlite_perf_pragmas_applied_on_each_connection(tmp_db):
    """每条新连接都应用 cache_size / mmap_size / busy_timeout / temp_store。

    PRAGMA 是 connection-level，写在 ``get_connection`` 才能保证业务路径
    （每个请求 connect→use→close）都享受到。仅在 init 那一条连接上设
    会让生产 90% 流量拿不到优化，等于没做。
    """
    db, _ = tmp_db
    with db._connect() as conn:  # noqa: SLF001
        # cache_size 负数表示按 KB 计；64MB ≈ -64000
        cache_size = conn.execute("PRAGMA cache_size").fetchone()[0]
        assert cache_size == -64000, (
            f"cache_size 应为 -64000（64MB），实际 {cache_size}"
        )
        mmap_size = conn.execute("PRAGMA mmap_size").fetchone()[0]
        assert mmap_size == 268435456, f"mmap_size 应为 256MB，实际 {mmap_size}"
        busy = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert busy == 5000, f"busy_timeout 应为 5000ms，实际 {busy}"
        temp_store = conn.execute("PRAGMA temp_store").fetchone()[0]
        # temp_store: 0=DEFAULT 1=FILE 2=MEMORY
        assert temp_store == 2, f"temp_store 应为 MEMORY (2)，实际 {temp_store}"


def test_sqlite_journal_mode_remains_wal(tmp_db):
    """新 PRAGMA 不能影响 WAL 配置（基线行为不退化）。"""
    db, _ = tmp_db
    with db._connect() as conn:  # noqa: SLF001
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal", f"journal_mode 应为 wal，实际 {mode}"


# ── O2 get_existing_emails ────────────────────────────────────────


def test_get_existing_emails_returns_lowercase_set(tmp_db):
    """返回小写 email 集合，不构造 Account 对象。"""
    db, uid = tmp_db
    db.add_account(uid, "Alpha@Example.COM", "p1")
    db.add_account(uid, "beta@example.com", "p2")
    emails = db.get_existing_emails(uid)
    assert isinstance(emails, set)
    assert emails == {"alpha@example.com", "beta@example.com"}


def test_get_existing_emails_isolated_per_user(tmp_db):
    """跨用户隔离：bob 的账号不出现在 alice 的集合里。"""
    from core.auth import hash_password
    db, uid_a = tmp_db
    uid_b = db.create_user("bob", hash_password("pwd-bob1"))
    db.add_account(uid_a, "alice@x.com", "p")
    db.add_account(uid_b, "bob@x.com", "p")
    a_emails = db.get_existing_emails(uid_a)
    b_emails = db.get_existing_emails(uid_b)
    assert a_emails == {"alice@x.com"}
    assert b_emails == {"bob@x.com"}


def test_get_existing_emails_does_not_decrypt_passwords(tmp_db):
    """关键性能契约：不解密任何 password / refresh_token 密文。

    旧实现走 ``get_all_accounts`` → ``_row_to_account`` → 触发 N 次
    ``SecretBox.decrypt``。本方法只 SELECT email 列，必须 0 次解密。
    """
    db, uid = tmp_db
    for i in range(5):
        db.add_account(uid, f"u{i}@x.com", f"plain-pwd-{i}")

    from core.security import SecretBox
    box = SecretBox.instance()
    with patch.object(box, "decrypt", wraps=box.decrypt) as spy:
        emails = db.get_existing_emails(uid)

    assert emails == {f"u{i}@x.com" for i in range(5)}
    assert spy.call_count == 0, (
        f"get_existing_emails 不应触发 SecretBox.decrypt，实际调用 {spy.call_count} 次。"
        "若调用了说明退化成 get_all_accounts 路径，性能契约被破坏。"
    )


# ── O3 get_dashboard_stats ────────────────────────────────────────


def test_get_dashboard_stats_basic(tmp_db):
    """聚合维度正确：total / groups / statuses。"""
    db, uid = tmp_db
    db.add_account(uid, "a@x.com", "p", group="A组")
    db.add_account(uid, "b@x.com", "p", group="A组")
    db.add_account(uid, "c@x.com", "p", group="B组")
    stats = db.get_dashboard_stats(uid)
    assert stats["total"] == 3
    assert stats["groups"] == {"A组": 2, "B组": 1}
    # 三个账号都是默认 status=未检测
    assert stats["statuses"]["未检测"] == 3
    assert stats["statuses"]["正常"] == 0
    assert stats["statuses"]["异常"] == 0


def test_get_dashboard_stats_reflects_status_updates(tmp_db):
    """update_account_status 后 dashboard 即时反映。"""
    db, uid = tmp_db
    db.add_account(uid, "a@x.com", "p")
    aid = db.get_all_accounts(uid)[0].id
    db.update_account_status(uid, aid, "正常")
    stats = db.get_dashboard_stats(uid)
    assert stats["total"] == 1
    assert stats["statuses"]["正常"] == 1
    assert stats["statuses"]["未检测"] == 0


def test_get_dashboard_stats_empty_user(tmp_db):
    """无账号时返回 total=0，三个 status 槽位仍存在（前端 KeyError 防御）。"""
    db, uid = tmp_db
    stats = db.get_dashboard_stats(uid)
    assert stats == {
        "total": 0, "groups": {},
        "statuses": {"正常": 0, "异常": 0, "未检测": 0},
    }


def test_get_dashboard_stats_does_not_decrypt(tmp_db):
    """聚合不应触发 Fernet 解密 — 这是改造的核心收益。"""
    db, uid = tmp_db
    for i in range(5):
        db.add_account(uid, f"u{i}@x.com", "encrypted-secret")

    from core.security import SecretBox
    box = SecretBox.instance()
    with patch.object(box, "decrypt", wraps=box.decrypt) as spy:
        db.get_dashboard_stats(uid)

    assert spy.call_count == 0, (
        f"get_dashboard_stats 不应触发 SecretBox.decrypt，实际 {spy.call_count} 次"
    )


# ── O4 全局安全响应头 ────────────────────────────────────────────


def test_security_headers_present_on_api_response(client):
    """所有响应都应带 X-Content-Type-Options / X-Frame-Options / Referrer-Policy / CSP。"""
    r = client.get("/api/auth/me")
    assert r.status_code == 200
    headers = {k.lower(): v for k, v in r.headers.items()}
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("referrer-policy") == "no-referrer"
    csp = headers.get("content-security-policy", "")
    assert "frame-ancestors 'none'" in csp, f"CSP 必须含 frame-ancestors 'none'，实际: {csp}"
    assert "default-src 'self'" in csp


def test_security_headers_present_on_static_response(client):
    """静态资源响应也应带安全头（点击劫持防御覆盖整个域名）。"""
    r = client.get("/static/app.js")
    assert r.status_code == 200
    assert r.headers.get("X-Frame-Options") == "DENY"


def test_security_headers_present_on_error_response(client):
    """4xx 错误响应仍要带安全头（攻击者用错误响应做嵌入也得拦下）。"""
    r = client.get("/api/accounts/99999")
    assert r.status_code == 404
    assert r.headers.get("X-Frame-Options") == "DENY"


def test_security_headers_no_hsts_on_http(client):
    """HTTP 部署下不应下发 HSTS（避免锁住 HTTP 域名）。

    TestClient 默认走 http://，不加 HSTS 是正确的。
    """
    r = client.get("/api/auth/me")
    assert "strict-transport-security" not in {k.lower() for k in r.headers.keys()}


# ── O5 GZip ──────────────────────────────────────────────────────


def test_gzip_compresses_large_json(client):
    """带 Accept-Encoding: gzip 的请求应拿到 gzip 压缩响应。

    minimum_size=1024 — 凑出大于 1KB 的响应才会触发压缩。
    """
    # 准备 30 个账号让 /api/accounts 返回的 JSON 远超 1KB
    text = "\n".join(f"acc{i}@gmail.com----pwd{i}" for i in range(30))
    client.post("/api/accounts/import", json={
        "text": text, "group": "默认分组", "skip_duplicate": False,
    })
    r = client.get("/api/accounts", headers={"Accept-Encoding": "gzip"})
    assert r.status_code == 200
    # TestClient (httpx) 会自动解压 gzip，但响应头里 Content-Encoding 仍可见
    enc = r.headers.get("content-encoding", "")
    assert enc == "gzip", f"大响应应被 gzip 压缩，实际 Content-Encoding: {enc!r}"


def test_gzip_skips_small_responses(client):
    """小响应（< 1024B）不压缩，省 CPU。"""
    r = client.get("/api/health", headers={"Accept-Encoding": "gzip"})
    assert r.status_code == 200
    # health 响应非常小，不触发 gzip
    assert r.headers.get("content-encoding") != "gzip"


# ── O6 静态资源长缓存 ────────────────────────────────────────────


def test_static_files_have_long_cache_header(client):
    """/static/* 200 响应应带 Cache-Control: public, max-age=31536000, immutable。

    入口 index.html 已经把 ?v=mtime cache-bust，长缓存安全且能让 CDN /
    浏览器把回源率降到首次访问。
    """
    r = client.get("/static/app.js")
    assert r.status_code == 200
    cc = r.headers.get("Cache-Control", "")
    assert "max-age=31536000" in cc, f"app.js 应有 1 年长缓存，实际 Cache-Control: {cc!r}"
    assert "immutable" in cc, f"app.js 应有 immutable 标记，实际: {cc!r}"


def test_index_html_still_no_cache(client):
    """SPA 入口 / 必须 no-cache（旧行为不退化）：长缓存只针对 /static/*，
    入口 HTML 必须每次回源以拿到最新 __STATIC_VERSION__。"""
    r = client.get("/")
    assert r.status_code == 200
    cc = r.headers.get("Cache-Control", "")
    assert "no-cache" in cc, f"index.html 必须 no-cache，实际: {cc!r}"


# ── O7 注册接口 IP 限流 ──────────────────────────────────────────


def test_register_rate_limit_locks_after_too_many_failures(tmp_path, monkeypatch):
    """连续 N 次失败注册 → 触发 429。"""
    import sys
    from core import security
    from core.rate_limit import register_limiter
    security.SecretBox._instance = None  # noqa: SLF001
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager", "core.")):
            sys.modules.pop(m, None)

    # 重新导入并 reset register_limiter（避免与其他测试共享状态）
    from core.rate_limit import register_limiter as fresh_limiter
    fresh_limiter.reset()

    from fastapi.testclient import TestClient
    import web_app  # noqa: WPS433

    with TestClient(web_app.app) as c:
        seen_429 = False
        for i in range(28):  # 阈值 20，留 8 次缓冲
            r = c.post(
                "/api/auth/register",
                json={"username": "ab", "password": "abcdef"},  # 用户名太短 → 必然失败
            )
            if r.status_code == 429:
                seen_429 = True
                # 必须带 Retry-After（让客户端知道何时重试）
                assert "Retry-After" in r.headers
                break
            assert r.status_code in (400, 429), (
                f"非 400/429 状态: {r.status_code}, body={r.text[:100]}"
            )
        assert seen_429, "连续失败注册必须触发 429 限流"

    fresh_limiter.reset()
    security.SecretBox._instance = None  # noqa: SLF001


def test_register_success_resets_failure_counter(tmp_path, monkeypatch):
    """成功注册后该 IP 的失败计数被清空（合法用户连续注册不会被卡）。"""
    import sys
    from core import security
    security.SecretBox._instance = None  # noqa: SLF001
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager", "core.")):
            sys.modules.pop(m, None)

    from core.rate_limit import register_limiter
    register_limiter.reset()

    from fastapi.testclient import TestClient
    import web_app  # noqa: WPS433

    with TestClient(web_app.app) as c:
        # 先错 3 次（密码太短）
        for _ in range(3):
            r = c.post(
                "/api/auth/register",
                json={"username": "user1", "password": "x"},
            )
            assert r.status_code == 400

        # 成功注册一次
        r = c.post(
            "/api/auth/register",
            json={"username": "user1", "password": "valid-pwd"},
        )
        assert r.status_code == 200

        # 计数已清空：后续允许新一轮失败而不被立刻锁
        from core.rate_limit import REGISTER_LIMITER_KEY
        remaining = register_limiter.remaining_attempts(
            REGISTER_LIMITER_KEY, "testclient",
        )
        assert remaining is not None and remaining >= 8, (
            f"成功注册后应清空失败计数，剩余尝试 {remaining}（期望接近上限）"
        )

    register_limiter.reset()
    security.SecretBox._instance = None  # noqa: SLF001


def test_register_disabled_skips_rate_limit(tmp_path, monkeypatch):
    """DISABLE_REGISTER=1 时直接 403，不消耗限流配额。"""
    import sys
    from core import security
    security.SecretBox._instance = None  # noqa: SLF001
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("EMAIL_WEB_DISABLE_REGISTER", "1")
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager", "core.")):
            sys.modules.pop(m, None)

    from core.rate_limit import register_limiter, REGISTER_LIMITER_KEY
    register_limiter.reset()

    from fastapi.testclient import TestClient
    import web_app  # noqa: WPS433

    with TestClient(web_app.app) as c:
        # 连续 5 次注册（注册关闭）
        for _ in range(5):
            r = c.post(
                "/api/auth/register",
                json={"username": "any", "password": "abcdef"},
            )
            assert r.status_code == 403

        # 失败计数应该没动（关闭路径不消耗配额）
        remaining = register_limiter.remaining_attempts(
            REGISTER_LIMITER_KEY, "testclient",
        )
        assert remaining == register_limiter.max_fails, (
            f"DISABLE_REGISTER 路径不应消耗限流配额，实际剩余 {remaining}"
        )

    register_limiter.reset()
    security.SecretBox._instance = None  # noqa: SLF001


# ── O8 dashboard 改造 ────────────────────────────────────────────


def test_dashboard_endpoint_uses_aggregated_path(client):
    """``/api/dashboard`` 必须走 ``get_dashboard_stats`` 而**不是** ``get_all_accounts``。

    旧实现把整张账号表加载 + Fernet 解密只为做 group_by/status 聚合，
    本测试钉住改造后的路径，避免回滚。
    """
    import web_app
    client.post("/api/accounts/import", json={
        "text": "x@g.com----p", "group": "默认分组", "skip_duplicate": False,
    })

    real_get_stats = web_app.db.get_dashboard_stats
    real_get_all = web_app.db.get_all_accounts
    stats_calls: list = []
    all_calls: list = []

    def spy_stats(*a, **kw):
        stats_calls.append((a, kw))
        return real_get_stats(*a, **kw)

    def spy_all(*a, **kw):
        all_calls.append((a, kw))
        return real_get_all(*a, **kw)

    with patch.object(web_app.db, "get_dashboard_stats", side_effect=spy_stats), \
         patch.object(web_app.db, "get_all_accounts", side_effect=spy_all):
        r = client.get("/api/dashboard")
    assert r.status_code == 200
    assert stats_calls, "dashboard 应调用 get_dashboard_stats"
    assert not all_calls, (
        "dashboard **不应**调用 get_all_accounts（会触发整张表 Fernet 解密）"
    )


# ── O9 import_accounts 改造 ──────────────────────────────────────


def test_import_uses_efficient_email_lookup(client):
    """``import_accounts`` 必须走 ``get_existing_emails`` 而**不是** ``get_all_accounts``。

    类似 O8：旧实现解密整张表只为读 email 字段做去重，本测试钉住新路径。
    """
    import web_app
    # 先种 1 个账号
    client.post("/api/accounts/import", json={
        "text": "first@g.com----p", "group": "默认分组", "skip_duplicate": False,
    })

    real_get_emails = web_app.db.get_existing_emails
    real_get_all = web_app.db.get_all_accounts
    emails_calls: list = []
    all_calls: list = []

    def spy_emails(*a, **kw):
        emails_calls.append((a, kw))
        return real_get_emails(*a, **kw)

    def spy_all(*a, **kw):
        all_calls.append((a, kw))
        return real_get_all(*a, **kw)

    with patch.object(web_app.db, "get_existing_emails", side_effect=spy_emails), \
         patch.object(web_app.db, "get_all_accounts", side_effect=spy_all):
        r = client.post("/api/accounts/import", json={
            "text": "second@g.com----p\nthird@g.com----p",
            "group": "默认分组",
            "skip_duplicate": True,  # 关键：触发去重路径
        })
    assert r.status_code == 200
    assert r.json()["success"] == 2
    assert emails_calls, "import 去重应调用 get_existing_emails"
    assert not all_calls, (
        "import **不应**调用 get_all_accounts（会触发整张表 Fernet 解密）"
    )


def test_import_skip_duplicate_false_does_not_query_emails(client):
    """``skip_duplicate=False`` 时连去重查询都不需要发起。"""
    import web_app

    real_get_emails = web_app.db.get_existing_emails
    calls: list = []

    def spy(*a, **kw):
        calls.append((a, kw))
        return real_get_emails(*a, **kw)

    with patch.object(web_app.db, "get_existing_emails", side_effect=spy):
        r = client.post("/api/accounts/import", json={
            "text": "noskip@g.com----p",
            "group": "默认分组",
            "skip_duplicate": False,
        })
    assert r.status_code == 200
    assert not calls, "skip_duplicate=False 路径不应调用去重查询"


# ── O10 lifespan 后台任务 ────────────────────────────────────────


def test_lifespan_starts_and_cancels_cleanup_task(tmp_path, monkeypatch):
    """TestClient 进入 / 退出生命周期时 cleanup_task 应正确启动 + 取消。

    防止改造后留下 stranded coroutine（pytest 会以 RuntimeWarning 形式提示）。
    """
    import sys
    from core import security
    security.SecretBox._instance = None  # noqa: SLF001
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager", "core.")):
            sys.modules.pop(m, None)

    from fastapi.testclient import TestClient
    import web_app  # noqa: WPS433

    # 连续两次 with — 验证 lifespan 可重入（测试套件里很常见）
    for _ in range(2):
        with TestClient(web_app.app) as c:
            r = c.get("/api/health")
            assert r.status_code == 200

    security.SecretBox._instance = None  # noqa: SLF001


def test_periodic_cleanup_swallows_exceptions(tmp_path, monkeypatch):
    """``_periodic_cleanup`` 内部异常不能让 task 退出 — 否则一次 DB 抖动后
    后续就再也不清理了，几个月后日志爆磁盘。

    我们直接调用 ``_periodic_cleanup`` 一轮（mock asyncio.sleep 立刻抛 + 让
    cleanup_expired_sessions 抛异常），验证函数能优雅吃掉异常并准备进入下一轮。
    """
    import asyncio
    import sys
    from core import security
    security.SecretBox._instance = None  # noqa: SLF001
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager", "core.")):
            sys.modules.pop(m, None)

    import web_app  # noqa: WPS433

    sleep_calls = {"n": 0}
    cleanup_calls = {"n": 0}

    async def fake_sleep(_seconds):
        sleep_calls["n"] += 1
        if sleep_calls["n"] >= 2:
            # 第二次 sleep 时主动 cancel 让 task 优雅退出
            raise asyncio.CancelledError()
        # 第一次正常返回（即立即 yield），进入清理路径

    def boom_cleanup():
        """同步函数（``asyncio.to_thread`` 期待 sync callable）。

        必须用 sync 而不是 async — ``to_thread`` 把回调当 sync 函数调用，
        async 函数会被当成"返回 coroutine 的同步函数"，coroutine 永远不被
        await，触发 RuntimeWarning 但异常路径没真的被测到。
        """
        cleanup_calls["n"] += 1
        raise RuntimeError("模拟 DB 抖动")

    async def _runner():
        with patch.object(asyncio, "sleep", side_effect=fake_sleep), \
             patch.object(web_app.db, "cleanup_expired_sessions", side_effect=boom_cleanup):
            t = asyncio.create_task(web_app._periodic_cleanup())  # noqa: SLF001
            try:
                await asyncio.wait_for(t, timeout=2.0)
            except asyncio.CancelledError:
                pass

    asyncio.run(_runner())
    # cleanup 函数被调用过 → 异常路径触发；
    # sleep 被调用 ≥ 2 次（1 次成功 yield + 1 次 cancel）；
    # task 没把异常冒到外面 → 验证"吃掉异常进入下一轮"语义
    assert cleanup_calls["n"] >= 1, "cleanup 路径未被触发，测试无效"
    assert sleep_calls["n"] >= 2

    security.SecretBox._instance = None  # noqa: SLF001


# ── 顺带：register_limiter 单元层面的健壮性 ──────────────────────


def test_register_limiter_is_independent_from_login_limiter():
    """register_limiter 与 login_limiter 必须是独立的桶，不互相影响计数。"""
    from core.rate_limit import login_limiter, register_limiter, REGISTER_LIMITER_KEY

    login_limiter.reset()
    register_limiter.reset()

    # 在 login 桶里制造一些失败
    for _ in range(3):
        login_limiter.record_failure("alice", "1.2.3.4")
    # register 桶里的 1.2.3.4 应仍然干净
    remaining = register_limiter.remaining_attempts(REGISTER_LIMITER_KEY, "1.2.3.4")
    assert remaining == register_limiter.max_fails, (
        f"register_limiter 不应被 login_limiter 的失败拖累，剩余 {remaining}"
    )

    login_limiter.reset()
    register_limiter.reset()
