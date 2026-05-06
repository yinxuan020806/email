# -*- coding: utf-8 -*-
"""TokenManager 进程级缓存：避免每次请求都跨海刷 access_token。"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _clear_cache():
    from core.oauth_token import clear_token_cache
    clear_token_cache()
    yield
    clear_token_cache()


def _mock_token_response(access_token="at-1", expires_in=3600,
                        scope="https://outlook.office.com/IMAP.AccessAsUser.All",
                        refresh_token="rt-original"):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "access_token": access_token,
        "expires_in": expires_in,
        "scope": scope,
        "refresh_token": refresh_token,
    }
    return resp


def test_first_call_hits_network(monkeypatch):
    from core.oauth_token import TokenManager

    call_count = {"n": 0}

    def fake_post(url, **kwargs):
        call_count["n"] += 1
        return _mock_token_response()

    with patch("core.oauth_token.SESSION.post", side_effect=fake_post):
        tm = TokenManager(client_id="cid", refresh_token="rt-original")
        token, msg = tm.get()
    assert token == "at-1"
    assert call_count["n"] == 1


def test_second_instance_with_same_creds_reuses_cache(monkeypatch):
    """关键测试：每次 web 请求创建新 TokenManager 时，必须复用进程级缓存。"""
    from core.oauth_token import TokenManager

    call_count = {"n": 0}

    def fake_post(url, **kwargs):
        call_count["n"] += 1
        return _mock_token_response()

    with patch("core.oauth_token.SESSION.post", side_effect=fake_post):
        # 第一个实例 → 触发 refresh
        tm1 = TokenManager(client_id="cid", refresh_token="rt-original")
        token1, _ = tm1.get()
        assert call_count["n"] == 1
        # 第二个实例（模拟新 web 请求）→ 应直接命中缓存，不再发请求
        tm2 = TokenManager(client_id="cid", refresh_token="rt-original")
        token2, msg2 = tm2.get()
        assert token2 == token1
        assert call_count["n"] == 1, "第二次创建相同凭据的 TokenManager 仍触发了网络请求"
        assert "缓存" in msg2


def test_cache_warm_at_construction(monkeypatch):
    """新 TokenManager 实例化时应自动从缓存加载（无需调用 get）。"""
    from core.oauth_token import TokenManager

    with patch("core.oauth_token.SESSION.post", return_value=_mock_token_response()):
        tm1 = TokenManager(client_id="cid", refresh_token="rt-x")
        tm1.get()
        # 第二个实例：构造时直接从缓存取，scopes/api_type 应已就绪
        tm2 = TokenManager(client_id="cid", refresh_token="rt-x")
    assert tm2._access_token == "at-1"
    assert tm2.scopes  # 非空
    assert tm2.has_scope("IMAP")


def test_different_refresh_token_does_not_share_cache(monkeypatch):
    """两个不同账号的凭据不能互相串扰。"""
    from core.oauth_token import TokenManager

    counter = {"n": 0}
    def fake_post(url, **kwargs):
        counter["n"] += 1
        rt = kwargs["data"]["refresh_token"]
        return _mock_token_response(access_token=f"at-for-{rt}", refresh_token=rt)

    with patch("core.oauth_token.SESSION.post", side_effect=fake_post):
        tm_a = TokenManager(client_id="cid", refresh_token="rt-A")
        tm_b = TokenManager(client_id="cid", refresh_token="rt-B")
        tok_a, _ = tm_a.get()
        tok_b, _ = tm_b.get()
    assert tok_a != tok_b
    assert counter["n"] == 2  # 每个独立账号都要单独刷


def test_expired_cache_entry_triggers_refresh(monkeypatch):
    from core.oauth_token import TokenManager, _TOKEN_CACHE, _CachedToken, _cache_key

    call_count = {"n": 0}
    def fake_post(url, **kwargs):
        call_count["n"] += 1
        return _mock_token_response(access_token="at-fresh")

    # 手工塞一个已过期的条目（_CachedToken 不再持有 refresh_token，移除该 kwarg）
    key = _cache_key("cid", "rt-expired")
    _TOKEN_CACHE[key] = _CachedToken(
        access_token="at-stale",
        expires_at=time.time() - 100,  # 已过期
    )

    with patch("core.oauth_token.SESSION.post", side_effect=fake_post):
        tm = TokenManager(client_id="cid", refresh_token="rt-expired")
        token, _ = tm.get()
    assert token == "at-fresh"
    assert call_count["n"] == 1


def test_clear_token_cache_resets():
    from core.oauth_token import TokenManager, clear_token_cache

    with patch("core.oauth_token.SESSION.post", return_value=_mock_token_response()):
        TokenManager(client_id="cid", refresh_token="rt-clear").get()
        cleared = clear_token_cache()
    assert cleared == 1


# ── 实例级 access_token 必须能被 get() 复用（修 baseline 失败的根因）──


def test_get_uses_instance_level_access_token(monkeypatch):
    """显式赋值 ``_access_token`` / ``_expires_at`` 后再次 get() 不能去刷网络。

    这是 baseline 失败的根本原因：``test_oauth_writes_route_to_graph_when_readwrite_scope_present``
    曾通过 mock 实例字段验证 ``_can_use_graph_for_writes`` 行为，但 perf commit 改了
    ``get()`` 让它只看进程级缓存，结果 mock 失效；现在补回实例级路径后，测试链
    被恢复。
    """
    from core.oauth_token import TokenManager

    call_count = {"n": 0}

    def fake_post(*a, **kw):
        call_count["n"] += 1
        return _mock_token_response()

    with patch("core.oauth_token.SESSION.post", side_effect=fake_post):
        tm = TokenManager(client_id="cid", refresh_token="rt-instance")
        # 直接给实例字段赋值（模拟测试 fixture 或运维注入）
        tm._access_token = "fake-instance-token"  # noqa: SLF001
        tm._expires_at = time.time() + 9999  # noqa: SLF001
        token, msg = tm.get()
    assert token == "fake-instance-token", "实例级 access_token 应优先生效"
    assert "实例级" in msg
    assert call_count["n"] == 0, "命中实例级缓存时不能打 token endpoint"


def test_clear_token_cache_also_clears_refresh_locks(monkeypatch):
    """``clear_token_cache`` 必须同时清掉 ``_REFRESH_LOCKS``，避免长期内存膨胀。"""
    from core.oauth_token import (
        TokenManager, clear_token_cache, _REFRESH_LOCKS,
    )

    with patch("core.oauth_token.SESSION.post", return_value=_mock_token_response()):
        TokenManager(client_id="cid", refresh_token="rt-A").get()
        TokenManager(client_id="cid", refresh_token="rt-B").get()

    # 触发后应该有 2 把 lock（每个 unique RT 一个）
    assert len(_REFRESH_LOCKS) >= 2
    clear_token_cache()
    assert len(_REFRESH_LOCKS) == 0, "clear_token_cache 必须把 _REFRESH_LOCKS 也清空"


def test_evict_expired_token_cache():
    """``evict_expired_token_cache`` 只清过期项，未过期的留下。"""
    from core.oauth_token import (
        _TOKEN_CACHE, _REFRESH_LOCKS, _CachedToken, _cache_key,
        evict_expired_token_cache,
    )

    # 手动塞两条：一过期、一未过期（_CachedToken 不再持有 refresh_token）
    fresh_key = _cache_key("cid", "rt-fresh")
    stale_key = _cache_key("cid", "rt-stale")
    _TOKEN_CACHE[fresh_key] = _CachedToken(
        access_token="fresh", expires_at=time.time() + 9999,
    )
    _TOKEN_CACHE[stale_key] = _CachedToken(
        access_token="stale", expires_at=time.time() - 1,
    )
    # 顺便给 stale 一个对应的 lock
    import threading
    _REFRESH_LOCKS[stale_key] = threading.Lock()

    n = evict_expired_token_cache()
    assert n == 1
    assert fresh_key in _TOKEN_CACHE
    assert stale_key not in _TOKEN_CACHE
    assert stale_key not in _REFRESH_LOCKS


def test_concurrent_refresh_singleflight(monkeypatch):
    """同一 (client_id, RT) 下 N 个并发 cache miss 只放一个去打 token endpoint。"""
    import threading
    from core.oauth_token import TokenManager

    call_count = {"n": 0}
    enter_event = threading.Event()
    can_release = threading.Event()

    def slow_post(*a, **kw):
        call_count["n"] += 1
        # 第一次进来后立刻 set，让其它线程都进入 _refresh，让单飞锁能 dedup
        enter_event.set()
        # 阻塞一下让其它线程都已经 await refresh lock
        can_release.wait(timeout=2)
        return _mock_token_response(access_token="at-shared")

    with patch("core.oauth_token.SESSION.post", side_effect=slow_post):
        threads = []
        results = []

        def worker():
            tm = TokenManager(client_id="cid", refresh_token="rt-concurrent")
            tok, msg = tm.get()
            results.append((tok, msg))

        for _ in range(8):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        # 等第一个线程进入 fake_post（说明它已经持有 refresh lock 了）
        assert enter_event.wait(timeout=2), "第一个 fake_post 应该被触发"
        # 让 fake_post 返回，其它线程将命中 double-check 缓存
        can_release.set()

        for t in threads:
            t.join(timeout=5)

    assert all(r[0] == "at-shared" for r in results), "所有线程应拿到同一个 token"
    assert call_count["n"] == 1, (
        f"singleflight 失败：8 个并发线程发起了 {call_count['n']} 次 token 刷新"
    )
