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

    # 手工塞一个已过期的条目
    key = _cache_key("cid", "rt-expired")
    _TOKEN_CACHE[key] = _CachedToken(
        access_token="at-stale",
        expires_at=time.time() - 100,  # 已过期
        refresh_token="rt-expired",
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
