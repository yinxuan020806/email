# -*- coding: utf-8 -*-
"""LoginRateLimiter 单元 + 端点集成测试。"""

from __future__ import annotations

import time

import pytest

from core.rate_limit import LoginRateLimiter


def test_allows_under_threshold():
    rl = LoginRateLimiter(max_fails=3, window=60, lock_duration=60)
    for _ in range(2):
        locked, _ = rl.record_failure("u", "1.1.1.1")
        assert not locked
    allowed, _ = rl.check("u", "1.1.1.1")
    assert allowed


def test_locks_at_threshold():
    rl = LoginRateLimiter(max_fails=3, window=60, lock_duration=60)
    locked = False
    for _ in range(3):
        locked, _ = rl.record_failure("u", "1.1.1.1")
    assert locked
    allowed, retry = rl.check("u", "1.1.1.1")
    assert not allowed
    assert retry > 0


def test_lock_expires():
    rl = LoginRateLimiter(max_fails=2, window=60, lock_duration=1)
    rl.record_failure("u", "1.1.1.1")
    rl.record_failure("u", "1.1.1.1")
    assert not rl.check("u", "1.1.1.1")[0]
    time.sleep(1.2)
    assert rl.check("u", "1.1.1.1")[0]


def test_success_clears_counter():
    rl = LoginRateLimiter(max_fails=3, window=60, lock_duration=60)
    rl.record_failure("u", "1.1.1.1")
    rl.record_failure("u", "1.1.1.1")
    rl.record_success("u", "1.1.1.1")
    assert rl.remaining_attempts("u", "1.1.1.1") == 3


def test_per_ip_isolation():
    rl = LoginRateLimiter(max_fails=2, window=60, lock_duration=60)
    rl.record_failure("u", "1.1.1.1")
    rl.record_failure("u", "1.1.1.1")
    assert not rl.check("u", "1.1.1.1")[0]
    # 同一用户名换 IP 不受影响
    assert rl.check("u", "2.2.2.2")[0]


def test_per_username_isolation():
    rl = LoginRateLimiter(max_fails=2, window=60, lock_duration=60)
    rl.record_failure("alice", "1.1.1.1")
    rl.record_failure("alice", "1.1.1.1")
    assert not rl.check("alice", "1.1.1.1")[0]
    # 同一 IP 换用户名不受影响
    assert rl.check("bob", "1.1.1.1")[0]


def test_remaining_attempts_decreases():
    rl = LoginRateLimiter(max_fails=5, window=60, lock_duration=60)
    assert rl.remaining_attempts("u", "1.1.1.1") == 5
    rl.record_failure("u", "1.1.1.1")
    assert rl.remaining_attempts("u", "1.1.1.1") == 4
    rl.record_failure("u", "1.1.1.1")
    assert rl.remaining_attempts("u", "1.1.1.1") == 3


def test_reset_clears_all():
    rl = LoginRateLimiter(max_fails=2, window=60, lock_duration=60)
    rl.record_failure("u", "1.1.1.1")
    rl.record_failure("u", "1.1.1.1")
    rl.reset()
    assert rl.check("u", "1.1.1.1")[0]


def test_lazy_gc_evicts_dead_entries():
    """超过 GC_INTERVAL 后调用 check，"既未锁定也无有效失败计数"的死 entry 应被清。

    这里用短的 window=1s + GC_INTERVAL=0.05s 让测试快。
    """
    rl = LoginRateLimiter(max_fails=10, window=1, lock_duration=60)
    rl.GC_INTERVAL = 0.05
    rl.record_failure("u", "1.1.1.1")
    assert rl.size() == 1

    # 等待时长超过 window，entry 变"有 fails 但都在窗外"的状态
    time.sleep(1.2)
    # check 一个不同 key，触发 GC，旧的 ('u', '1.1.1.1') 被清
    rl.check("v", "9.9.9.9")
    # 刚访问过的 ('v', '9.9.9.9') 也不会被创建（只读不写）
    assert rl.size() == 0, f"GC 后应为空，实际 size={rl.size()}"


def test_size_reflects_tracked_entries():
    rl = LoginRateLimiter(max_fails=3, window=60, lock_duration=60)
    assert rl.size() == 0
    rl.record_failure("u1", "1.1.1.1")
    rl.record_failure("u2", "2.2.2.2")
    assert rl.size() == 2


# ── 端点集成测试 ────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_limiter():
    """每个测试前清空全局限流器，避免相互污染。"""
    from core.rate_limit import login_limiter
    login_limiter.reset()
    yield
    login_limiter.reset()


def test_login_endpoint_locks_after_n_failures(client, monkeypatch):
    """登录端点失败 max_fails 次后即触发锁（429）。"""
    from core.rate_limit import login_limiter
    monkeypatch.setattr(login_limiter, "max_fails", 3)

    client.post("/api/auth/logout")
    # 前 max_fails-1 次都是 401（仍可继续尝试）
    for _ in range(2):
        r = client.post("/api/auth/login", json={"username": "alice", "password": "bad"})
        assert r.status_code == 401
    # 第 max_fails 次触发锁定
    r = client.post("/api/auth/login", json={"username": "alice", "password": "bad"})
    assert r.status_code == 429
    # 即使密码正确也应被锁
    r = client.post("/api/auth/login", json={"username": "alice", "password": "pwd-alice"})
    assert r.status_code == 429


def test_successful_login_resets_counter(client, monkeypatch):
    from core.rate_limit import login_limiter
    monkeypatch.setattr(login_limiter, "max_fails", 3)

    client.post("/api/auth/logout")
    # 失败 2 次
    for _ in range(2):
        client.post("/api/auth/login", json={"username": "alice", "password": "bad"})
    # 成功一次
    r = client.post("/api/auth/login", json={"username": "alice", "password": "pwd-alice"})
    assert r.status_code == 200
    # 退出后再失败应该计数已清零
    client.post("/api/auth/logout")
    for _ in range(2):
        r = client.post("/api/auth/login", json={"username": "alice", "password": "bad"})
        assert r.status_code == 401
