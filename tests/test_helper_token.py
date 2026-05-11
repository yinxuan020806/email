# -*- coding: utf-8 -*-
"""
``database.helper_token`` 单测覆盖：

- provision_token / validate_token 基本流程
- TTL 过期判定
- touch_token 刷新 last_used_at 与元信息
- revoke_token 与 revoke_all 按 owner_id 隔离
- list_tokens 按 owner_id 过滤
- purge_expired 物理清理
- 跨用户撤销隔离（owner A 不能撤 owner B 的 token）
"""
from __future__ import annotations

import time

import pytest

from database import helper_token as tk


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    """每个用例独立 helper.db；不污染真实 data/。"""
    db_path = tmp_path / "helper.db"
    tk.set_db_path(str(db_path))
    yield
    tk.set_db_path(None)


def test_provision_and_validate(fresh_db):
    token = tk.provision_token(owner_id=1, label="t1")
    assert len(token) == 64  # 32 字节 hex
    info = tk.validate_token(token)
    assert info is not None
    assert info["owner_id"] == 1
    assert info["label"] == "t1"
    assert info["revoked"] == 0


def test_provision_rejects_invalid_owner(fresh_db):
    with pytest.raises(ValueError):
        tk.provision_token(owner_id=0)
    with pytest.raises(ValueError):
        tk.provision_token(owner_id=-1)


def test_validate_unknown_returns_none(fresh_db):
    assert tk.validate_token("nonexistent") is None
    assert tk.validate_token("") is None
    # 太短的 token 直接拒（防 timing attack 加快路径）
    assert tk.validate_token("abc") is None


def test_validate_respects_ttl(fresh_db, monkeypatch):
    token = tk.provision_token(owner_id=42)
    # 把 last_used_at 改成"很久以前"
    base_now = int(time.time())
    monkeypatch.setattr(time, "time", lambda: base_now + 31 * 24 * 3600)
    assert tk.validate_token(token) is None  # 默认 30 天过期
    # ttl_seconds=0 表示"永不过期" — 验证短路
    assert tk.validate_token(token, ttl_seconds=0) is not None


def test_touch_updates_last_used_and_metadata(fresh_db):
    token = tk.provision_token(owner_id=1)
    info_before = tk.validate_token(token)
    assert info_before["platform"] is None

    time.sleep(1.05)  # 至少跨秒
    tk.touch_token(token, platform="win32", version="0.1.2")
    info_after = tk.validate_token(token)
    assert info_after["platform"] == "win32"
    assert info_after["version"] == "0.1.2"
    assert info_after["last_used_at"] >= info_before["last_used_at"]


def test_revoke_token_cross_owner_isolation(fresh_db):
    """owner B 不能用 revoke_token 撤掉 owner A 的 token。

    安全：撤销 token 必须按 owner_id 校验，避免任意用户构造请求撤掉别人的 helper。
    """
    token_a = tk.provision_token(owner_id=1, label="alice-laptop")
    # owner B 尝试撤掉 alice 的 token
    assert tk.revoke_token(token_a, owner_id=2) is False
    # alice 自己撤
    assert tk.revoke_token(token_a, owner_id=1) is True
    assert tk.validate_token(token_a) is None  # 撤销后 validate 返回 None


def test_revoke_token_without_owner_bypass(fresh_db):
    """不传 owner_id 是"管理员模式"，可以撤任何 token（仅测试场景使用）。"""
    token = tk.provision_token(owner_id=1)
    assert tk.revoke_token(token) is True
    assert tk.validate_token(token) is None


def test_revoke_all_per_owner(fresh_db):
    """revoke_all 必须按 owner_id 隔离。"""
    a1 = tk.provision_token(owner_id=1)
    a2 = tk.provision_token(owner_id=1)
    b1 = tk.provision_token(owner_id=2)

    n = tk.revoke_all(owner_id=1)
    assert n == 2
    # owner 1 的全失效
    assert tk.validate_token(a1) is None
    assert tk.validate_token(a2) is None
    # owner 2 的不受影响
    assert tk.validate_token(b1) is not None


def test_list_tokens_per_owner(fresh_db):
    a1 = tk.provision_token(owner_id=1, label="laptop")
    a2 = tk.provision_token(owner_id=1, label="desktop")
    b1 = tk.provision_token(owner_id=2)

    out = tk.list_tokens(owner_id=1)
    assert len(out) == 2
    assert {x["label"] for x in out} == {"laptop", "desktop"}

    out_b = tk.list_tokens(owner_id=2)
    assert len(out_b) == 1


def test_list_tokens_excludes_revoked_by_default(fresh_db):
    t = tk.provision_token(owner_id=1)
    tk.revoke_token(t, owner_id=1)
    assert tk.list_tokens(owner_id=1) == []
    # include_revoked=True 时仍能看到
    all_t = tk.list_tokens(owner_id=1, include_revoked=True)
    assert len(all_t) == 1
    assert all_t[0]["revoked"] == 1


def test_purge_expired_drops_old_and_revoked(fresh_db, monkeypatch):
    t_alive = tk.provision_token(owner_id=1)
    t_revoked = tk.provision_token(owner_id=1)
    tk.revoke_token(t_revoked, owner_id=1)

    # 把 t_alive 的 last_used_at 拉远到 1 年前
    base_now = int(time.time())
    monkeypatch.setattr(time, "time", lambda: base_now + 365 * 24 * 3600)

    n = tk.purge_expired()
    assert n >= 2  # revoked 和过期的都被物理清理
    monkeypatch.undo()
    # purge_expired 后 list 应该空
    assert tk.list_tokens(owner_id=1, include_revoked=True) == []


def test_concurrent_provision_unique_tokens(fresh_db):
    """大量 provision 应该全部唯一（secrets.token_hex 担保 + DB PK 强制）。

    数量不超过 ``MAX_TOKENS_PER_USER`` —— 上限本身另有专测覆盖。
    """
    n = min(25, tk.MAX_TOKENS_PER_USER)
    tokens = {tk.provision_token(owner_id=1) for _ in range(n)}
    assert len(tokens) == n


def test_provision_token_respects_max_limit(fresh_db):
    """超过 MAX_TOKENS_PER_USER 应抛 ValueError。"""
    for _ in range(tk.MAX_TOKENS_PER_USER):
        tk.provision_token(owner_id=1)
    with pytest.raises(ValueError, match="上限"):
        tk.provision_token(owner_id=1)
    # 撤销旧的腾出空间应该能继续 provision
    olds = tk.list_tokens(owner_id=1)
    tk.revoke_token(olds[0]["token"], owner_id=1)
    new_t = tk.provision_token(owner_id=1)
    assert new_t  # 撤销后能继续
