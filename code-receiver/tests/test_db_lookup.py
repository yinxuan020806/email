# -*- coding: utf-8 -*-
"""DatabaseManager.get_public_account_for_lookup 的真实 DB 接入测试。

覆盖三种命中路径：
- ``allowed_categories='*'``                显式允许所有分类
- ``allowed_categories='cursor'``           显式包含
- ``allowed_categories=''`` + ``group_name='cursor'``  自动推断（与管理端实际数据一致）
- ``allowed_categories=''`` + ``group_name='默认分组'``  推断不出 → 拒绝（防误公开）
"""

from __future__ import annotations

import os
import sys

import pytest


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    """每个 test 用独立的临时 sqlite + master.key，避免 SecretBox 单例污染。"""
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))

    # SecretBox 是单例，跨测试要清掉，否则会拿到上一次的 key
    if "core.security" in sys.modules:
        sys.modules["core.security"].SecretBox._instance = None

    from database.db_manager import DatabaseManager

    db = DatabaseManager(db_path=str(tmp_path / "emails.db"))
    yield db

    # 清理单例避免污染下一个测试
    if "core.security" in sys.modules:
        sys.modules["core.security"].SecretBox._instance = None


def _create_owner_with_account(
    db, username: str, email: str, group: str = "默认分组",
) -> tuple[int, int]:
    user_id = db.create_user(username, "fake-pbkdf2-hash")
    assert user_id is not None
    ok, _ = db.add_account(
        owner_id=user_id,
        email=email,
        password="fake-password",
        group=group,
    )
    assert ok is True
    acc = db.get_account_by_email(user_id, email)
    assert acc is not None
    return user_id, acc.id


def test_lookup_blocked_when_not_public(fresh_db):
    """is_public=0 默认情况下，不论分类都拒绝。"""
    db = fresh_db
    _create_owner_with_account(db, "xiaoxuan", "a@outlook.com", group="cursor")
    assert db.get_public_account_for_lookup("xiaoxuan", "a@outlook.com", "cursor") is None
    assert db.get_public_account_for_lookup("xiaoxuan", "a@outlook.com", "openai") is None


def test_lookup_via_group_name_cursor(fresh_db):
    """group_name='cursor' + is_public=1 + allowed_categories 留空
    → cursor 命中、openai 不命中。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "a@outlook.com", group="cursor")
    assert db.set_account_public(uid, acc_id, is_public=True, allowed_categories=None) is True

    assert db.get_public_account_for_lookup("xiaoxuan", "a@outlook.com", "cursor") is not None
    assert db.get_public_account_for_lookup("xiaoxuan", "a@outlook.com", "openai") is None


def test_lookup_via_group_name_cursor_plus_gpt(fresh_db):
    """group_name='cursor+gpt' + is_public=1 → cursor / openai 都命中。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(
        db, "xiaoxuan", "b@outlook.com", group="cursor+gpt",
    )
    db.set_account_public(uid, acc_id, is_public=True, allowed_categories=None)

    assert db.get_public_account_for_lookup("xiaoxuan", "b@outlook.com", "cursor") is not None
    assert db.get_public_account_for_lookup("xiaoxuan", "b@outlook.com", "openai") is not None


def test_lookup_default_group_blocks_when_no_explicit(fresh_db):
    """group='默认分组' + is_public=1 + 没显式 allowed_categories
    → 全部拒绝（防止默认分组被误公开）。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "c@outlook.com")
    db.set_account_public(uid, acc_id, is_public=True, allowed_categories=None)

    assert db.get_public_account_for_lookup("xiaoxuan", "c@outlook.com", "cursor") is None
    assert db.get_public_account_for_lookup("xiaoxuan", "c@outlook.com", "openai") is None


def test_lookup_allowed_categories_explicit_overrides(fresh_db):
    """显式 allowed_categories='cursor' → 仅 cursor 命中，即使 group_name 不含 cursor。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "d@outlook.com")
    db.set_account_public(uid, acc_id, is_public=True, allowed_categories=["cursor"])

    assert db.get_public_account_for_lookup("xiaoxuan", "d@outlook.com", "cursor") is not None
    assert db.get_public_account_for_lookup("xiaoxuan", "d@outlook.com", "openai") is None


def test_lookup_wildcard_allows_all(fresh_db):
    """allowed_categories='*' → 任何分类都命中。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "e@outlook.com")
    # 直接在 SQL 里写 *（set_account_public 会过滤非法分类，所以这里直接 UPDATE）
    with db._connect() as conn:
        conn.execute(
            "UPDATE accounts SET is_public = 1, allowed_categories = '*' WHERE id = ?",
            (acc_id,),
        )

    assert db.get_public_account_for_lookup("xiaoxuan", "e@outlook.com", "cursor") is not None
    assert db.get_public_account_for_lookup("xiaoxuan", "e@outlook.com", "openai") is not None


def test_lookup_wrong_owner_blocked(fresh_db):
    """同样的邮箱属于另一个用户 → 不会被错误暴露给 xiaoxuan 路径。"""
    db = fresh_db
    _create_owner_with_account(db, "alice", "shared@outlook.com", group="cursor")
    # 注意：xiaoxuan 没有这个邮箱
    assert db.get_public_account_for_lookup("xiaoxuan", "shared@outlook.com", "cursor") is None


def test_lookup_case_in_group_name(fresh_db):
    """group_name='Cursor' 大小写也能命中（lower() 处理）。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "f@outlook.com", group="Cursor")
    db.set_account_public(uid, acc_id, is_public=True, allowed_categories=None)
    assert db.get_public_account_for_lookup("xiaoxuan", "f@outlook.com", "cursor") is not None
