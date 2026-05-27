# -*- coding: utf-8 -*-
"""DatabaseManager.get_public_account_for_lookup 的真实 DB 接入测试。

覆盖三种命中路径：
- ``allowed_categories='*'``                显式允许所有分类
- ``allowed_categories='cursor'``           显式包含
- ``allowed_categories=''`` + ``group_name='cursor'``  自动推断（与管理端实际数据一致）
- ``allowed_categories=''`` + ``group_name='默认分组'``  推断不出 → 拒绝（防误公开）

v9 起 ``get_public_account_for_lookup`` 必须带分类独立的 ``access_token`` 参数；
Cursor 凭证以 C 开头，GPT/OpenAI 凭证以 G 开头。
"""

from __future__ import annotations

import sys

import pytest


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    """每个 test 用独立的临时 sqlite + master.key，避免 SecretBox 单例污染。"""
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))

    if "core.security" in sys.modules:
        sys.modules["core.security"].SecretBox._instance = None

    from database.db_manager import DatabaseManager

    db = DatabaseManager(db_path=str(tmp_path / "emails.db"))
    yield db

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


def _make_public_tokens(db, uid: int, acc_id: int, cats=None) -> dict[str, str]:
    """加入接码白名单并返回自动生成的分类凭证明文。"""
    ok, tokens = db.set_account_public(
        uid, acc_id, is_public=True, allowed_categories=cats,
    )
    assert ok is True
    return tokens


def _make_public(db, uid: int, acc_id: int, cats=None, category: str = "cursor") -> str:
    tokens = _make_public_tokens(db, uid, acc_id, cats=cats)
    token = tokens.get(category)
    assert token, f"首次 is_public=True 必须自动生成 {category} 凭证"
    assert len(token) == 6
    assert token[0] == ("C" if category == "cursor" else "G")
    return token


def _add_account_under(db, uid: int, email: str, group: str = "默认分组") -> int:
    """给已存在的 owner 加一个账号，返回 account_id。"""
    ok, _ = db.add_account(
        owner_id=uid, email=email, password="fake-password", group=group,
    )
    assert ok is True
    acc = db.get_account_by_email(uid, email)
    assert acc is not None
    return acc.id


def test_lookup_blocked_when_not_public(fresh_db):
    """is_public=0 默认情况下，不论分类都拒绝（无 token 也直接拒绝）。"""
    db = fresh_db
    _create_owner_with_account(db, "xiaoxuan", "a@outlook.com", group="cursor")
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "a@outlook.com", "cursor", access_token="XXXXXX",
    ) is None
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "a@outlook.com", "openai", access_token="XXXXXX",
    ) is None


def test_lookup_via_group_name_cursor(fresh_db):
    """group_name='cursor' + is_public=1 + allowed_categories 留空
    → cursor 命中、openai 不命中（且必须带正确 token）。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "a@outlook.com", group="cursor")
    token = _make_public(db, uid, acc_id)

    assert db.get_public_account_for_lookup(
        "xiaoxuan", "a@outlook.com", "cursor", access_token=token,
    ) is not None
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "a@outlook.com", "openai", access_token=token,
    ) is None


def test_lookup_can_skip_access_token_when_owner_disables_credentials(fresh_db):
    """全局关闭凭证时，只跳过 token，比 owner / public / category 更外层的限制不变。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "no-token@outlook.com", group="cursor")
    _make_public(db, uid, acc_id)

    assert db.get_public_account_for_lookup(
        "xiaoxuan",
        "no-token@outlook.com",
        "cursor",
        require_access_token=False,
    ) is not None
    assert db.get_public_account_for_lookup(
        "xiaoxuan",
        "no-token@outlook.com",
        "openai",
        require_access_token=False,
    ) is None
    assert db.get_public_account_for_lookup(
        "other-owner",
        "no-token@outlook.com",
        "cursor",
        require_access_token=False,
    ) is None


def test_lookup_via_group_name_cursor_plus_gpt(fresh_db):
    """group_name='cursor+gpt' + is_public=1 → cursor / openai 都命中。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(
        db, "xiaoxuan", "b@outlook.com", group="cursor+gpt",
    )
    tokens = _make_public_tokens(db, uid, acc_id)
    cursor_token = tokens["cursor"]
    openai_token = tokens["openai"]

    assert db.get_public_account_for_lookup(
        "xiaoxuan", "b@outlook.com", "cursor", access_token=cursor_token,
    ) is not None
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "b@outlook.com", "openai", access_token=openai_token,
    ) is not None
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "b@outlook.com", "cursor", access_token=openai_token,
    ) is None


def test_lookup_default_group_blocks_when_no_explicit(fresh_db):
    """group='默认分组' + is_public=1 + 没显式 allowed_categories
    → 全部拒绝（防止默认分组被误公开）。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "c@outlook.com")
    tokens = _make_public_tokens(db, uid, acc_id)
    assert tokens == {}

    assert db.get_public_account_for_lookup(
        "xiaoxuan", "c@outlook.com", "cursor", access_token="CXXXXX",
    ) is None
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "c@outlook.com", "openai", access_token="GXXXXX",
    ) is None


def test_lookup_allowed_categories_explicit_overrides(fresh_db):
    """显式 allowed_categories='cursor' → 仅 cursor 命中，即使 group_name 不含 cursor。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "d@outlook.com")
    token = _make_public(db, uid, acc_id, cats=["cursor"])

    assert db.get_public_account_for_lookup(
        "xiaoxuan", "d@outlook.com", "cursor", access_token=token,
    ) is not None
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "d@outlook.com", "openai", access_token=token,
    ) is None


def test_lookup_allowed_categories_openai_only(fresh_db):
    """显式 allowed_categories='openai' → 仅 GPT/OpenAI 命中，凭证以 G 开头。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "gpt@outlook.com")
    token = _make_public(db, uid, acc_id, cats=["openai"], category="openai")

    assert db.get_public_account_for_lookup(
        "xiaoxuan", "gpt@outlook.com", "openai", access_token=token,
    ) is not None
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "gpt@outlook.com", "cursor", access_token=token,
    ) is None


def test_lookup_wildcard_allows_all(fresh_db):
    """allowed_categories='*' → 任何分类都命中。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "e@outlook.com")
    tokens = _make_public_tokens(db, uid, acc_id, cats=["*"])

    assert db.get_public_account_for_lookup(
        "xiaoxuan", "e@outlook.com", "cursor", access_token=tokens["cursor"],
    ) is not None
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "e@outlook.com", "openai", access_token=tokens["openai"],
    ) is not None


def test_lookup_wrong_owner_blocked(fresh_db):
    """同样的邮箱属于另一个用户 → 不会被错误暴露给 xiaoxuan 路径。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "alice", "shared@outlook.com", group="cursor")
    token = _make_public(db, uid, acc_id)
    # xiaoxuan 没有这个邮箱，无论传任何 token 都拿不到
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "shared@outlook.com", "cursor", access_token=token,
    ) is None


def test_lookup_case_in_group_name(fresh_db):
    """group_name='Cursor' 大小写也能命中（lower() 处理）。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "f@outlook.com", group="Cursor")
    token = _make_public(db, uid, acc_id)
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "f@outlook.com", "cursor", access_token=token,
    ) is not None


# ── v8: access_token 校验路径 ───────────────────────────────────────


def test_lookup_requires_access_token(fresh_db):
    """v8 起：未传 access_token / 传空串 一律拒绝（撤底关闭"只邮箱"路径）。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "g@outlook.com", group="cursor")
    _make_public(db, uid, acc_id)
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "g@outlook.com", "cursor", access_token=None,
    ) is None
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "g@outlook.com", "cursor", access_token="",
    ) is None


def test_lookup_wrong_token_rejected(fresh_db):
    """token 错一位也拒绝（hmac.compare_digest 严格匹配）。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "h@outlook.com", group="cursor")
    token = _make_public(db, uid, acc_id)
    # 错一位
    bad = ("X" if token[0] != "X" else "Y") + token[1:]
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "h@outlook.com", "cursor", access_token=bad,
    ) is None


def test_rotate_token_invalidates_old(fresh_db):
    """旋转后老 token 立即失效；新 token 可用。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "i@outlook.com", group="cursor")
    old_token = _make_public(db, uid, acc_id)

    new_tokens = db.rotate_access_token(uid, acc_id)
    assert new_tokens is not None
    new_token = new_tokens["cursor"]
    assert new_token != old_token
    assert len(new_token) == 6
    assert new_token.startswith("C")

    assert db.get_public_account_for_lookup(
        "xiaoxuan", "i@outlook.com", "cursor", access_token=old_token,
    ) is None
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "i@outlook.com", "cursor", access_token=new_token,
    ) is not None


def test_set_public_does_not_overwrite_existing_token(fresh_db):
    """已有 token 的账号被再次 set_account_public(True) 时，token 不变。"""
    db = fresh_db
    uid, acc_id = _create_owner_with_account(db, "xiaoxuan", "j@outlook.com", group="cursor")
    token1 = _make_public(db, uid, acc_id)
    # 第二次再加入 — 不应生成新 token
    ok, token2 = db.set_account_public(uid, acc_id, is_public=True, allowed_categories=None)
    assert ok is True
    assert token2 == {}  # 没有"新"凭证生成
    assert db.get_public_account_for_lookup(
        "xiaoxuan", "j@outlook.com", "cursor", access_token=token1,
    ) is not None


def test_bulk_rotate_only_public(fresh_db):
    """rotate_access_tokens_bulk(only_public=True) 仅旋转已 is_public=1 账号。"""
    db = fresh_db
    uid, pub_id = _create_owner_with_account(db, "xiaoxuan", "p@outlook.com", group="cursor")
    priv_id = _add_account_under(db, uid, "p_private@outlook.com", group="cursor")
    _make_public(db, uid, pub_id)
    # 同 owner 下另一个未加入接码的账号不应被纳入
    tokens = db.rotate_access_tokens_bulk(uid, account_ids=None, only_public=True)
    assert pub_id in tokens
    assert priv_id not in tokens
    assert len(tokens) == 1


def test_bulk_rotate_ids_filter(fresh_db):
    """传 ids 时仅旋转指定的、属于当前 owner 的账号。"""
    db = fresh_db
    uid, id1 = _create_owner_with_account(db, "xiaoxuan", "x1@outlook.com", group="cursor")
    id2 = _add_account_under(db, uid, "x2@outlook.com", group="cursor")
    _make_public(db, uid, id1)
    _make_public(db, uid, id2)
    tokens = db.rotate_access_tokens_bulk(uid, account_ids=[id1])
    assert set(tokens.keys()) == {id1}


def test_bulk_rotate_cross_owner_isolation(fresh_db):
    """跨 owner 的 ids 必须被 SQL 自动隔离掉。"""
    db = fresh_db
    uid1, id1 = _create_owner_with_account(db, "xiaoxuan", "z1@outlook.com", group="cursor")
    uid2, id2 = _create_owner_with_account(db, "alice", "z2@outlook.com", group="cursor")
    _make_public(db, uid1, id1)
    _make_public(db, uid2, id2)
    # 用 xiaoxuan 的 owner_id 但把 alice 的 id2 混进来
    tokens = db.rotate_access_tokens_bulk(uid1, account_ids=[id1, id2])
    assert id1 in tokens
    assert id2 not in tokens
