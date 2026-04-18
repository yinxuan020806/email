# -*- coding: utf-8 -*-
"""DatabaseManager CRUD 测试（多用户隔离版）。"""

from __future__ import annotations

import pytest

from core.auth import hash_password


def test_add_and_fetch_account(tmp_db):
    db, uid = tmp_db
    ok, _ = db.add_account(uid, "a@gmail.com", "secret123")
    assert ok
    accs = db.get_all_accounts(uid)
    assert len(accs) == 1
    assert accs[0].email == "a@gmail.com"
    assert accs[0].password == "secret123"


def test_password_is_encrypted_on_disk(tmp_db):
    import sqlite3
    db, uid = tmp_db
    db.add_account(uid, "b@gmail.com", "myplain")
    raw = sqlite3.connect(db.db_path).execute(
        "SELECT password FROM accounts WHERE email='b@gmail.com'"
    ).fetchone()[0]
    assert "myplain" not in raw
    assert raw.startswith("enc::v1::")


def test_duplicate_email_rejected_within_user(tmp_db):
    db, uid = tmp_db
    db.add_account(uid, "dup@gmail.com", "p")
    ok, msg = db.add_account(uid, "dup@gmail.com", "p2")
    assert not ok
    assert "已存在" in msg


def test_same_email_allowed_for_different_users(tmp_db):
    """同一邮箱在不同用户名下应可独立存在。"""
    db, uid = tmp_db
    other = db.create_user("other", hash_password("pwdother"))
    assert db.add_account(uid, "shared@g.com", "p1")[0]
    assert db.add_account(other, "shared@g.com", "p2")[0]


def test_import_creates_group_automatically(tmp_db):
    db, uid = tmp_db
    db.add_account(uid, "c@gmail.com", "p", group="新分组X")
    groups = [g[1] for g in db.get_all_groups(uid)]
    assert "新分组X" in groups


def test_delete_account_returns_rowcount(tmp_db):
    db, uid = tmp_db
    db.add_account(uid, "d@gmail.com", "p")
    aid = db.get_all_accounts(uid)[0].id
    assert db.delete_account(uid, aid) is True
    assert db.delete_account(uid, aid) is False


def test_delete_accounts_batch(tmp_db):
    db, uid = tmp_db
    for e in ("x@g.com", "y@g.com", "z@g.com"):
        db.add_account(uid, e, "p")
    ids = [a.id for a in db.get_all_accounts(uid)]
    assert db.delete_accounts(uid, ids + [99999]) == len(ids)


def test_update_nonexistent_returns_false(tmp_db):
    db, uid = tmp_db
    assert db.update_account_group(uid, 99999, "X") is False
    assert db.update_account_remark(uid, 99999, "r") is False
    assert db.update_account_status(uid, 99999, "正常") is False
    assert db.update_aws_code_status(uid, 99999, True) is False


def test_user_cannot_touch_other_users_account(tmp_db):
    """跨用户读/改/删，必须全部失败/返回空。"""
    db, uid = tmp_db
    other = db.create_user("other", hash_password("pwdother"))
    db.add_account(uid, "mine@g.com", "p")
    aid = db.get_all_accounts(uid)[0].id

    assert db.get_account(other, aid) is None
    assert db.delete_account(other, aid) is False
    assert db.update_account_group(other, aid, "x") is False
    assert db.update_account_remark(other, aid, "r") is False
    assert db.update_account_status(other, aid, "正常") is False
    # 自己仍能正常操作
    assert db.get_account(uid, aid) is not None


def test_group_lifecycle(tmp_db):
    db, uid = tmp_db
    assert db.add_group(uid, "Foo")
    assert not db.add_group(uid, "Foo")
    assert not db.add_group(uid, "   ")
    assert db.group_exists(uid, "Foo")
    assert not db.group_exists(uid, "Bar")

    assert db.rename_group(uid, "Foo", "Bar")
    assert not db.rename_group(uid, "Bar", "Bar")
    assert not db.rename_group(uid, "默认分组", "X")
    assert not db.rename_group(uid, "不存在", "Z")

    assert db.delete_group(uid, "Bar")
    assert not db.delete_group(uid, "Bar")
    assert not db.delete_group(uid, "默认分组")


def test_groups_are_per_user(tmp_db):
    """不同用户可以创建同名分组互不冲突。"""
    db, uid = tmp_db
    other = db.create_user("other", hash_password("pwdother"))
    assert db.add_group(uid, "Same")
    assert db.add_group(other, "Same")
    assert db.group_exists(uid, "Same") and db.group_exists(other, "Same")


def test_settings_are_per_user(tmp_db):
    db, uid = tmp_db
    other = db.create_user("other", hash_password("pwdother"))
    assert db.set_setting(uid, "theme", "dark")
    assert db.set_setting(other, "theme", "light")
    assert db.get_setting(uid, "theme") == "dark"
    assert db.get_setting(other, "theme") == "light"
    # 白名单
    assert not db.set_setting(uid, "hack", "x")
    assert db.get_setting(uid, "hack") is None


def test_sort_falls_back_to_id(tmp_db):
    db, uid = tmp_db
    db.add_account(uid, "x@g.com", "p")
    res = db.get_all_accounts_sorted(uid, sort_by="hack;DROP", sort_order="ASC")
    assert len(res) == 1


def test_oauth_update_encrypts_refresh_token(tmp_db):
    import sqlite3
    db, uid = tmp_db
    db.add_account(uid, "oa@outlook.com", "")
    aid = db.get_all_accounts(uid)[0].id
    db.update_account_oauth(uid, aid, "client123", "rt-xyz")

    raw = sqlite3.connect(db.db_path).execute(
        "SELECT refresh_token, client_id, account_type FROM accounts WHERE id=?", (aid,)
    ).fetchone()
    assert "rt-xyz" not in raw[0]
    assert raw[0].startswith("enc::v1::")
    assert raw[1] == "client123"
    assert raw[2] == "OAuth2"

    acc = db.get_account(uid, aid)
    assert acc.refresh_token == "rt-xyz"


def test_user_account_uniqueness(tmp_db):
    """create_user 重名应返回 None。"""
    db, _ = tmp_db
    assert db.create_user("dup", hash_password("p")) is not None
    assert db.create_user("dup", hash_password("p")) is None


def test_session_lifecycle(tmp_db):
    db, uid = tmp_db
    token = db.create_session(uid, ttl_seconds=60)
    assert token
    user = db.get_session_user(token)
    assert user and user["id"] == uid
    assert db.delete_session(token) is True
    assert db.get_session_user(token) is None


def test_session_expires(tmp_db):
    """ttl_seconds<=0 时立刻过期，校验失败。"""
    db, uid = tmp_db
    token = db.create_session(uid, ttl_seconds=-1)
    assert db.get_session_user(token) is None
