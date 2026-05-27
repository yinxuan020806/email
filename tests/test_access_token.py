# -*- coding: utf-8 -*-
"""接码邮箱凭证（access_token）相关的 HTTP 与 DB 行为测试。

覆盖：
- /api/accounts/set-public          自动生成 Cursor/GPT 分类 token + 返回 tokens 映射
- /api/accounts/{id}                站长 / 非站长返回 access_tokens 字段差异
- /api/accounts                     列表里 access_tokens 仅站长可见
- /api/accounts/{id}/rotate-token   单个旋转（仅站长）
- /api/accounts/rotate-tokens-bulk  批量旋转（仅站长）
- DB.rotate_access_tokens_bulk(only_public=True) 严格仅旋转 is_public=1
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


# 共享 conftest 的辅助
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _reset_globals() -> None:
    from core import security
    security.SecretBox._instance = None  # noqa: SLF001
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager")):
            sys.modules.pop(m, None)


@pytest.fixture
def owner_client(tmp_path, monkeypatch):
    """以"测试用户=站长"的身份登录一个 TestClient。

    通过把 ``CODE_OWNER_USERNAME`` 设成测试用户名，让这一个 fixture 既能
    走"站长专属"接口又能走普通账号路径。其它已有 fixture（client / client2）
    保持非站长身份，方便对照测试。
    """
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CODE_OWNER_USERNAME", "owner-alice")
    _reset_globals()

    from fastapi.testclient import TestClient
    import web_app  # noqa: WPS433

    # 二次确认：环境变量在 import web_app 之前已生效
    assert web_app.CODE_OWNER_USERNAME == "owner-alice"

    with TestClient(web_app.app) as c:
        r = c.post(
            "/api/auth/register",
            json={"username": "owner-alice", "password": "pwd-owner"},
        )
        assert r.status_code == 200, r.text
        yield c

    _reset_globals()


@pytest.fixture
def normal_client(tmp_path, monkeypatch):
    """普通用户身份（不等于 CODE_OWNER_USERNAME）。"""
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CODE_OWNER_USERNAME", "someone-else")
    _reset_globals()

    from fastapi.testclient import TestClient
    import web_app  # noqa: WPS433

    with TestClient(web_app.app) as c:
        r = c.post(
            "/api/auth/register",
            json={"username": "normal-bob", "password": "pwd-bob-long"},
        )
        assert r.status_code == 200, r.text
        yield c

    _reset_globals()


def _import_one_account(c, email: str = "user1@outlook.com", group: str = "cursor") -> int:
    """通过 /api/accounts/import 导入一个账号，返回其 id。"""
    r = c.post(
        "/api/accounts/import",
        json={"text": f"{email}----p4ssw0rd----{group}", "group": group},
    )
    assert r.status_code == 200, r.text
    # 拉列表找出 id
    r2 = c.get("/api/accounts")
    assert r2.status_code == 200, r2.text
    rows = r2.json()
    for row in rows:
        if row["email"].lower() == email.lower():
            return int(row["id"])
    raise AssertionError(f"未找到刚导入的账号 {email}")


# ── /api/accounts/set-public ─────────────────────────────────────────


def test_set_public_auto_generates_and_returns_token(owner_client):
    """加入接码白名单时若账号尚无 token，自动生成分类凭证并回包。"""
    aid = _import_one_account(owner_client)
    r = owner_client.post(
        "/api/accounts/set-public",
        json={"ids": [aid], "is_public": True},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["updated"] == 1
    tokens = body.get("tokens") or {}
    assert str(aid) in tokens
    new_tokens = tokens[str(aid)]
    assert set(new_tokens) == {"cursor", "openai"}
    assert new_tokens["cursor"].startswith("C")
    assert new_tokens["openai"].startswith("G")
    assert len(new_tokens["cursor"]) == 6
    assert len(new_tokens["openai"]) == 6
    # 再次调用：已有 token 不应再生成 — tokens 字段应为空
    r2 = owner_client.post(
        "/api/accounts/set-public",
        json={"ids": [aid], "is_public": True},
    )
    assert r2.status_code == 200
    assert (r2.json().get("tokens") or {}) == {}


def test_set_public_can_enable_single_category(owner_client):
    """可以只开放 Cursor 或只开放 GPT，且只生成对应前缀凭证。"""
    cursor_id = _import_one_account(owner_client, "cursor-only@outlook.com")
    gpt_id = _import_one_account(owner_client, "gpt-only@outlook.com")

    r1 = owner_client.post(
        "/api/accounts/set-public",
        json={
            "ids": [cursor_id],
            "is_public": True,
            "allowed_categories": ["cursor"],
        },
    )
    assert r1.status_code == 200, r1.text
    cursor_tokens = r1.json()["tokens"][str(cursor_id)]
    assert set(cursor_tokens) == {"cursor"}
    assert cursor_tokens["cursor"].startswith("C")

    r2 = owner_client.post(
        "/api/accounts/set-public",
        json={
            "ids": [gpt_id],
            "is_public": True,
            "allowed_categories": ["openai"],
        },
    )
    assert r2.status_code == 200, r2.text
    gpt_tokens = r2.json()["tokens"][str(gpt_id)]
    assert set(gpt_tokens) == {"openai"}
    assert gpt_tokens["openai"].startswith("G")

    r3 = owner_client.get("/api/accounts/public-ids")
    assert r3.status_code == 200
    categories = r3.json()["categories"]
    assert categories[str(cursor_id)] == "cursor"
    assert categories[str(gpt_id)] == "openai"


def test_set_public_blocked_for_non_owner(normal_client):
    """非站长调用 set-public → 403。"""
    aid = _import_one_account(normal_client)
    r = normal_client.post(
        "/api/accounts/set-public",
        json={"ids": [aid], "is_public": True},
    )
    assert r.status_code == 403


# ── account list / get：access_token 仅站长可见 ───────────────────────


def test_account_list_includes_access_token_for_owner(owner_client):
    aid = _import_one_account(owner_client)
    owner_client.post(
        "/api/accounts/set-public",
        json={"ids": [aid], "is_public": True},
    )
    r = owner_client.get("/api/accounts")
    assert r.status_code == 200, r.text
    rows = r.json()
    row = next(x for x in rows if int(x["id"]) == aid)
    assert "access_tokens" in row, "站长身份下 /api/accounts 必须返回 access_tokens 字段"
    assert row["access_tokens"]["cursor"].startswith("C")
    assert row["access_tokens"]["openai"].startswith("G")
    assert len(row["access_token"]) == 6


def test_account_list_omits_access_token_for_non_owner(normal_client):
    aid = _import_one_account(normal_client)
    # 非站长也不能 set-public，这里直接看列表里不返回 access_token
    r = normal_client.get("/api/accounts")
    assert r.status_code == 200, r.text
    rows = r.json()
    row = next(x for x in rows if int(x["id"]) == aid)
    assert "access_token" not in row, (
        "非站长用户名下的 /api/accounts 响应**绝不应**含 access_token 字段"
    )
    assert "access_tokens" not in row


def test_account_detail_includes_access_token_for_owner(owner_client):
    aid = _import_one_account(owner_client)
    owner_client.post(
        "/api/accounts/set-public",
        json={"ids": [aid], "is_public": True},
    )
    r = owner_client.get(f"/api/accounts/{aid}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("access_tokens")
    assert body["access_tokens"]["cursor"].startswith("C")
    assert body["access_tokens"]["openai"].startswith("G")
    assert body.get("access_token") and len(body["access_token"]) == 6


# ── /api/accounts/{id}/rotate-token ──────────────────────────────────


def test_rotate_single_token(owner_client):
    aid = _import_one_account(owner_client)
    r1 = owner_client.post(
        "/api/accounts/set-public",
        json={"ids": [aid], "is_public": True},
    )
    old_tokens = (r1.json().get("tokens") or {}).get(str(aid))
    assert old_tokens

    r2 = owner_client.post(f"/api/accounts/{aid}/rotate-token", json={})
    assert r2.status_code == 200, r2.text
    new_tokens = r2.json().get("access_tokens") or {}
    assert set(new_tokens) == {"cursor", "openai"}
    assert new_tokens["cursor"].startswith("C")
    assert new_tokens["openai"].startswith("G")
    assert new_tokens != old_tokens

    # 列表里读到的也是新 token
    r3 = owner_client.get("/api/accounts")
    row = next(x for x in r3.json() if int(x["id"]) == aid)
    assert row["access_tokens"] == new_tokens


def test_rotate_single_token_404_for_unknown_id(owner_client):
    r = owner_client.post("/api/accounts/9999999/rotate-token", json={})
    assert r.status_code == 404


def test_rotate_single_token_blocked_for_non_owner(normal_client):
    aid = _import_one_account(normal_client)
    r = normal_client.post(f"/api/accounts/{aid}/rotate-token", json={})
    assert r.status_code == 403


# ── /api/accounts/rotate-tokens-bulk ────────────────────────────────


def test_rotate_tokens_bulk_only_public(owner_client):
    """only_public=True 仅旋转已加入接码的账号。"""
    pub_id = _import_one_account(owner_client, "p@outlook.com", group="cursor")
    priv_id = _import_one_account(owner_client, "q@outlook.com", group="cursor")
    owner_client.post(
        "/api/accounts/set-public", json={"ids": [pub_id], "is_public": True},
    )
    r = owner_client.post(
        "/api/accounts/rotate-tokens-bulk",
        json={"only_public": True},
    )
    assert r.status_code == 200, r.text
    tokens = r.json().get("tokens") or {}
    assert str(pub_id) in tokens
    assert str(priv_id) not in tokens
    assert r.json()["count"] == 1


def test_rotate_tokens_bulk_with_ids(owner_client):
    """传 ids 时仅旋转指定的、属于当前 owner 的账号。"""
    aid = _import_one_account(owner_client)
    owner_client.post(
        "/api/accounts/set-public", json={"ids": [aid], "is_public": True},
    )
    r = owner_client.post(
        "/api/accounts/rotate-tokens-bulk",
        json={"ids": [aid], "only_public": True},
    )
    assert r.status_code == 200
    tokens = r.json().get("tokens") or {}
    assert str(aid) in tokens


def test_rotate_tokens_bulk_rejects_empty_unfiltered(owner_client):
    """不传 ids 且 only_public=False → 400 拒绝（防止误旋转全量账号）。"""
    r = owner_client.post(
        "/api/accounts/rotate-tokens-bulk",
        json={"only_public": False},
    )
    assert r.status_code == 400


def test_rotate_tokens_bulk_blocked_for_non_owner(normal_client):
    r = normal_client.post(
        "/api/accounts/rotate-tokens-bulk",
        json={"only_public": True},
    )
    assert r.status_code == 403


# ── DB 层 v9 自动迁移：老库升级时给公开账号自动生成分类 token ──


def test_v9_migration_auto_generates_category_token_for_public_accounts(tmp_path, monkeypatch):
    """v7 → v9 升级时：公开账号会按分类自动生成 C/G 前缀凭证。

    模拟方式：手工建一个 v7 状态的 DB（user_version=7、accounts.access_token=''），
    再用当前 DatabaseManager 打开，触发 _init_database 内的迁移逻辑。
    """
    import sqlite3

    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    _reset_globals()

    from core.security import SecretBox
    from database.db_manager import DatabaseManager

    db_path = str(tmp_path / "emails.db")

    # 1) 先用当前实现建库（schema 已经包含分类 access_token 列）
    db = DatabaseManager(db_path=db_path)
    box = SecretBox.instance()
    uid = db.create_user("owner", "fake-pbkdf2")
    ok, _ = db.add_account(
        owner_id=uid, email="leg@outlook.com", password="x", group="cursor",
    )
    assert ok is True
    acc_id = db.get_account_by_email(uid, "leg@outlook.com").id

    # 2) 把数据库"回退"成 v7 状态：手工把 access_token 清空、user_version 降为 7
    #    （SecretBox 缓存的密文会过期，但 v8 迁移会用同一个 box.encrypt，所以 OK）
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE accounts SET is_public = 1, access_token = '' "
            "WHERE id = ?",
            (acc_id,),
        )
        conn.execute("PRAGMA user_version = 7")
        conn.commit()

    # 3) 重新 import DatabaseManager 触发 _init_database 跑 v7→v9 迁移
    _reset_globals()
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    from database.db_manager import DatabaseManager as _DM
    db2 = _DM(db_path=db_path)

    acc = db2.get_account(uid, acc_id)
    assert acc is not None
    assert acc.access_token_cursor, "v9 迁移必须自动给 cursor 账号生成 C 开头 token"
    assert acc.access_token_cursor.startswith("C")
    assert len(acc.access_token_cursor) == 6
    # 与该 token 配套的 lookup 应能成功
    found = db2.get_public_account_for_lookup(
        "owner", "leg@outlook.com", "cursor", access_token=acc.access_token_cursor,
    )
    assert found is not None
