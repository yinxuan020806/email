# -*- coding: utf-8 -*-
"""FastAPI 端点回归测试（多用户隔离版）。"""

from __future__ import annotations


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["auth_required"] is True
    assert body["register_enabled"] is True


def test_export_route_not_shadowed_by_int_param(client):
    """/api/accounts/export 不能被 /{account_id} 路由吞掉。

    自 v3.1 起 GET 已禁用（要求 POST + 二次密码），但路由本身必须存在，
    否则会被 /{account_id} 把 'export' 当成整数解析失败返回 422。
    """
    r = client.get("/api/accounts/export")
    # 405 = 路由命中但方法不允许（正确）；422 = 被吞了（错）
    assert r.status_code == 405


def test_get_nonexistent_account_returns_404(client):
    r = client.get("/api/accounts/99999")
    assert r.status_code == 404


def test_update_nonexistent_account_returns_404(client):
    r = client.put("/api/accounts/99999/group", json={"group": "X"})
    assert r.status_code == 404
    r = client.put("/api/accounts/99999/remark", json={"remark": "x"})
    assert r.status_code == 404


def test_delete_nonexistent_group_returns_404(client):
    r = client.delete("/api/groups/notexist")
    assert r.status_code == 404


def test_rename_nonexistent_group_returns_404(client):
    r = client.put("/api/groups/notexist", json={"new_name": "x"})
    assert r.status_code == 404


def test_default_group_protected(client):
    assert client.delete("/api/groups/默认分组").status_code == 400
    assert client.put("/api/groups/默认分组", json={"new_name": "x"}).status_code == 400


def test_blank_group_name_rejected(client):
    r = client.post("/api/groups", json={"name": "   "})
    assert r.status_code == 422


def test_settings_whitelist_enforced(client):
    r = client.put("/api/settings", json={"key": "hack", "value": "1"})
    assert r.status_code == 400


def test_invalid_folder_rejected(client):
    client.post("/api/accounts/import", json={
        "text": "u@gmail.com----p", "group": "默认分组", "skip_duplicate": False
    })
    aid = client.get("/api/accounts").json()[0]["id"]
    r = client.get(f"/api/accounts/{aid}/emails?folder=hack")
    assert r.status_code == 422


def test_limit_out_of_range_rejected(client):
    client.post("/api/accounts/import", json={
        "text": "u@gmail.com----p", "group": "默认分组", "skip_duplicate": False
    })
    aid = client.get("/api/accounts").json()[0]["id"]
    r = client.get(f"/api/accounts/{aid}/emails?limit=99999")
    assert r.status_code == 422


def test_import_creates_group_automatically(client):
    r = client.post("/api/accounts/import", json={
        "text": "auto@gmail.com----p", "group": "新分组Z", "skip_duplicate": False,
    })
    assert r.status_code == 200
    assert r.json()["success"] == 1

    groups = [g["name"] for g in client.get("/api/groups").json()]
    assert "新分组Z" in groups


def test_batch_delete_returns_actual_count(client):
    r = client.post("/api/accounts/import", json={
        "text": "a@g.com----p\nb@g.com----p", "group": "默认分组", "skip_duplicate": False,
    })
    assert r.status_code == 200
    ids = [a["id"] for a in client.get("/api/accounts").json()]

    r = client.post("/api/accounts/delete", json={"ids": ids + [99999]})
    assert r.status_code == 200
    assert r.json() == {"deleted": len(ids), "requested": len(ids) + 1}


def test_dashboard_counts(client):
    client.post("/api/accounts/import", json={
        "text": "a@g.com----p\nb@g.com----p\nc@g.com----p",
        "group": "默认分组", "skip_duplicate": False,
    })
    d = client.get("/api/dashboard").json()
    assert d["total"] == 3
    assert d["statuses"]["未检测"] == 3


def test_password_returned_decrypted(client):
    client.post("/api/accounts/import", json={
        "text": "x@g.com----myplain", "group": "默认分组", "skip_duplicate": False,
    })
    a = client.get("/api/accounts").json()[0]
    assert a["password"] == "myplain"


def test_data_dir_env_var(tmp_path, monkeypatch):
    """EMAIL_DATA_DIR 应能控制数据库与主密钥的位置。"""
    import sys
    from core import security
    security.SecretBox._instance = None  # noqa: SLF001

    custom_dir = tmp_path / "custom"
    monkeypatch.setenv("EMAIL_DATA_DIR", str(custom_dir))
    monkeypatch.chdir(tmp_path)
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager", "core.")):
            sys.modules.pop(m, None)

    from database.db_manager import DatabaseManager  # noqa: WPS433
    db = DatabaseManager()
    assert (custom_dir / "emails.db").exists()
    assert (custom_dir / ".master.key").exists()

    security.SecretBox._instance = None  # noqa: SLF001


# ── Auth ─────────────────────────────────────────────────────────


def test_unauthenticated_requests_rejected(tmp_path, monkeypatch):
    """未登录访问受保护接口应 401，且不区分 GET/POST/PUT/DELETE。"""
    import sys
    from core import security
    security.SecretBox._instance = None  # noqa: SLF001
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager", "core.")):
            sys.modules.pop(m, None)

    from fastapi.testclient import TestClient
    import web_app

    with TestClient(web_app.app) as c:
        # 未登录：受保护接口 401
        assert c.get("/api/accounts").status_code == 401
        assert c.get("/api/groups").status_code == 401
        assert c.get("/api/settings").status_code == 401
        assert c.get("/api/dashboard").status_code == 401
        assert c.get("/api/auth/me").status_code == 401
        # 公开接口可访问
        assert c.get("/api/health").status_code == 200

    security.SecretBox._instance = None  # noqa: SLF001


def test_register_login_logout_flow(client):
    """登录态由 cookie 维护：注销后不应再被识别为已登录。"""
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json() == {"username": "alice"}

    # 注销后 cookie 失效
    assert client.post("/api/auth/logout").status_code == 200
    # TestClient 自带 cookie jar，注销后 cookie 已被清，应当 401
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/accounts").status_code == 401

    # 重新登录应成功
    r = client.post("/api/auth/login", json={"username": "alice", "password": "pwd-alice"})
    assert r.status_code == 200
    assert client.get("/api/auth/me").status_code == 200


def test_register_validates_fields(client):
    # 用户名太短
    r = client.post("/api/auth/register", json={"username": "ab", "password": "abcdef"})
    assert r.status_code == 400
    # 密码太短
    r = client.post("/api/auth/register", json={"username": "valid", "password": "123"})
    assert r.status_code == 400
    # 用户名含非法字符
    r = client.post("/api/auth/register", json={"username": "中文名", "password": "abcdef"})
    assert r.status_code == 400


def test_register_duplicate_rejected(client):
    """alice 已存在（来自 fixture），不能再注册同名。"""
    r = client.post("/api/auth/register", json={"username": "alice", "password": "anything"})
    assert r.status_code == 409


def test_login_wrong_password_rejected(client):
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"username": "alice", "password": "wrong"})
    assert r.status_code == 401


def test_login_username_case_insensitive(client):
    """注册时统一小写存储，登录支持任意大小写。"""
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"username": "ALICE", "password": "pwd-alice"})
    assert r.status_code == 200


def test_change_password_requires_old(client):
    r = client.post(
        "/api/auth/change-password",
        json={"old_password": "wrong", "new_password": "abcdef-new"},
    )
    assert r.status_code == 400

    r = client.post(
        "/api/auth/change-password",
        json={"old_password": "pwd-alice", "new_password": "abcdef-new"},
    )
    assert r.status_code == 200
    # 修改密码后会清当前 cookie
    assert client.get("/api/auth/me").status_code == 401
    # 旧密码不能再用
    r = client.post("/api/auth/login", json={"username": "alice", "password": "pwd-alice"})
    assert r.status_code == 401
    # 新密码可登录
    r = client.post("/api/auth/login", json={"username": "alice", "password": "abcdef-new"})
    assert r.status_code == 200


# ── 数据隔离 ─────────────────────────────────────────────────────


def test_two_users_data_isolated(client2):
    """两个登录用户互不可见对方的账号、分组、仪表盘。"""
    a, b = client2

    a.post("/api/accounts/import", json={
        "text": "a1@g.com----p\na2@g.com----p", "group": "默认分组", "skip_duplicate": False,
    })
    b.post("/api/accounts/import", json={
        "text": "b1@g.com----p", "group": "默认分组", "skip_duplicate": False,
    })

    a_emails = sorted(x["email"] for x in a.get("/api/accounts").json())
    b_emails = sorted(x["email"] for x in b.get("/api/accounts").json())
    assert a_emails == ["a1@g.com", "a2@g.com"]
    assert b_emails == ["b1@g.com"]

    assert a.get("/api/dashboard").json()["total"] == 2
    assert b.get("/api/dashboard").json()["total"] == 1


def test_groups_isolated_between_users(client2):
    """同名分组分别归属，互不影响；删除/重命名不会牵连对方。"""
    a, b = client2
    a.post("/api/groups", json={"name": "Common"})
    b.post("/api/groups", json={"name": "Common"})
    assert "Common" in [g["name"] for g in a.get("/api/groups").json()]
    assert "Common" in [g["name"] for g in b.get("/api/groups").json()]

    # alice 删除自己的 Common，不影响 bob
    assert a.delete("/api/groups/Common").status_code == 200
    assert "Common" not in [g["name"] for g in a.get("/api/groups").json()]
    assert "Common" in [g["name"] for g in b.get("/api/groups").json()]


def test_user_cannot_read_other_users_account_by_id(client2):
    """alice 拿到自己的 account_id 后，bob 直接 GET 不能读到。"""
    a, b = client2
    a.post("/api/accounts/import", json={
        "text": "secret@g.com----top", "group": "默认分组", "skip_duplicate": False,
    })
    aid = a.get("/api/accounts").json()[0]["id"]
    assert a.get(f"/api/accounts/{aid}").status_code == 200
    assert b.get(f"/api/accounts/{aid}").status_code == 404
    # 改/删也都不行
    assert b.put(f"/api/accounts/{aid}/remark", json={"remark": "x"}).status_code == 404
    assert b.post("/api/accounts/delete", json={"ids": [aid]}).json()["deleted"] == 0
    # alice 仍然可以读到
    assert a.get(f"/api/accounts/{aid}").status_code == 200


def test_settings_isolated_between_users(client2):
    a, b = client2
    a.put("/api/settings", json={"key": "theme", "value": "dark"})
    b.put("/api/settings", json={"key": "theme", "value": "light"})
    assert a.get("/api/settings").json()["theme"] == "dark"
    assert b.get("/api/settings").json()["theme"] == "light"
