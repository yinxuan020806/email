# -*- coding: utf-8 -*-
"""审计日志：DB 层 + 端点集成。"""

from __future__ import annotations


def test_log_audit_basic(tmp_db):
    db, uid = tmp_db
    db.log_audit("test_action", user_id=uid, username="tester",
                 ip="1.2.3.4", target="abc", detail="hello")
    items = db.list_audit(user_id=uid)
    assert len(items) == 1
    item = items[0]
    assert item["action"] == "test_action"
    assert item["user_id"] == uid
    assert item["username"] == "tester"
    assert item["ip"] == "1.2.3.4"
    assert item["target"] == "abc"
    assert item["detail"] == "hello"
    assert item["success"] is True


def test_log_audit_filtering(tmp_db):
    db, uid = tmp_db
    db.log_audit("login", user_id=uid)
    db.log_audit("logout", user_id=uid)
    db.log_audit("export_accounts", user_id=uid)

    assert len(db.list_audit(user_id=uid, action="login")) == 1
    assert len(db.list_audit(user_id=uid, action="export_accounts")) == 1
    assert len(db.list_audit(user_id=uid)) == 3


def test_audit_isolated_per_user(tmp_db):
    from core.auth import hash_password
    db, uid = tmp_db
    other = db.create_user("other", hash_password("pwdother"))
    db.log_audit("login", user_id=uid)
    db.log_audit("login", user_id=other)
    db.log_audit("logout", user_id=uid)

    a = db.list_audit(user_id=uid)
    b = db.list_audit(user_id=other)
    assert len(a) == 2
    assert len(b) == 1
    assert b[0]["user_id"] == other


def test_audit_truncates_long_fields(tmp_db):
    db, uid = tmp_db
    long_ua = "x" * 1000
    long_detail = "y" * 1000
    db.log_audit("test", user_id=uid, user_agent=long_ua, detail=long_detail)
    item = db.list_audit(user_id=uid)[0]
    assert len(item["detail"]) <= 500


def test_audit_failure_does_not_raise(tmp_db):
    """log_audit 必须吞掉所有异常，不能影响主流程。"""
    db, uid = tmp_db
    # 即使表被破坏也不应抛出
    with db._connect() as conn:
        conn.execute("DROP TABLE audit_log")
    db.log_audit("after_drop", user_id=uid)


# ── 端点测试 ────────────────────────────────────────────────


def test_login_creates_audit_entry(client):
    """登录成功应有审计记录可见。"""
    # client fixture 走的是 register，需要主动 login 一次才会有 login 审计
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "alice", "password": "pwd-alice"})
    r = client.get("/api/audit?action=login")
    assert r.status_code == 200
    items = r.json()["items"]
    assert any(i["action"] == "login" and i["success"] for i in items)


def test_failed_login_creates_failure_audit(client):
    """登录失败应记录 success=false 的审计。"""
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "alice", "password": "wrong"})
    # 重新登录后才能访问审计
    client.post("/api/auth/login", json={"username": "alice", "password": "pwd-alice"})
    r = client.get("/api/audit?only_self=false&action=login")
    assert r.status_code == 200
    items = r.json()["items"]
    assert any(i["action"] == "login" and not i["success"] for i in items)


def test_change_password_audited(client):
    client.post(
        "/api/auth/change-password",
        json={"old_password": "pwd-alice", "new_password": "pwd-alice-new"},
    )
    client.post("/api/auth/login", json={"username": "alice", "password": "pwd-alice-new"})
    r = client.get("/api/audit?action=change_password")
    items = r.json()["items"]
    assert any(i["action"] == "change_password" and i["success"] for i in items)


def test_audit_isolated_per_user_endpoint(client2):
    a, b = client2
    # 让两人各打几条 audit
    a.post("/api/auth/logout")
    a.post("/api/auth/login", json={"username": "alice", "password": "pwd-alice"})
    b.post("/api/auth/logout")
    b.post("/api/auth/login", json={"username": "bob", "password": "pwd-bob"})

    a_items = a.get("/api/audit?only_self=true").json()["items"]
    b_items = b.get("/api/audit?only_self=true").json()["items"]
    # alice 的审计里不应出现 bob 的用户名
    assert all(i["username"] != "bob" for i in a_items if i["username"])
    assert all(i["username"] != "alice" for i in b_items if i["username"])


def test_audit_unauthenticated_returns_401(client):
    client.post("/api/auth/logout")
    r = client.get("/api/audit")
    assert r.status_code == 401
