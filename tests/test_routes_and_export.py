# -*- coding: utf-8 -*-
"""SPA 路由 + 二次密码导出 + body 接口测试。"""

from __future__ import annotations


# ── SPA 路由 ────────────────────────────────────────────────


def test_root_returns_index(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "<title" in r.text.lower()
    assert "邮箱管家" in r.text or "mail butler" in r.text.lower()


def test_login_path_returns_index(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert "<html" in r.text.lower()


def test_register_path_returns_index(client):
    r = client.get("/register")
    assert r.status_code == 200
    assert "<html" in r.text.lower()


def test_dashboard_path_returns_index(client):
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert "<html" in r.text.lower()


def test_settings_path_returns_index(client):
    r = client.get("/settings")
    assert r.status_code == 200
    assert "<html" in r.text.lower()


def test_oauth_path_returns_index(client):
    r = client.get("/oauth")
    assert r.status_code == 200
    assert "<html" in r.text.lower()


def test_index_injects_static_version(client):
    """index.html 中的 __STATIC_VERSION__ 占位符应被替换为实际版本号。"""
    r = client.get("/")
    assert r.status_code == 200
    assert "__STATIC_VERSION__" not in r.text, "占位符必须被替换，否则缓存破坏失效"
    # 应该有 ?v=数字 的查询串
    import re
    matches = re.findall(r'app\.(?:js|css)\?v=(\d+)', r.text)
    assert matches, "未在 index.html 中找到 ?v=数字 的版本化 URL"
    # 同一次响应里所有静态资源版本号应一致
    assert len(set(matches)) == 1


def test_index_has_no_cache_headers(client):
    """index.html 必须设置 no-cache 头，避免 CDN/浏览器缓存住入口页。"""
    r = client.get("/")
    cc = r.headers.get("cache-control", "").lower()
    assert "no-cache" in cc or "no-store" in cc


def test_static_assets_served_with_version(client):
    """带 ?v=xxx query 访问静态资源应能正常返回（FastAPI StaticFiles 忽略 query）。"""
    # 先取实际版本
    idx = client.get("/").text
    import re
    m = re.search(r'app\.js\?v=(\d+)', idx)
    assert m
    version = m.group(1)
    r = client.get(f"/static/app.js?v={version}")
    assert r.status_code == 200
    assert len(r.content) > 1000


# ── 二次密码导出 ────────────────────────────────────────────


def test_export_get_method_disabled(client):
    """旧的 GET /api/accounts/export 应明确报 405，让前端立即知道要切换。"""
    r = client.get("/api/accounts/export")
    assert r.status_code == 405


def test_export_post_requires_password(client):
    client.post("/api/accounts/import", json={
        "text": "x@gmail.com----secret", "group": "默认分组", "skip_duplicate": False,
    })
    # 错误密码
    r = client.post("/api/accounts/export", json={"password": "wrong"})
    assert r.status_code == 401
    # 正确密码
    r = client.post("/api/accounts/export", json={"password": "pwd-alice"})
    assert r.status_code == 200
    assert "x@gmail.com----secret" in r.text


def test_export_post_with_group(client):
    client.post("/api/groups", json={"name": "GroupA"})
    client.post("/api/accounts/import", json={
        "text": "ga@g.com----p1", "group": "GroupA", "skip_duplicate": False,
    })
    client.post("/api/accounts/import", json={
        "text": "def@g.com----p2", "group": "默认分组", "skip_duplicate": False,
    })
    r = client.post(
        "/api/accounts/export",
        json={"password": "pwd-alice", "group": "GroupA"},
    )
    assert r.status_code == 200
    assert "ga@g.com" in r.text
    assert "def@g.com" not in r.text


def test_export_includes_group_by_default(client):
    client.post("/api/accounts/import", json={
        "text": "a@g.com----secret----GroupZ", "group": "默认分组", "skip_duplicate": False,
    })
    r = client.post("/api/accounts/export", json={"password": "pwd-alice"})
    assert r.status_code == 200
    # 默认 include_group=True，最后一段应是组名
    assert "a@g.com----secret----GroupZ" in r.text


def test_export_can_omit_group(client):
    client.post("/api/accounts/import", json={
        "text": "a@g.com----secret----GroupZ", "group": "默认分组", "skip_duplicate": False,
    })
    r = client.post(
        "/api/accounts/export",
        json={"password": "pwd-alice", "include_group": False},
    )
    assert r.status_code == 200
    assert "a@g.com----secret" in r.text
    assert "GroupZ" not in r.text


def test_export_dollar_separator(client):
    client.post("/api/accounts/import", json={
        "text": "a@g.com----p1\nb@g.com----p2",
        "group": "默认分组", "skip_duplicate": False,
    })
    r = client.post(
        "/api/accounts/export",
        json={"password": "pwd-alice", "separator": "dollar"},
    )
    assert r.status_code == 200
    assert "$$" in r.text


def test_export_then_reimport_round_trip(client):
    """导出 → 清空 → 再导入，账号、密码、分组、OAuth 字段都应一致。"""
    original = (
        "u1@outlook.com----pw1----abc-uuid----M.C123-rt----GroupA\n"
        "u2@outlook.com----pw2----GroupB\n"
        "u3@gmail.com----pw3"
    )
    client.post("/api/accounts/import", json={
        "text": original, "group": "默认分组", "skip_duplicate": False,
    })

    # 导出
    r = client.post("/api/accounts/export", json={"password": "pwd-alice"})
    assert r.status_code == 200
    exported = r.text

    # 清空所有账号
    ids = [a["id"] for a in client.get("/api/accounts").json()]
    client.post("/api/accounts/delete", json={"ids": ids})
    assert client.get("/api/accounts").json() == []

    # 再导入
    r = client.post("/api/accounts/import", json={
        "text": exported, "group": "默认分组", "skip_duplicate": False,
    })
    assert r.json()["success"] == 3

    accs = {a["email"]: a for a in client.get("/api/accounts").json()}
    assert accs["u1@outlook.com"]["group"] == "GroupA"
    assert accs["u1@outlook.com"]["client_id"] == "abc-uuid"
    assert accs["u1@outlook.com"]["refresh_token"] == "M.C123-rt"
    assert accs["u1@outlook.com"]["password"] == "pw1"
    assert accs["u1@outlook.com"]["type"] == "OAuth2"
    assert accs["u2@outlook.com"]["group"] == "GroupB"
    assert accs["u3@gmail.com"]["password"] == "pw3"


def test_export_unauthenticated_rejected(client):
    client.post("/api/auth/logout")
    r = client.post("/api/accounts/export", json={"password": "any"})
    assert r.status_code == 401


# ── 邮件正文按需拉取接口 ────────────────────────────────


def test_email_body_endpoint_404_for_unknown_account(client):
    r = client.get("/api/accounts/99999/emails/body?email_id=abc")
    assert r.status_code == 404


def test_email_body_endpoint_validates_email_id(client):
    client.post("/api/accounts/import", json={
        "text": "u@gmail.com----p", "group": "默认分组", "skip_duplicate": False,
    })
    aid = client.get("/api/accounts").json()[0]["id"]
    # 缺 email_id
    r = client.get(f"/api/accounts/{aid}/emails/body")
    assert r.status_code == 422
    # email_id 太长
    r = client.get(f"/api/accounts/{aid}/emails/body?email_id={'x' * 3000}")
    assert r.status_code == 422


def test_email_body_endpoint_validates_folder(client):
    client.post("/api/accounts/import", json={
        "text": "u@gmail.com----p", "group": "默认分组", "skip_duplicate": False,
    })
    aid = client.get("/api/accounts").json()[0]["id"]
    r = client.get(f"/api/accounts/{aid}/emails/body?email_id=abc&folder=hack")
    assert r.status_code == 422
