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


# ── 按选中导出（ids 优先于 group） ────────────────────────────


def test_export_by_ids_only_returns_selected(client):
    """传 ids 只导出指定账号，忽略 group。"""
    client.post("/api/accounts/import", json={
        "text": "a@g.com----p1\nb@g.com----p2\nc@g.com----p3",
        "group": "默认分组", "skip_duplicate": False,
    })
    accs = client.get("/api/accounts").json()
    # 取前两个账号的 id
    chosen = sorted(a["id"] for a in accs)[:2]
    chosen_emails = {a["email"] for a in accs if a["id"] in chosen}

    r = client.post("/api/accounts/export", json={
        "password": "pwd-alice",
        "ids": chosen,
    })
    assert r.status_code == 200
    text = r.text
    for em in chosen_emails:
        assert em in text, f"应包含选中的 {em}"
    # 第三个未被选中的账号不应出现
    others = [a["email"] for a in accs if a["id"] not in chosen]
    for em in others:
        assert em not in text, f"未选中的 {em} 不应在导出中"


def test_export_ids_overrides_group(client):
    """ids 与 group 同时给时应优先用 ids。"""
    client.post("/api/groups", json={"name": "GroupX"})
    client.post("/api/accounts/import", json={
        "text": "x@g.com----p1----GroupX\ny@g.com----p2",
        "group": "默认分组", "skip_duplicate": False,
    })
    accs = client.get("/api/accounts").json()
    y_acc = next(a for a in accs if a["email"] == "y@g.com")

    # group=GroupX 但 ids=[y_acc.id] —— ids 应该胜出
    r = client.post("/api/accounts/export", json={
        "password": "pwd-alice",
        "group": "GroupX",
        "ids": [y_acc["id"]],
    })
    assert r.status_code == 200
    assert "y@g.com" in r.text
    assert "x@g.com" not in r.text, "ids 优先于 group，不应包含 GroupX 的 x@g.com"


def test_export_ids_isolated_per_user(client2):
    """alice 不能通过传 bob 的 account_id 偷取 bob 的账号导出。"""
    a, b = client2
    b.post("/api/accounts/import", json={
        "text": "secret-bob@g.com----very-secret",
        "group": "默认分组", "skip_duplicate": False,
    })
    bob_id = b.get("/api/accounts").json()[0]["id"]

    r = a.post("/api/accounts/export", json={
        "password": "pwd-alice",
        "ids": [bob_id, bob_id + 9999],
    })
    # 应当 200 但内容为空（owner 隔离过滤掉所有非 alice 账号）
    assert r.status_code == 200
    assert "secret-bob" not in r.text
    assert "very-secret" not in r.text
    assert r.text.strip() == "", f"alice 不应导出到 bob 的账号；实际拿到: {r.text!r}"


def test_export_empty_ids_falls_back_to_all(client):
    """ids 显式传空数组应等价于"未传"，按 group/all 处理。"""
    client.post("/api/accounts/import", json={
        "text": "z@g.com----p",
        "group": "默认分组", "skip_duplicate": False,
    })
    r = client.post("/api/accounts/export", json={
        "password": "pwd-alice",
        "ids": [],
    })
    assert r.status_code == 200
    assert "z@g.com" in r.text


def test_export_ids_dedup_preserves_order(client):
    """传重复的 id 时只会出现一次。"""
    client.post("/api/accounts/import", json={
        "text": "u1@g.com----p1\nu2@g.com----p2",
        "group": "默认分组", "skip_duplicate": False,
    })
    accs = client.get("/api/accounts").json()
    aid = accs[0]["id"]
    r = client.post("/api/accounts/export", json={
        "password": "pwd-alice",
        "ids": [aid, aid, aid],
    })
    assert r.status_code == 200
    assert r.text.count(accs[0]["email"]) == 1, "重复 id 不应导致重复行"


# ── 前端：复制按钮 + 导出对话框新选项 ────────────────────────


def test_index_html_export_modal_has_selected_option(client):
    """导出对话框必须新增「仅选中的账号」选项（i18n key 应在 HTML 中）。"""
    text = client.get("/").text
    assert "modal_export_selected" in text, (
        "导出对话框应有 modal_export_selected i18n key 标记"
    )
    assert 'value="selected"' in text


def test_app_js_has_copy_full_button_and_helper(client):
    """app.js 应该：
    1. 渲染账号行时调用 buildAccountFullString 把账号串拷到剪贴板
    2. 暴露 op_copy_full_hint i18n key 用作按钮 title
    3. doExport 在 scope=selected 时通过 ids 字段提交（而非 group）
    """
    body = client.get("/static/app.js").text
    assert "buildAccountFullString" in body, "操作列复制按钮缺失辅助函数"
    assert "toast_copied_full" in body, "复制成功 toast 缺失 i18n 提示"
    assert "op_copy_full_hint" in body, "复制按钮 title 缺失 i18n 提示"
    # 导出走 ids 路径时 payload 必须有 ids 字段
    assert "payload.ids" in body, "doExport 在 scope=selected 时未传 ids"


def test_i18n_includes_new_keys(client):
    body = client.get("/static/i18n.js").text
    for key in (
        "toast_copied_full",
        "op_copy_full_hint",
        "modal_export_selected",
        "modal_export_selected_n",
        "modal_export_selected_empty",
        "modal_export_selected_hint",
    ):
        assert key in body, f"i18n.js 缺少新 key: {key}"


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
