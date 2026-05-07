# -*- coding: utf-8 -*-
"""/api/accounts/{id}/emails 端点行为：默认 with_body=False 节省带宽。"""

from __future__ import annotations

from unittest.mock import patch
from datetime import datetime


def _import_acc(client, email="u@gmail.com", pw="pw"):
    client.post("/api/accounts/import", json={
        "text": f"{email}----{pw}", "group": "默认分组", "skip_duplicate": False,
    })
    return client.get("/api/accounts").json()[0]["id"]


def _fake_emails():
    """模拟 fetch_emails 的返回结构。"""
    return ([
        {
            "uid": "1", "subject": "Test", "sender": "x@y.com",
            "sender_email": "x@y.com",
            "date": datetime(2026, 4, 18, 10, 0, 0),
            "body": "<p>Hello world</p>" * 100,
            "body_type": "html",
            "preview": "Hello world",
            "is_read": False, "has_attachments": False,
        },
    ], "ok")


def test_emails_default_strips_body(client):
    aid = _import_acc(client)
    with patch("core.email_client.EmailClient.fetch_emails", return_value=_fake_emails()):
        r = client.get(f"/api/accounts/{aid}/emails?folder=inbox")
    assert r.status_code == 200
    e = r.json()["emails"][0]
    # 默认 with_body=False：body 必须被清空，preview 保留
    assert e["body"] == ""
    assert e["preview"]  # 非空


# ── 上游软失败透传：Graph 限流不能被静默成"暂无数据" ────────────────


def test_emails_empty_inbox_still_returns_200(client):
    """真的没邮件（IMAP / Graph 都返回 (空, "获取成功")）必须仍然返回 200，
    避免把"空收件箱"误判成上游错误。
    """
    aid = _import_acc(client)
    with patch(
        "core.email_client.EmailClient.fetch_emails", return_value=([], "获取成功"),
    ):
        r = client.get(f"/api/accounts/{aid}/emails?folder=inbox")
    assert r.status_code == 200
    assert r.json()["emails"] == []


def test_emails_graph_429_propagates_as_429(client):
    """上游 Graph 返回 429 时后端必须把状态码抛出去，前端 catch 分支才能
    显示明确"加载失败"+ 详情，而不是被前端误读为"暂无数据"。
    """
    aid = _import_acc(client)
    upstream_msg = "API 错误: 429 - {error: throttle}"
    with patch(
        "core.email_client.EmailClient.fetch_emails", return_value=([], upstream_msg),
    ):
        r = client.get(f"/api/accounts/{aid}/emails?folder=inbox")
    assert r.status_code == 429
    # 错误详情透传给前端，便于运维 / 用户看清根因
    body = r.json()
    assert "429" in body.get("detail", "")
    # 给前端一个保守的 Retry-After 提示
    assert r.headers.get("Retry-After")


def test_emails_graph_502_propagates_as_502(client):
    """非 429 的上游软失败（503/504/网络错误/OAuth 错误）走 502 Bad Gateway。"""
    aid = _import_acc(client)
    upstream_msg = "API 错误: 503 - service unavailable"
    with patch(
        "core.email_client.EmailClient.fetch_emails", return_value=([], upstream_msg),
    ):
        r = client.get(f"/api/accounts/{aid}/emails?folder=inbox")
    assert r.status_code == 502
    assert "503" in r.json().get("detail", "")


def test_emails_oauth_error_propagates_as_502(client):
    """OAuth refresh 失败也属于"上游不通"，不能装作"暂无邮件"。"""
    aid = _import_acc(client)
    with patch(
        "core.email_client.EmailClient.fetch_emails",
        return_value=([], "OAuth2 错误: invalid_grant"),
    ):
        r = client.get(f"/api/accounts/{aid}/emails?folder=inbox")
    assert r.status_code == 502


# ── GraphClient 软抖动单次重试：429/503/504 不应一次失败就告诉用户"没邮件" ──


def _stub_graph_client():
    """构造一个最小可用的 GraphClient（不发真实请求）。"""
    from core.graph_client import GraphClient
    from unittest.mock import MagicMock

    tm = MagicMock()
    tm.get.return_value = ("fake-token", "ok")
    tm.api_type = "graph"
    return GraphClient(tm)


def test_graph_fetch_emails_retries_once_on_429():
    """Graph 第一次 429，第二次 200 → 最终成功（重试 1 次）。"""
    from unittest.mock import MagicMock, patch

    client = _stub_graph_client()
    resp_429 = MagicMock()
    resp_429.status_code = 429
    resp_429.headers = {"Retry-After": "1"}
    resp_429.text = "throttled"
    resp_ok = MagicMock()
    resp_ok.status_code = 200
    resp_ok.headers = {}
    resp_ok.json.return_value = {"value": []}

    with patch.object(client, "_req", side_effect=[resp_429, resp_ok]) as req, \
         patch("core.graph_client.time.sleep") as sleep_mock:
        emails, msg = client.fetch_emails("inbox", limit=10)

    # 严格只重试一次：先后调用 _req 两次
    assert req.call_count == 2
    # Retry-After 头被尊重，且 sleep 至少被调用一次
    sleep_mock.assert_called_once()
    assert emails == []
    assert msg == "获取成功"


def test_graph_fetch_emails_does_not_retry_more_than_once():
    """连续 429 时只重试 1 次后返回错误，避免循环踩限流计时器。"""
    from unittest.mock import MagicMock, patch

    client = _stub_graph_client()
    resp_429 = MagicMock()
    resp_429.status_code = 429
    resp_429.headers = {}
    resp_429.text = "throttled"

    with patch.object(client, "_req", return_value=resp_429) as req, \
         patch("core.graph_client.time.sleep"):
        emails, msg = client.fetch_emails("inbox", limit=10)

    assert req.call_count == 2  # 1 原始 + 1 重试，**不再** 3+ 次
    assert emails == []
    assert "429" in msg


def test_graph_fetch_emails_clamps_retry_after_header():
    """服务端给个离谱的 Retry-After=600（10 分钟）也只 sleep ≤ 4s，
    避免单次 web 请求阻塞用户太久。
    """
    from unittest.mock import MagicMock, patch
    from core import graph_client as gc

    client = _stub_graph_client()
    resp_429 = MagicMock()
    resp_429.status_code = 429
    resp_429.headers = {"Retry-After": "600"}  # 故意离谱
    resp_429.text = "throttled"
    resp_ok = MagicMock()
    resp_ok.status_code = 200
    resp_ok.headers = {}
    resp_ok.json.return_value = {"value": []}

    with patch.object(client, "_req", side_effect=[resp_429, resp_ok]), \
         patch("core.graph_client.time.sleep") as sleep_mock:
        client.fetch_emails("inbox", limit=10)

    actual_sleep = sleep_mock.call_args[0][0]
    assert actual_sleep <= gc._RETRY_BACKOFF_MAX_SEC


# ── batch_check / single_check 合并：1 次 fetch_emails 替换 2 次上游请求 ──


def test_quick_check_with_aws_merges_status_and_aws_into_one_request():
    """``quick_check_with_aws`` 应该只调用一次 fetch_emails，而不是
    历史的 check_status + check_aws_verification_emails 两次。
    """
    from core.email_client import EmailClient
    from unittest.mock import MagicMock

    c = EmailClient.__new__(EmailClient)
    c.email_addr = "u@outlook.com"
    c.password = ""
    c.account_id = 1
    c._token_manager = MagicMock()
    c._graph = MagicMock()
    c._imap = MagicMock()

    # 用 spy 监控 fetch_emails 是否只被调用一次
    fake_emails = [
        {"subject": "Your AWS verification code", "uid": "1"},
        {"subject": "Hello", "uid": "2"},
    ]
    spy = MagicMock(return_value=(fake_emails, "获取成功"))
    c.fetch_emails = spy
    # 旧 check_status + check_aws 仍在但**不应**被调用
    check_status_spy = MagicMock(return_value=("不该被调用", "x"))
    c.check_status = check_status_spy

    status_str, has_aws, msg = c.quick_check_with_aws(limit=30)
    assert status_str == "正常"
    assert has_aws is True
    assert msg == "获取成功"
    assert spy.call_count == 1, "quick_check_with_aws 应该只调一次 fetch_emails"
    assert check_status_spy.call_count == 0, (
        "quick_check_with_aws 不应再回退到 check_status + check_aws 两次请求"
    )


def test_quick_check_with_aws_reports_status_abnormal_on_429():
    """fetch_emails 返回 ([], "API 错误: 429") 时，状态判异常、has_aws=False。"""
    from core.email_client import EmailClient
    from unittest.mock import MagicMock

    c = EmailClient.__new__(EmailClient)
    c.email_addr = "u@outlook.com"
    c.password = ""
    c.account_id = 1
    c._token_manager = MagicMock()
    c._graph = MagicMock()
    c._imap = MagicMock()
    c.fetch_emails = MagicMock(return_value=([], "API 错误: 429"))

    status_str, has_aws, msg = c.quick_check_with_aws(limit=30)
    assert status_str == "异常"
    assert has_aws is False
    assert "429" in msg


def test_quick_check_with_aws_treats_empty_inbox_as_normal():
    """收件箱真的没邮件（[], "获取成功"）应判正常 + has_aws=False，
    避免误把"空收件箱"标成异常账号。
    """
    from core.email_client import EmailClient
    from unittest.mock import MagicMock

    c = EmailClient.__new__(EmailClient)
    c.email_addr = "u@outlook.com"
    c.password = ""
    c.account_id = 1
    c._token_manager = MagicMock()
    c._graph = MagicMock()
    c._imap = MagicMock()
    c.fetch_emails = MagicMock(return_value=([], "获取成功"))

    status_str, has_aws, msg = c.quick_check_with_aws(limit=30)
    assert status_str == "正常"
    assert has_aws is False


# ── 上游 401/HTML 登录页：错误信息必须被净化 ───────────────────────


def test_graph_fetch_emails_does_not_leak_html_login_page_on_401():
    """OAuth 凭据失效时 Microsoft 会返回 HTML 登录页。msg 必须不含 ``<html>``
    / ``<!DOCTYPE`` 等原始 HTML，且应给出"重新授权"提示。
    """
    from unittest.mock import MagicMock, patch

    c = _stub_graph_client()
    html_login = (
        "<!DOCTYPE html>\n<!--[if lt IE 7]> <html class=\"no-js ie6 oldie\""
        " lang=\"en-US\"> <![endif]-->\n<title>Sign in to your account</title>"
        "<body>...</body></html>"
    )
    resp_401 = MagicMock()
    resp_401.status_code = 401
    resp_401.headers = {}
    resp_401.text = html_login
    resp_401.json.side_effect = ValueError("not json")

    with patch.object(c, "_req", return_value=resp_401):
        emails, msg = c.fetch_emails("inbox", limit=30)

    assert emails == []
    # 关键：msg 里不能有 HTML 片段；应该出现"凭据失效 / 重新授权"提示
    assert "<!DOCTYPE" not in msg
    assert "<html" not in msg
    assert "<title" not in msg
    assert ("OAuth" in msg or "凭据" in msg or "重新授权" in msg)


def test_graph_get_email_body_does_not_leak_html_login_page_on_401():
    """点开单封邮件遇到 401 + HTML 时同样不能泄露 HTML 给前端。"""
    from unittest.mock import MagicMock, patch

    c = _stub_graph_client()
    html_login = "<!DOCTYPE html><html><body>login</body></html>"
    resp_401 = MagicMock()
    resp_401.status_code = 401
    resp_401.headers = {}
    resp_401.text = html_login
    resp_401.json.side_effect = ValueError("not json")

    with patch.object(c, "_req", return_value=resp_401):
        body, body_type, mid, msg = c.get_email_body("graph-id-x")

    assert body is None
    assert "<!DOCTYPE" not in msg
    assert "<html" not in msg


def test_graph_check_status_does_not_leak_html_login_page():
    """check_status 在 401/HTML 时也走净化路径（避免账号"状态"列泄露 HTML）。"""
    from unittest.mock import MagicMock, patch

    c = _stub_graph_client()
    resp_401 = MagicMock()
    resp_401.status_code = 401
    resp_401.headers = {}
    resp_401.text = "<!DOCTYPE html><html><body>login</body></html>"
    resp_401.json.side_effect = ValueError("not json")

    with patch.object(c, "_req", return_value=resp_401):
        status_str, msg = c.check_status()
    assert status_str == "异常"
    assert "<!DOCTYPE" not in msg
    assert "<html" not in msg


def test_emails_endpoint_does_not_leak_html_to_client(client):
    """端到端：fetch_emails 返回的 msg 即使含 ``<html>`` 残片，HTTPException
    detail 也要被净化（防御纵深第二层），保证浏览器看不到 HTML 标签字符。
    """
    aid = _import_acc(client)
    leaked = "API 错误 401: <!DOCTYPE html><html><body>login</body></html>"
    with patch(
        "core.email_client.EmailClient.fetch_emails", return_value=([], leaked),
    ):
        r = client.get(f"/api/accounts/{aid}/emails?folder=inbox")
    assert r.status_code == 502
    detail = r.json().get("detail", "")
    # 关键：浏览器能看到的字符里不该有 HTML 标签
    assert "<" not in detail
    assert ">" not in detail
    assert "DOCTYPE" not in detail or "html" not in detail.lower()


# ── 邮件列表 5s 进程级缓存：把"刷次数"和"上游调用次数"解耦 ────────


def test_emails_list_uses_short_term_cache(client, monkeypatch):
    """连续两次刷新同账号同文件夹，第二次应命中后端 5s 缓存，
    fetch_emails 只被调一次（防止用户连点把上游撞穿）。
    """
    import web_app
    monkeypatch.setattr(web_app, "_EMAIL_LIST_CACHE_TTL", 5.0)
    web_app._email_list_cache.clear()

    aid = _import_acc(client)
    fake = ([
        {"uid": "1", "subject": "T", "sender": "x", "sender_email": "x@y",
         "date": None, "body": "<p>hi</p>", "body_type": "html",
         "preview": "hi", "is_read": False, "has_attachments": False},
    ], "获取成功")
    with patch(
        "core.email_client.EmailClient.fetch_emails", return_value=fake,
    ) as spy:
        r1 = client.get(f"/api/accounts/{aid}/emails?folder=inbox")
        r2 = client.get(f"/api/accounts/{aid}/emails?folder=inbox")
        r3 = client.get(f"/api/accounts/{aid}/emails?folder=inbox")
    assert r1.status_code == r2.status_code == r3.status_code == 200
    assert spy.call_count == 1, (
        f"3 次刷新只应命中 1 次上游 fetch_emails，实际 {spy.call_count} 次"
    )
    # 命中缓存的响应有 cached: True 标记
    assert r2.json().get("cached") is True
    assert r3.json().get("cached") is True


def test_emails_list_cache_keyed_by_account(client, monkeypatch):
    """换账号 / 换文件夹必须各自独立缓存，不能让 A 的列表污染 B。"""
    import web_app
    monkeypatch.setattr(web_app, "_EMAIL_LIST_CACHE_TTL", 5.0)
    web_app._email_list_cache.clear()

    a1 = _import_acc(client, email="a1@gmail.com")
    a2 = _import_acc(client, email="a2@gmail.com")
    fake = ([
        {"uid": "1", "subject": "T", "sender": "x", "sender_email": "x@y",
         "date": None, "body": "", "body_type": "text",
         "preview": "", "is_read": False, "has_attachments": False},
    ], "获取成功")
    with patch(
        "core.email_client.EmailClient.fetch_emails", return_value=fake,
    ) as spy:
        client.get(f"/api/accounts/{a1}/emails?folder=inbox")
        client.get(f"/api/accounts/{a2}/emails?folder=inbox")
        client.get(f"/api/accounts/{a1}/emails?folder=junk")
    # 三个不同 (account_id, folder) 组合 → 三次都打上游
    assert spy.call_count == 3


def test_emails_list_cache_failure_not_stored(client, monkeypatch):
    """上游错误不能进缓存——否则一次失败把 5 秒窗口都钉死成"加载失败"，
    用户体验比没缓存更差。
    """
    import web_app
    monkeypatch.setattr(web_app, "_EMAIL_LIST_CACHE_TTL", 5.0)
    web_app._email_list_cache.clear()

    aid = _import_acc(client)
    # 第一次 → 上游失败（429）
    # 第二次 → 上游恢复
    side = [
        ([], "API 错误: 429"),
        ([
            {"uid": "1", "subject": "T", "sender": "x", "sender_email": "x@y",
             "date": None, "body": "", "body_type": "text",
             "preview": "", "is_read": False, "has_attachments": False},
        ], "获取成功"),
    ]
    with patch(
        "core.email_client.EmailClient.fetch_emails", side_effect=side,
    ):
        r1 = client.get(f"/api/accounts/{aid}/emails?folder=inbox")
        r2 = client.get(f"/api/accounts/{aid}/emails?folder=inbox")
    assert r1.status_code == 429   # 失败透传
    assert r2.status_code == 200   # 失败没进缓存，第二次重新打上游
    assert r2.json().get("cached") is None or r2.json().get("cached") is False


def test_emails_list_cache_invalidated_on_delete(client, monkeypatch):
    """删邮件后缓存必须失效——否则用户删了之后下次刷新还能看到那封。"""
    import web_app
    monkeypatch.setattr(web_app, "_EMAIL_LIST_CACHE_TTL", 5.0)
    web_app._email_list_cache.clear()

    aid = _import_acc(client)
    fake = ([
        {"uid": "abc", "subject": "T", "sender": "x", "sender_email": "x@y",
         "date": None, "body": "", "body_type": "text",
         "preview": "", "is_read": False, "has_attachments": False},
    ], "获取成功")
    with patch(
        "core.email_client.EmailClient.fetch_emails", return_value=fake,
    ) as fetch_spy, patch(
        "core.email_client.EmailClient.delete_email", return_value=(True, "删除成功"),
    ):
        client.get(f"/api/accounts/{aid}/emails?folder=inbox")
        client.post(
            f"/api/accounts/{aid}/emails/delete",
            json={"email_id": "abc", "folder": "inbox"},
        )
        client.get(f"/api/accounts/{aid}/emails?folder=inbox")
    assert fetch_spy.call_count == 2, (
        "删除后下次 GET emails 必须重新打上游，否则用户看到已删邮件"
    )


def test_app_js_refresh_button_throttle_present(client):
    """前端"刷新"按钮要有 disable 防连点机制。"""
    body = client.get("/static/app.js").text
    # disable 1.5s 防连点
    assert "btn.disabled = true" in body
    # 与 EMAIL_LIST_MIN_INTERVAL_MS 对齐
    assert "EMAIL_LIST_MIN_INTERVAL_MS = 1500" in body, (
        "loadEmails 节流间隔应升到 1500ms（与后端缓存层级匹配）"
    )


def test_app_js_sanitizes_upstream_msg_in_loadEmails(client):
    """前端 loadEmails 必须有 _sanitizeUpstreamMsg 第三层兜底，确保 HTML
    不会出现在错误条文本里。"""
    body = client.get("/static/app.js").text
    assert "_sanitizeUpstreamMsg" in body, (
        "loadEmails 缺少 _sanitizeUpstreamMsg 兜底，HTML 上游泄漏时还会被原样渲染"
    )
    # 反例守护：旧的"未净化直接渲染"不能再回归
    assert "String(err.message).slice(0, 200)" not in body, (
        "loadEmails 不能再直接 slice err.message —— 要经 _sanitizeUpstreamMsg"
    )


def test_check_single_endpoint_uses_merged_path(client):
    """``POST /api/accounts/{id}/check`` 不再调用旧的 ``check_status`` +
    ``check_aws_verification_emails`` 两次接口；只走 ``quick_check_with_aws``。
    """
    aid = _import_acc(client)
    with patch(
        "core.email_client.EmailClient.quick_check_with_aws",
        return_value=("正常", True, "获取成功"),
    ) as merged, patch(
        "core.email_client.EmailClient.check_status",
        return_value=("不该被调用", "x"),
    ) as old_status:
        r = client.post(f"/api/accounts/{aid}/check")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "正常"
    assert body["has_aws"] is True
    merged.assert_called_once()
    old_status.assert_not_called()


def test_graph_get_email_body_retries_once_on_503():
    """单封邮件 body 拉取也享受同样的重试待遇——避免点开邮件偶发软抖动。"""
    from unittest.mock import MagicMock, patch

    client = _stub_graph_client()
    resp_503 = MagicMock()
    resp_503.status_code = 503
    resp_503.headers = {}
    resp_503.text = "service unavailable"
    resp_ok = MagicMock()
    resp_ok.status_code = 200
    resp_ok.headers = {}
    resp_ok.json.return_value = {
        "id": "x", "subject": "s",
        "body": {"contentType": "html", "content": "<p>hi</p>" * 30},
        "bodyPreview": "hi",
        "internetMessageId": "<x@y>",
    }

    with patch.object(client, "_req", side_effect=[resp_503, resp_ok]) as req, \
         patch("core.graph_client.time.sleep"):
        body, body_type, mid, msg = client.get_email_body("graph-id-xxx")

    assert req.call_count == 2
    assert body and "hi" in body
    assert msg == "获取成功"


def test_emails_with_body_keeps_full(client):
    aid = _import_acc(client)
    with patch("core.email_client.EmailClient.fetch_emails", return_value=_fake_emails()):
        r = client.get(f"/api/accounts/{aid}/emails?folder=inbox&with_body=true")
    assert r.status_code == 200
    e = r.json()["emails"][0]
    # with_body=True：body 完整保留
    assert "<p>Hello world</p>" in e["body"]


def test_emails_preview_auto_filled_when_missing(client):
    """如果 fetch_emails 返回的 preview 为空但 body 有内容，应自动填 preview。"""
    fake = ([
        {
            "uid": "1", "subject": "T", "sender": "x", "sender_email": "x@y.com",
            "date": None, "body": "A" * 500, "body_type": "text",
            "preview": "",
            "is_read": True, "has_attachments": False,
        },
    ], "ok")
    aid = _import_acc(client)
    with patch("core.email_client.EmailClient.fetch_emails", return_value=fake):
        r = client.get(f"/api/accounts/{aid}/emails?folder=inbox")
    e = r.json()["emails"][0]
    assert e["body"] == ""
    assert e["preview"] == "A" * 200


def test_email_body_endpoint_returns_full_body(client):
    """/emails/body 应返回完整 body 用于点击单封时按需获取。"""
    aid = _import_acc(client)
    with patch(
        "core.email_client.EmailClient.fetch_email_body",
        return_value=("<p>Full body</p>", "html", "ok"),
    ):
        r = client.get(f"/api/accounts/{aid}/emails/body?email_id=abc&folder=inbox")
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert body["body"] == "<p>Full body</p>"
    assert body["body_type"] == "html"


def test_email_body_endpoint_handles_failure(client):
    aid = _import_acc(client)
    with patch(
        "core.email_client.EmailClient.fetch_email_body",
        return_value=(None, "", "Token expired"),
    ):
        r = client.get(f"/api/accounts/{aid}/emails/body?email_id=abc&folder=inbox")
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False
    assert "Token expired" in body["message"]


# ── EmailClient.fetch_email_body Graph→IMAP 兜底 ─────────────


def test_fetch_email_body_falls_back_to_imap_when_graph_empty():
    """Graph 返回空 body 但 internet_msg_id 有值时，应用 IMAP 反查。"""
    from core.email_client import EmailClient
    from unittest.mock import MagicMock

    client = EmailClient.__new__(EmailClient)
    client.email_addr = "x@outlook.com"
    client.password = ""
    client.account_id = 1
    client._token_manager = MagicMock()
    client._graph = MagicMock()
    client._imap = MagicMock()

    client._graph.get_email_body.return_value = ("", "html", "<msgid@x>", "ok")
    client._imap.fetch_body_by_message_id.return_value = (
        "<p>recovered from imap</p>", "html", "got",
    )

    body, body_type, msg = client.fetch_email_body("graph-id-xxx", "inbox")
    assert body == "<p>recovered from imap</p>"
    assert body_type == "html"
    client._imap.fetch_body_by_message_id.assert_called_once_with("<msgid@x>", "inbox")


def test_fetch_email_body_uses_graph_when_long_enough():
    """Graph body 足够长时不应触发 IMAP fallback（性能考虑）。"""
    from core.email_client import EmailClient
    from unittest.mock import MagicMock

    client = EmailClient.__new__(EmailClient)
    client.email_addr = "x@outlook.com"
    client.password = ""
    client.account_id = 1
    client._token_manager = MagicMock()
    client._graph = MagicMock()
    client._imap = MagicMock()

    long_body = "<p>" + "x" * 200 + "</p>"
    client._graph.get_email_body.return_value = (long_body, "html", "<id>", "ok")

    body, body_type, msg = client.fetch_email_body("graph-id", "inbox")
    assert body == long_body
    client._imap.fetch_body_by_message_id.assert_not_called()


def test_fetch_email_body_returns_short_body_when_imap_also_fails():
    """Graph 返回短 body 且 IMAP 反查也失败时，至少返回 Graph 的短 body。"""
    from core.email_client import EmailClient
    from unittest.mock import MagicMock

    client = EmailClient.__new__(EmailClient)
    client.email_addr = "x@outlook.com"
    client.password = ""
    client.account_id = 1
    client._token_manager = MagicMock()
    client._graph = MagicMock()
    client._imap = MagicMock()

    client._graph.get_email_body.return_value = ("short", "text", "<id>", "ok")
    client._imap.fetch_body_by_message_id.return_value = (None, "", "not found")

    body, body_type, msg = client.fetch_email_body("graph-id", "inbox")
    # 至少把 Graph 拿到的短 body 返回，而不是 None（避免前端永远显示 loading）
    assert body == "short"
