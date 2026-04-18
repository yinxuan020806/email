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
