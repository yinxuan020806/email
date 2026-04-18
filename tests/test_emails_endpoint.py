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
