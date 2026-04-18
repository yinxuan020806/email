# -*- coding: utf-8 -*-
"""mail_parser.get_email_body_with_type 行为测试。"""

from __future__ import annotations

import email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from core.mail_parser import get_email_body_with_type


def _build_multipart(text=None, html=None):
    msg = MIMEMultipart("alternative")
    if text:
        msg.attach(MIMEText(text, "plain", "utf-8"))
    if html:
        msg.attach(MIMEText(html, "html", "utf-8"))
    return email.message_from_string(msg.as_string())


def test_prefers_text_over_html():
    msg = _build_multipart(text="hello text", html="<p>hello html</p>")
    body, body_type = get_email_body_with_type(msg)
    assert body == "hello text"
    assert body_type == "text"


def test_falls_back_to_html_when_no_text():
    msg = _build_multipart(html="<p>only html</p>")
    body, body_type = get_email_body_with_type(msg)
    assert "only html" in body
    assert body_type == "html"


def test_empty_message_returns_empty_text():
    msg = email.message_from_string("Subject: x\n\n")
    body, body_type = get_email_body_with_type(msg)
    assert body == ""
    assert body_type == "text"


def test_single_part_html_message():
    raw = (
        "Subject: x\n"
        'Content-Type: text/html; charset="utf-8"\n'
        "\n"
        "<p>direct html</p>"
    )
    msg = email.message_from_string(raw)
    body, body_type = get_email_body_with_type(msg)
    assert "direct html" in body
    assert body_type == "html"


def test_single_part_text_message():
    raw = (
        "Subject: x\n"
        'Content-Type: text/plain; charset="utf-8"\n'
        "\n"
        "plain content"
    )
    msg = email.message_from_string(raw)
    body, body_type = get_email_body_with_type(msg)
    assert body == "plain content"
    assert body_type == "text"


def test_truncates_to_max_size():
    """超过 MAX_BODY_BYTES 的正文会被截断。"""
    from core import mail_parser
    big = "a" * (mail_parser.MAX_BODY_BYTES + 1000)
    raw = (
        "Subject: x\n"
        'Content-Type: text/plain; charset="utf-8"\n'
        "\n"
        + big
    )
    msg = email.message_from_string(raw)
    body, _ = get_email_body_with_type(msg)
    assert len(body) == mail_parser.MAX_BODY_BYTES
