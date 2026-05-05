# -*- coding: utf-8 -*-
"""extractors 默认规则的提取效果测试。

构造塑料邮件 dict 喂进 first_match，验证 cursor / openai 各自能提取出
预期的 code / link。
"""

from __future__ import annotations

from extractors import get_extractors
from extractors.base import SafeLinks, first_match


def make_mail(sender: str, subject: str, body: str, date: str = "2026-05-05T10:00:00"):
    return {
        "sender": sender,
        "from": sender,
        "subject": subject,
        "body": body,
        "preview": body[:200],
        "date": date,
    }


# ── Cursor ────────────────────────────────────────────────────────


def test_cursor_extract_code():
    mails = [
        make_mail(
            sender="no-reply@cursor.sh",
            subject="Your Cursor verification code",
            body="Hi,\n\nYour code is 384910. It expires in 10 minutes.\n",
        )
    ]
    extractors = get_extractors("cursor")
    result = first_match(extractors, mails)
    assert result is not None
    assert result.code == "384910"


def test_cursor_extract_link():
    mails = [
        make_mail(
            sender="auth@cursor.com",
            subject="Sign in to Cursor",
            body=(
                "Click here to sign in:\n"
                "https://cursor.com/auth/sign-in?token=abc123xyz\n"
            ),
        )
    ]
    extractors = get_extractors("cursor")
    result = first_match(extractors, mails)
    assert result is not None
    assert result.link is not None
    assert "cursor.com/auth/sign-in" in result.link


def test_cursor_ignores_unrelated_sender():
    mails = [
        make_mail(
            sender="random@example.com",
            subject="Your code is 123456",
            body="Code: 123456",
        )
    ]
    extractors = get_extractors("cursor")
    result = first_match(extractors, mails)
    assert result is None


def test_cursor_ignores_order_number():
    """6 位 OTP 必须出现在 code/verification/验证码 关键词后 40 字符内，
    不能误抓订单号、票号等其他 6 位数字。"""
    mails = [
        make_mail(
            sender="no-reply@cursor.sh",
            subject="Your Cursor verification code",
            body=(
                "Order #748392 has been confirmed.\n\n"
                "Your verification code is 583024.\n\n"
                "Reference: 999111"
            ),
        )
    ]
    extractors = get_extractors("cursor")
    result = first_match(extractors, mails)
    assert result is not None
    assert result.code == "583024", f"应优先抓到 583024，实际抓到 {result.code}"


def test_cursor_chinese_keyword_otp():
    """中文'验证码'前缀也能命中。"""
    mails = [
        make_mail(
            sender="no-reply@cursor.com",
            subject="Cursor 验证码",
            body="您的验证码是 246810，请在 10 分钟内使用。",
        )
    ]
    extractors = get_extractors("cursor")
    result = first_match(extractors, mails)
    assert result is not None
    assert result.code == "246810"


# ── OpenAI ────────────────────────────────────────────────────────


def test_openai_extract_link_priority():
    mails = [
        make_mail(
            sender="noreply@tm.openai.com",
            subject="Verify your email",
            body=(
                "Hi,\n\nClick to verify:\n"
                "https://auth.openai.com/log-in/identifier?session=abc\n\n"
                "Thanks, OpenAI"
            ),
        )
    ]
    extractors = get_extractors("openai")
    result = first_match(extractors, mails)
    assert result is not None
    assert result.link is not None
    assert "auth.openai.com" in result.link


def test_openai_safelinks_unwrap():
    wrapped = (
        "https://nam11.safelinks.protection.outlook.com/?url=https%3A%2F%2Fauth.openai.com"
        "%2Flog-in%2Fidentifier%3Fsession%3Dabc&data=05%7C..."
    )
    mails = [
        make_mail(
            sender="noreply@auth.openai.com",
            subject="Log in to OpenAI",
            body=f"Sign in: {wrapped}",
        )
    ]
    extractors = get_extractors("openai")
    result = first_match(extractors, mails)
    assert result is not None
    assert result.link.startswith("https://auth.openai.com/log-in/identifier")


def test_openai_otp_fallback():
    mails = [
        make_mail(
            sender="noreply@tm.openai.com",
            subject="Your ChatGPT verification code",
            body="Your code is 749210. It expires in 10 minutes.",
        )
    ]
    extractors = get_extractors("openai")
    result = first_match(extractors, mails)
    assert result is not None
    assert result.code == "749210"


def test_safelinks_unwrap_passthrough():
    """非 SafeLinks 原样返回。"""
    raw = "https://example.com/x?y=1"
    assert SafeLinks.unwrap(raw) == raw


def test_safelinks_unwrap_extracts_url():
    wrapped = (
        "https://nam11.safelinks.protection.outlook.com/?url="
        "https%3A%2F%2Fauth.openai.com%2Flog-in%2F&data=z"
    )
    assert SafeLinks.unwrap(wrapped) == "https://auth.openai.com/log-in/"
