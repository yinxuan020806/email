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


def test_openai_chinese_subject_with_code():
    """OpenAI 中文模板：主题 '你的 OpenAI 代码为 186862' 自身就含验证码 → 应能抓到。"""
    mails = [
        make_mail(
            sender="noreply@tm.openai.com",
            subject="你的 OpenAI 代码为 186862",
            body="OpenAI\n\n输入此临时验证码以继续:\n\n186862\n\n如果您无意登录...",
        )
    ]
    extractors = get_extractors("openai")
    result = first_match(extractors, mails)
    assert result is not None
    assert result.code == "186862", f"实际抓到 {result.code}"


def test_openai_html_email_extracts_otp():
    """真实场景 OpenAI HTML 邮件：6 位数字被 <div> 包着 + 关键词在另一段 <p>。"""
    html_body = """<!DOCTYPE html><html><head><style>.body{font-family:Sohne}</style></head>
    <body>
      <table><tr><td>
        <p>输入此临时验证码以继续:</p>
        <div style="font-size:32px;text-align:center;letter-spacing:6px">186862</div>
        <p>如果您无意登录 OpenAI，请<a href="#">重置密码</a>。</p>
      </td></tr></table>
    </body></html>"""
    mails = [
        make_mail(
            sender="noreply@tm.openai.com",
            subject="OpenAI - Your verification code",
            body=html_body,
        )
    ]
    extractors = get_extractors("openai")
    result = first_match(extractors, mails)
    assert result is not None
    assert result.code == "186862"


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


# ── ReDoS 防护：正则长度限制 ────────────────────────────────


def test_extractor_rejects_oversize_code_regex():
    """``code_regex`` 超过 200 字符不应被编译（防 ReDoS / 避免管理员误用）。"""
    from extractors.base import Extractor

    long_pattern = r"(?P<code>" + r"\d" * 300 + r")"
    ex = Extractor.from_strings(category="cursor", code_regex=long_pattern)
    assert ex.code_regex is None, "超长 code_regex 必须被静默拒绝"


def test_extractor_rejects_oversize_link_regex():
    from extractors.base import Extractor

    long_pattern = r"(?P<link>" + r"[a-z]" * 300 + r")"
    ex = Extractor.from_strings(category="cursor", link_regex=long_pattern)
    assert ex.link_regex is None


def test_extractor_rejects_oversize_sender_pattern():
    """通配符 sender_pattern 单条 > 100 字符直接丢弃，但其它 segment 正常用。"""
    from extractors.base import Extractor

    huge = "x" * 200
    ex = Extractor.from_strings(
        category="cursor",
        sender_pattern=f"{huge}|*@cursor.sh",
    )
    # 只剩 *@cursor.sh 一个有效 pattern
    assert len(ex.sender_patterns) == 1


def test_extractor_accepts_normal_regex():
    """正常长度的正则正常工作（确保限制没误伤合法规则）。"""
    from extractors.base import Extractor

    ex = Extractor.from_strings(
        category="cursor",
        code_regex=r"(?P<code>\d{6})",
        link_regex=r"(?P<link>https?://cursor\.com/[^\s]+)",
        sender_pattern="*@cursor.com|*@cursor.sh",
    )
    assert ex.code_regex is not None
    assert ex.link_regex is not None
    assert len(ex.sender_patterns) == 2


def test_extractor_invalid_regex_returns_none():
    """非法正则 (unbalanced paren) 必须被吞掉而非抛异常。"""
    from extractors.base import Extractor

    ex = Extractor.from_strings(category="cursor", code_regex="(unclosed")
    assert ex.code_regex is None
