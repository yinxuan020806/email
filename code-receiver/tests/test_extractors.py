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


def test_openai_new_subdomain_email_openai_com():
    """回归：OpenAI 切到 ``email.openai.com`` 子域时，前台必须仍能拿到最新邮件。

    历史现象：旧 sender pattern 写死 4 个固定子域（openai.com / tm.openai.com /
    auth.openai.com / mail.openai.com）。当 OpenAI 切到 email.openai.com 后这条
    最新邮件被 extractor 跳过，前台只能拿到老的 tm.openai.com 邮件 → 用户感受是
    "接码取到的不是最新"。修复后 ``*@*.openai.com`` 通配涵盖任意子域。
    """
    mails = [
        # 最新邮件：新子域，旧 pattern 漏匹
        make_mail(
            sender='OpenAI <noreply@email.openai.com>',
            subject='您的临时 ChatGPT 登录代码',
            body='输入此临时验证码以继续: 654321 如果并非你本人...',
            date='2026-05-06T20:57:00',
        ),
        # 老邮件：旧 pattern 能命中
        make_mail(
            sender='noreply@tm.openai.com',
            subject='您的临时 ChatGPT 验证码',
            body='输入此临时验证码以继续: 245602',
            date='2026-05-06T20:43:00',
        ),
    ]
    extractors = get_extractors("openai")
    result = first_match(extractors, mails)
    assert result is not None
    assert result.code == "654321", (
        f"应取最新邮件 654321（email.openai.com 子域），实际拿到 {result.code} "
        "—— 说明 sender pattern 没正确通配 .openai.com 子域"
    )


def test_openai_graph_display_name_only_with_sender_email_field():
    """Graph API 返回的邮件 ``sender`` 字段只是 display name（如 ``"OpenAI"``），
    实际邮箱在 ``sender_email``。Extractor.match 必须把两个字段一起看，否则
    pattern ``*@*.openai.com`` 在纯 ``"OpenAI"`` 上永远找不到 @，漏匹。

    这是用户实测场景：管理端 UI 显示的 sender 列就是纯 ``"OpenAI"``，
    背后 Graph 返回的是 ``{from.emailAddress.name: "OpenAI", address: "noreply@email.openai.com"}``。
    """
    mails = [
        {
            "sender": "OpenAI",  # display name only — 实际 Graph 返回就是这样
            "sender_email": "noreply@email.openai.com",
            "subject": "您的临时 ChatGPT 验证码",
            "body": "输入此临时验证码以继续: 777888",
            "preview": "输入此临时验证码以继续: 777888",
            "date": "2026-05-06T20:57:00",
        }
    ]
    extractors = get_extractors("openai")
    result = first_match(extractors, mails)
    assert result is not None
    assert result.code == "777888", (
        f"Extractor 应同时看 sender + sender_email 字段，实际抓到 {result.code}"
    )


def test_openai_subject_only_fallback():
    """终极兜底：sender 完全陌生（如 OpenAI 转 ESP），但 subject 含 ChatGPT 字样
    应该靠 priority=10 的 subject-only 规则命中。"""
    mails = [
        make_mail(
            sender='OpenAI <support@some-third-party-esp.io>',
            subject='您的 ChatGPT 验证码',
            body='输入此临时验证码以继续: 999000',
        )
    ]
    extractors = get_extractors("openai")
    result = first_match(extractors, mails)
    assert result is not None
    assert result.code == "999000"


def test_openai_subject_only_fallback_does_not_match_random():
    """terminal 兜底必须只在 subject 含 ChatGPT/OpenAI 时触发，不能误抓通用邮件。"""
    mails = [
        make_mail(
            sender='spam@example.com',
            subject='Your shopping order #123456',
            body='Code 123456 is your order ID',
        )
    ]
    extractors = get_extractors("openai")
    result = first_match(extractors, mails)
    assert result is None, (
        "随机商家邮件不能被 OpenAI extractor 误抓"
    )


def test_cursor_new_subdomain_notifications():
    """Cursor 后续可能切到 ``notifications.cursor.com`` 等新子域，通配 pattern
    必须能命中，而不是漏掉最新邮件回退到老的。"""
    mails = [
        make_mail(
            sender='Cursor <no-reply@notifications.cursor.com>',
            subject='Your verification code',
            body='Your verification code is 384910.',
            date='2026-05-06T20:00:00',
        ),
        make_mail(
            sender='no-reply@cursor.sh',
            subject='Your code',
            body='Your code is 100000.',
            date='2026-05-05T10:00:00',
        ),
    ]
    extractors = get_extractors("cursor")
    result = first_match(extractors, mails)
    assert result is not None
    assert result.code == "384910"


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
