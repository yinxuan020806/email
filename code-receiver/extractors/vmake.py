# -*- coding: utf-8 -*-
"""Vmake (vmake.ai) 登录验证码默认提取规则。

Vmake 登录走邮箱 OTP，输入邮箱后发送 6 位数字验证码。实测发信：

发件人参考：
    Vmake <account@vmake.ai>
    （品牌域也可能是 *@vmake.ai / *@*.vmake.ai）

主题参考：
    "Vmake verification code"

正文参考（HTML → 纯文本）：
    Hello, We received a request to log in to Vmake using this email address.
    Please enter the following login code within 10 minutes to access your account.
    3 0 3 5 8 2
    This login code is used to verify your identity.

注意：验证码每个数字在 HTML 里是独立的 span，strip_html_tags 后数字之间
会有空格（"3 0 3 5 8 2"），正则需要兼容这种格式。
"""

from __future__ import annotations

from extractors.base import Extractor


def default_rules() -> list[Extractor]:
    sender = "*@vmake.ai|*@*.vmake.ai"
    subject = "Vmake*|*verification*code*|*Verify*code*|*验证*码*"

    # 匹配 "login code" / "verification code" 后面跟着的 6 位数字
    # 数字之间可能有空格（HTML span 拆分导致）
    # 注意：用 .{0,200}? 而不是 [^\d]{0,200}?，因为中间可能有 "10 minutes" 这类带数字的文本
    contextual_code_spaced = (
        r"(?:login\s+code|verification\s+code|verify\s+code|验证码)"
        r".{0,200}?"
        r"(?P<code>\d(?:\s*\d){5})(?!\d)"
    )

    # 连续 6 位数字的 fallback
    continuous_code = r"(?<!\d)(?P<code>\d{6})(?!\d)"

    return [
        # 规则1：发件人 + 主题双匹配，上下文验证码（数字间可能有空格）
        Extractor.from_strings(
            category="vmake",
            sender_pattern=sender,
            subject_pattern=subject,
            code_regex=contextual_code_spaced,
            priority=100,
        ),
        # 规则2：发件人匹配，正文直接找 6 位连续数字
        Extractor.from_strings(
            category="vmake",
            sender_pattern=sender,
            subject_pattern="*verification*|*code*|*verify*|*Vmake*",
            code_regex=continuous_code,
            priority=50,
        ),
        # 规则3：主题含 Vmake，发件人被改写时兜底（上下文验证码）
        Extractor.from_strings(
            category="vmake",
            sender_pattern="",
            subject_pattern="*Vmake*|*vmake.ai*",
            code_regex=contextual_code_spaced,
            priority=10,
        ),
    ]
