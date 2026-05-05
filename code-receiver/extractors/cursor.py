# -*- coding: utf-8 -*-
"""Cursor 验证码 / Magic-Link 默认提取规则。

发件人参考（截至撰写时）：
    no-reply@cursor.sh   auth@cursor.sh   no-reply@cursor.com
主题参考：
    "Verify your email"  "Sign in to Cursor"  "Your verification code"

Cursor 同时下发 6 位 OTP 与一个 magic link，二者任选其一即可登录。
"""

from __future__ import annotations

from extractors.base import Extractor


def default_rules() -> list[Extractor]:
    sender = "*@cursor.sh|*@cursor.com|*@mail.cursor.sh|*@mail.cursor.com"
    subject = "Cursor|Verify*|Sign in*|verification*|登录*|验证*|代码*"
    # 关键词触发后允许 80 字符（跨换行、跨 HTML 标签 strip 后的空格）再抓 6 位数
    # 避免误抓订单号；非贪婪 ? 抓"最近"的 6 位数字
    contextual_code = (
        r"(?:code|verification|verify|验证码|验证|代码|otp)[^\d]{0,80}?"
        r"(?P<code>\d{6})(?!\d)"
    )
    link = r"(?P<link>https?://(?:[a-z0-9-]+\.)?cursor\.(?:sh|com)/[^\s\"'>]+)"
    return [
        Extractor.from_strings(
            category="cursor",
            sender_pattern=sender,
            subject_pattern=subject,
            code_regex=contextual_code,
            link_regex=link,
            priority=100,
        ),
        # 兜底规则：上下文版没匹中时，仅在主题已含 "verification/code" 才允许全文 \d{6}
        Extractor.from_strings(
            category="cursor",
            sender_pattern=sender,
            subject_pattern="*verification*|*code*|*verify*|*验证*",
            code_regex=r"(?<!\d)(?P<code>\d{6})(?!\d)",
            priority=50,
        ),
    ]
