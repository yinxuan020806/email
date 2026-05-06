# -*- coding: utf-8 -*-
"""Cursor 验证码 / Magic-Link 默认提取规则。

发件人参考（截至撰写时已知 + 历史曾用过的）：
    no-reply@cursor.sh   auth@cursor.sh
    no-reply@cursor.com
    notifications@cursor.com   notifications@cursor.sh
    no-reply@mail.cursor.sh / mail.cursor.com  （营销）

主题参考：
    "Verify your email"  "Sign in to Cursor"  "Your verification code"

Cursor 同时下发 6 位 OTP 与一个 magic link，二者任选其一即可登录。

教训（与 openai_chatgpt.py 同步修复）：早期 sender pattern 写死固定子域，
Cursor 多发邮件用 ``notifications.cursor.com`` 等新子域时**静默漏匹**，前台
只能拿到老邮件。改用 ``*@*.cursor.sh`` / ``*@*.cursor.com`` 涵盖所有子域。
"""

from __future__ import annotations

from extractors.base import Extractor


def default_rules() -> list[Extractor]:
    # 通配涵盖任意 cursor 子域 — 编译后形如 .*@.*\.cursor\.sh
    sender = (
        "*@cursor.sh|*@*.cursor.sh|"
        "*@cursor.com|*@*.cursor.com"
    )
    subject = "Cursor|Verify*|Sign in*|verification*|登录*|验证*|代码*|临时*"
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
        # 兜底 1：上下文版没匹中时，仅在主题已含 "verification/code" 才允许全文 \d{6}
        Extractor.from_strings(
            category="cursor",
            sender_pattern=sender,
            subject_pattern="*verification*|*code*|*verify*|*验证*|*临时*",
            code_regex=r"(?<!\d)(?P<code>\d{6})(?!\d)",
            priority=50,
        ),
        # 兜底 2：sender 完全漏匹（Cursor 切到新子域 / 第三方 ESP）但 subject
        # 明确含 Cursor 关键字 → 凭 subject 提码。优先级最低防误抓。
        Extractor.from_strings(
            category="cursor",
            sender_pattern="",
            subject_pattern="*Cursor*",
            code_regex=contextual_code,
            priority=10,
        ),
    ]
