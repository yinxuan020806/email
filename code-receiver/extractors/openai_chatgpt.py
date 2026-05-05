# -*- coding: utf-8 -*-
"""OpenAI / ChatGPT 验证码 / Magic-Link 默认提取规则。

发件人参考：
    noreply@tm.openai.com   noreply@auth.openai.com   noreply@openai.com
主题参考：
    "Verify your email"  "Log in to OpenAI"  "Your ChatGPT verification code"

OpenAI 主推 magic link 一键登录，少数场景才下发 6 位 OTP。
我们同时收两条规则：高优先级先匹 link，未命中再退化匹 code。
"""

from __future__ import annotations

from extractors.base import Extractor


def default_rules() -> list[Extractor]:
    sender = "*@openai.com|*@tm.openai.com|*@auth.openai.com|*@mail.openai.com"
    subject_general = "OpenAI|ChatGPT|Verify*|Log in*|sign in*|verification*|登录*|验证*"
    contextual_code = (
        r"(?:code|verification|verify|验证码|验证)[^\d\n]{0,40}(?P<code>\d{6})(?!\d)"
    )
    link = r"(?P<link>https?://(?:[a-z0-9-]+\.)?(?:auth\.)?openai\.com/[^\s\"'>]+)"
    return [
        # 1) 优先 magic-link（OpenAI 主推）
        Extractor.from_strings(
            category="openai",
            sender_pattern=sender,
            subject_pattern=subject_general,
            link_regex=link,
            priority=100,
        ),
        # 2) 带上下文的 OTP（避免误抓邮件中的其他数字）
        Extractor.from_strings(
            category="openai",
            sender_pattern=sender,
            subject_pattern=subject_general,
            code_regex=contextual_code,
            priority=80,
        ),
        # 3) 主题已明确是验证码邮件时的 6 位数字兜底
        Extractor.from_strings(
            category="openai",
            sender_pattern=sender,
            subject_pattern="*verification*|*code*|*verify*|*验证*",
            code_regex=r"(?<!\d)(?P<code>\d{6})(?!\d)",
            priority=50,
        ),
    ]
