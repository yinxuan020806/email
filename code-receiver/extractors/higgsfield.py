# -*- coding: utf-8 -*-
"""Higgsfield.AI 验证码默认提取规则。

发件人参考：
    Higgsfield.AI <noreply@higgsfield.ai>（display name 可能只有品牌名）

主题参考：
    "183762 is your verification code"

正文参考：
    Verification code
    Enter the following verification code when prompted:
    183762
"""

from __future__ import annotations

from extractors.base import Extractor


def default_rules() -> list[Extractor]:
    sender = "*@higgsfield.ai|*@*.higgsfield.ai"
    subject = "Higgsfield|verification*|Verify*|code*"
    contextual_code = (
        r"(?:code|verification|verify|验证码|验证|代码|otp)[^\d]{0,120}?"
        r"(?P<code>\d{6})(?!\d)"
    )
    return [
        Extractor.from_strings(
            category="higgsfield",
            sender_pattern=sender,
            subject_pattern=subject,
            code_regex=contextual_code,
            priority=100,
        ),
        Extractor.from_strings(
            category="higgsfield",
            sender_pattern=sender,
            subject_pattern="*verification*|*code*|*verify*",
            code_regex=r"(?<!\d)(?P<code>\d{6})(?!\d)",
            priority=50,
        ),
        Extractor.from_strings(
            category="higgsfield",
            sender_pattern="",
            subject_pattern="*Higgsfield*|*verification*code*",
            code_regex=contextual_code,
            priority=10,
        ),
    ]
