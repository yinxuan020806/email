# -*- coding: utf-8 -*-
"""Nim (nim.video) 登录验证码默认提取规则。

Nim 登录走自有后端邮箱 OTP，前端一次输入 6 位数字。实测发信：

发件人参考：
    Nim <security@nim.video>
    （品牌域也可能是 *@nim.video / *@*.nim.video）

主题参考：
    "476834 – verification code"

正文参考（HTML）：
    Your verification code
    476834
    This code expires in 3 minutes.
    If you did not request this code, you can safely ignore this email.
"""

from __future__ import annotations

from extractors.base import Extractor


def default_rules() -> list[Extractor]:
    sender = "*@nim.video|*@*.nim.video"
    subject = "Nim|verification*|Verify*|code*|验证*|登录*"
    contextual_code = (
        r"(?:code|verification|verify|验证码|验证|代码|otp)"
        r"[^\d]{0,120}?(?P<code>\d{6})(?!\d)"
    )
    return [
        Extractor.from_strings(
            category="nimvideo",
            sender_pattern=sender,
            subject_pattern=subject,
            code_regex=contextual_code,
            priority=100,
        ),
        # 主题已是 "{6 位} – verification code" 时，码在关键词前面
        Extractor.from_strings(
            category="nimvideo",
            sender_pattern=sender,
            subject_pattern="*verification*|*code*|*verify*|*验证*|*Nim*",
            code_regex=r"(?<!\d)(?P<code>\d{6})(?!\d)",
            priority=50,
        ),
        # 发件人被改写时：主题含 Nim + 上下文验证码
        Extractor.from_strings(
            category="nimvideo",
            sender_pattern="",
            subject_pattern="*Nim*|*nim.video*",
            code_regex=contextual_code,
            priority=10,
        ),
    ]
