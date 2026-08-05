# -*- coding: utf-8 -*-
"""Hedra 验证码默认提取规则。

Hedra 登录走 WorkOS AuthKit Magic Auth / Email Verification：

发件人参考：
    Hedra <access@workos-mail.com>   # Magic Auth 登录 OTP
    Hedra <welcome@workos-mail.com>  # 注册邮箱验证 OTP
    （若配置自定义域名也可能是 access@hedra.com / welcome@hedra.com）

主题参考：
    "登录 Hedra"
    "Verify your email address"
    "Sign in to Hedra" / "Log in to Hedra"

正文参考（中文 Magic Auth）：
    您的一次性验证码是 287985。此验证码将在 10 分钟后过期。
    ...
    由 WorkOS 代表 Hedra 发送的邮件。

正文参考（英文 Email Verification）：
    Your verification code is 134551. This code expires in 10 minutes.
"""

from __future__ import annotations

from extractors.base import Extractor


def default_rules() -> list[Extractor]:
    # WorkOS 默认域 + Hedra 自有域（自定义发信时）
    sender = (
        "*@workos-mail.com|*@*.workos-mail.com|"
        "*@hedra.com|*@*.hedra.com"
    )
    subject = "Hedra|登录*|Sign*in*|Log*in*|Verify*|验证*|code*|Magic*"
    contextual_code = (
        r"(?:code|verification|verify|一次性验证码|验证码|验证|代码|otp)"
        r"[^\d]{0,120}?(?P<code>\d{6})(?!\d)"
    )
    return [
        Extractor.from_strings(
            category="hedra",
            sender_pattern=sender,
            subject_pattern=subject,
            code_regex=contextual_code,
            priority=100,
        ),
        # subject/正文无关键词时，WorkOS 发件人 + 裸 6 位数字兜底
        Extractor.from_strings(
            category="hedra",
            sender_pattern=sender,
            subject_pattern="*Hedra*|*Verify*|*登录*|*Sign*|*code*",
            code_regex=r"(?<!\d)(?P<code>\d{6})(?!\d)",
            priority=50,
        ),
        # 发件人被改写时：主题含 Hedra + 上下文验证码
        Extractor.from_strings(
            category="hedra",
            sender_pattern="",
            subject_pattern="*Hedra*",
            code_regex=contextual_code,
            priority=10,
        ),
    ]
