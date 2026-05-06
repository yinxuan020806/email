# -*- coding: utf-8 -*-
"""OpenAI / ChatGPT 验证码 / Magic-Link 默认提取规则。

发件人参考（截至撰写时已知 + 历史曾用过的）：
    noreply@openai.com         （根域）
    noreply@tm.openai.com      （历史）
    noreply@auth.openai.com    （登录类）
    noreply@email.openai.com   （营销 / 通知，2025+ 切换的子域）
    noreply@mail.openai.com    （历史）
    noreply@accounts.openai.com（少见）

主题参考：
    "Verify your email"  "Log in to OpenAI"  "Your ChatGPT verification code"
    "您的临时 ChatGPT 登录代码" / "您的临时 ChatGPT 验证码"（中文模板）

OpenAI 主推 magic link 一键登录，少数场景才下发 6 位 OTP。
我们同时收两条规则：高优先级先匹 link，未命中再退化匹 code。

教训：早期 sender pattern 写死 4 个固定子域（tm/auth/mail/openai.com）。
当 OpenAI 切到 ``email.openai.com`` 后这条规则**静默漏匹**，前台只能拿到
更老的 ``tm.openai.com`` 邮件，看起来像"接码取到的不是最新"——实际是
extractor 跳过了最新邮件回退到老邮件。修复：用通配 ``*@*.openai.com``
覆盖任意子域。
"""

from __future__ import annotations

from extractors.base import Extractor


def default_rules() -> list[Extractor]:
    # 通配涵盖任意 openai.com 子域：``*@openai.com`` 匹配根域，
    # ``*@*.openai.com`` 匹配 ``xxx@<任意子域>.openai.com``。
    # 编译后形如 ``.*@.*\.openai\.com``——能命中 email.openai.com / tm.openai.com /
    # auth.openai.com / accounts.openai.com 等所有 OpenAI 自家域名。
    sender = "*@openai.com|*@*.openai.com"
    subject_general = (
        "OpenAI|ChatGPT|Verify*|Log in*|sign in*|verification*|"
        "登录*|验证*|代码*|临时*"
    )
    contextual_code = (
        r"(?:code|verification|verify|验证码|验证|代码|otp)[^\d]{0,80}?"
        r"(?P<code>\d{6})(?!\d)"
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
            subject_pattern="*verification*|*code*|*verify*|*验证*|*临时*",
            code_regex=r"(?<!\d)(?P<code>\d{6})(?!\d)",
            priority=50,
        ),
        # 4) 终极兜底：sender 完全没匹中（OpenAI 又开了个新子域 / 转 ESP），
        # 但 subject 明确含 ChatGPT/OpenAI 关键字 → 凭 subject 提码。
        # 这条优先级最低，确保它只在前 3 条都漏的情况下才生效，避免误抓。
        Extractor.from_strings(
            category="openai",
            sender_pattern="",  # 不限发件人
            subject_pattern="*ChatGPT*|*OpenAI*",
            code_regex=contextual_code,
            priority=10,
        ),
    ]
