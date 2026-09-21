# -*- coding: utf-8 -*-
"""freebeat.ai 登录验证码默认提取规则。

登录走自有后端邮箱 OTP（``POST /v1/user/com/sendEmailVerifyCodeV2``），
前端一次输入 6 位数字。实测发信：

发件人参考：
    freebeat support <support@notify.freebrio.com>
    （品牌域也可能是 *@freebeat.ai / *@*.freebeat.ai）

主题参考：
    "800543 is your verification code"

正文参考：
    Please enter this verification code to continue using freebeat:
    800543
    Verification codes expire after two hours.
"""

from __future__ import annotations

from extractors.base import Extractor


def default_rules() -> list[Extractor]:
    sender = (
        "*@notify.freebrio.com|*@*.freebrio.com|*@freebrio.com|"
        "*@freebeat.ai|*@*.freebeat.ai"
    )
    subject = "freebeat|freebrio|verification*|Verify*|code*|验证*|登录*"
    contextual_code = (
        r"(?:code|verification|verify|验证码|验证|代码|otp)[^\d]{0,120}?"
        r"(?P<code>\d{6})(?!\d)"
    )
    return [
        Extractor.from_strings(
            category="freebeat",
            sender_pattern=sender,
            subject_pattern=subject,
            code_regex=contextual_code,
            priority=100,
        ),
        # 主题已是 "{6 位} is your verification code" 时，码在关键词前面
        Extractor.from_strings(
            category="freebeat",
            sender_pattern=sender,
            subject_pattern="*verification*|*code*|*verify*|*验证*|*freebeat*",
            code_regex=r"(?<!\d)(?P<code>\d{6})(?!\d)",
            priority=50,
        ),
        Extractor.from_strings(
            category="freebeat",
            sender_pattern="",
            subject_pattern="*freebeat*|*freebrio*|*verification*code*",
            code_regex=contextual_code,
            priority=10,
        ),
    ]
