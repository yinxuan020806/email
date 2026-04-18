# -*- coding: utf-8 -*-
"""日志脱敏工具：邮箱地址、token 等不应明文出现在日志中。"""

from __future__ import annotations

from typing import Optional


def mask_email(addr: Optional[str]) -> str:
    """ab***@example.com 风格脱敏。"""
    if not addr or "@" not in addr:
        return "***"
    user, domain = addr.split("@", 1)
    if len(user) <= 2:
        masked_user = user[:1] + "***"
    else:
        masked_user = user[:2] + "***"
    return f"{masked_user}@{domain}"


def mask_token(token: Optional[str]) -> str:
    """前 4 + 后 4 字符可见，中间 *** 替换。"""
    if not token:
        return "***"
    if len(token) <= 8:
        return "***"
    return f"{token[:4]}***{token[-4:]}"
