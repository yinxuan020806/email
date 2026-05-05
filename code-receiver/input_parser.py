# -*- coding: utf-8 -*-
"""用户输入凭据解析。

支持的 5 种输入格式（用 ``----`` 分隔，或仅邮箱地址）::

    1. email                                              # 仅邮箱（要求 is_public 公开账号）
    2. email----password                                  # 邮箱 + IMAP 密码 / Gmail 应用专用密码 / Yahoo 授权码
    3. email----password----extra                         # 第 3 段当作"备注/分组"忽略，不影响协议
    4. email----password----client_id----refresh_token    # Outlook OAuth2（4 段）
    5. email----client_id----refresh_token                # Outlook OAuth2 无密码变体（3 段，第 2 段以 - 开头或 UUID）

复用 ``email/web_app.py:parse_import_text`` 的核心策略，但前台只接受
**单条输入**，故剥离了多账号 / ``$$`` 拼接 / 组名启发式那部分。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


@dataclass
class ParsedCredential:
    """解析后的凭据（绝不可序列化进日志）。"""

    email: str
    password: str = ""
    client_id: Optional[str] = None
    refresh_token: Optional[str] = None
    is_oauth: bool = False
    needs_lookup: bool = False
    """True 表示用户只输入了邮箱地址，需要去 DB 查 is_public 的公开账号。"""

    def __repr__(self) -> str:
        masked_pwd = "***" if self.password else ""
        masked_rt = "***" if self.refresh_token else ""
        return (
            f"ParsedCredential(email={self.email!r}, password={masked_pwd!r}, "
            f"client_id={self.client_id!r}, refresh_token={masked_rt!r}, "
            f"is_oauth={self.is_oauth}, needs_lookup={self.needs_lookup})"
        )


class InputParseError(ValueError):
    """输入格式不合法。"""


def _looks_like_uuid(s: str) -> bool:
    return bool(_UUID_RE.match(s.strip()))


def parse_user_input(text: str) -> ParsedCredential:
    """解析单行用户输入；若无法识别返回 InputParseError。"""
    if not text or not text.strip():
        raise InputParseError("输入为空")

    raw = text.strip()
    fields = [f.strip() for f in raw.split("----")]
    if not fields:
        raise InputParseError("无法解析")

    email = fields[0]
    if not _EMAIL_RE.match(email):
        raise InputParseError("第一段不是合法邮箱地址")

    n = len(fields)
    if n == 1:
        return ParsedCredential(email=email, needs_lookup=True)

    if n == 2:
        return ParsedCredential(email=email, password=fields[1])

    if n == 3:
        # 两种可能：(email, password, 备注) 或 (email, client_id, refresh_token)
        # 用第 2 段是不是 UUID 来区分 — Azure AD client_id 一定是 UUID。
        if _looks_like_uuid(fields[1]):
            return ParsedCredential(
                email=email,
                password="",
                client_id=fields[1],
                refresh_token=fields[2],
                is_oauth=True,
            )
        # 否则按 (email, password, 第 3 段忽略) 处理
        return ParsedCredential(email=email, password=fields[1])

    if n >= 4:
        # 标准 4 段：email, password, client_id, refresh_token；多余的字段忽略
        if _looks_like_uuid(fields[2]):
            return ParsedCredential(
                email=email,
                password=fields[1],
                client_id=fields[2],
                refresh_token=fields[3],
                is_oauth=True,
            )
        return ParsedCredential(email=email, password=fields[1])

    raise InputParseError("无法识别的输入格式")  # pragma: no cover
