# -*- coding: utf-8 -*-
"""
RFC 822 邮件解析辅助：解码 header / 提取正文 / 附件检测。
"""

from __future__ import annotations

import logging
import re
from email.header import decode_header
from email.message import Message
from typing import Optional


logger = logging.getLogger(__name__)


MAX_BODY_BYTES = 200_000  # 给前端的正文长度上限，避免巨型 HTML 邮件拉爆传输


def decode_str(value: Optional[str]) -> str:
    """解码 RFC 2047 邮件头（=?charset?Q?xxx?=）。"""
    if not value:
        return ""
    parts = decode_header(value)
    out: list[str] = []
    for part, charset in parts:
        if isinstance(part, bytes):
            try:
                out.append(part.decode(charset or "utf-8", errors="ignore"))
            except (LookupError, UnicodeDecodeError):
                out.append(part.decode("utf-8", errors="ignore"))
        else:
            out.append(part)
    return "".join(out)


def extract_email_address(sender: str) -> str:
    """从 'Name <addr@x>' 中提取 addr@x；找不到尖括号时按整串包含 '@' 处理。"""
    if not sender:
        return ""
    m = re.search(r"<([^>]+)>", sender)
    if m:
        return m.group(1)
    return sender.strip() if "@" in sender else ""


def get_email_body(msg: Message) -> str:
    """提取纯文本正文（兼容旧调用），截断到 MAX_BODY_BYTES。"""
    body, _ = get_email_body_with_type(msg)
    return body


def get_email_body_with_type(msg: Message) -> tuple[str, str]:
    """提取邮件正文 + 类型标签 ("html" / "text")。

    优先返回 text/plain；如果没有 plain 部分则回退到 text/html。
    避免空白：只要任何一种 body 非空都会被采用。
    """
    text_body = ""
    html_body = ""

    def _decode(part: Message) -> str:
        try:
            charset = part.get_content_charset() or "utf-8"
            payload = part.get_payload(decode=True)
            if payload:
                return payload.decode(charset, errors="ignore")
        except (LookupError, UnicodeDecodeError, AttributeError):
            return ""
        return ""

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain" and not text_body:
                text_body = _decode(part)
            elif ctype == "text/html" and not html_body:
                html_body = _decode(part)
            if text_body and html_body:
                break
    else:
        decoded = _decode(msg)
        if msg.get_content_type() == "text/html":
            html_body = decoded
        else:
            text_body = decoded

    if text_body:
        return text_body[:MAX_BODY_BYTES], "text"
    if html_body:
        return html_body[:MAX_BODY_BYTES], "html"
    return "", "text"


def has_attachments(msg: Message) -> bool:
    if not msg.is_multipart():
        return False
    for part in msg.walk():
        if "attachment" in part.get("Content-Disposition", "") or "":
            return True
    return False
