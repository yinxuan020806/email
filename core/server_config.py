# -*- coding: utf-8 -*-
"""
邮件服务器配置 - 单一数据源

替代原来散布在 db_manager.py 和 email_client.py 中的 3 份服务器配置。
"""

from __future__ import annotations

from core.models import ServerProfile
from typing import Optional


# ── 服务器配置注册表 ──────────────────────────────────────────

_PROFILES: dict[str, ServerProfile] = {
    "outlook": ServerProfile(
        imap_host="outlook.office365.com",
        imap_port=993,
        smtp_host="smtp.office365.com",
        smtp_port=587,
        use_ssl=True,
    ),
    "gmail": ServerProfile(
        imap_host="imap.gmail.com",
        imap_port=993,
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        use_ssl=True,
    ),
    "qq": ServerProfile(
        imap_host="imap.qq.com",
        imap_port=993,
        smtp_host="smtp.qq.com",
        smtp_port=465,
        use_ssl=True,
    ),
    "163": ServerProfile(
        imap_host="imap.163.com",
        imap_port=993,
        smtp_host="smtp.163.com",
        smtp_port=465,
        use_ssl=True,
    ),
    "126": ServerProfile(
        imap_host="imap.126.com",
        imap_port=993,
        smtp_host="smtp.126.com",
        smtp_port=465,
        use_ssl=True,
    ),
    "sina": ServerProfile(
        imap_host="imap.sina.com",
        imap_port=993,
        smtp_host="smtp.sina.com",
        smtp_port=465,
        use_ssl=True,
    ),
    "yahoo": ServerProfile(
        imap_host="imap.mail.yahoo.com",
        imap_port=993,
        smtp_host="smtp.mail.yahoo.com",
        smtp_port=465,
        use_ssl=True,
    ),
}

# 域名 → 配置名映射
_DOMAIN_MAP: dict[str, str] = {
    "outlook.com": "outlook",
    "hotmail.com": "outlook",
    "live.com": "outlook",
    "msn.com": "outlook",
    "gmail.com": "gmail",
    "googlemail.com": "gmail",
    "qq.com": "qq",
    "foxmail.com": "qq",
    "163.com": "163",
    "126.com": "126",
    "sina.com": "sina",
    "sina.cn": "sina",
    "yahoo.com": "yahoo",
    "yahoo.co.jp": "yahoo",
}


def detect_server(email_addr: str) -> Optional[ServerProfile]:
    """根据邮箱地址自动识别服务器配置。

    匹配策略（严格优先精确）：
    1. 精确域名命中 _DOMAIN_MAP（如 outlook.com / gmail.com）
    2. 真子域命中（如 corp.gmail.com / mail.outlook.com）—— 用 ``endswith('.<key>')``
       而不是 ``startswith('outlook.')``，避免 ``outlook.evil.com`` 这类伪装域被
       路由到 Outlook 服务器（启用 OAuth 路径）

    Returns:
        ServerProfile 如果匹配，否则 None。
        返回 None 时调用方应使用 imap.{domain} / smtp.{domain} 作为默认值。
    """
    if not email_addr or "@" not in email_addr:
        return None
    domain = email_addr.rsplit('@', 1)[-1].lower()

    # 精确匹配
    if domain in _DOMAIN_MAP:
        return _PROFILES[_DOMAIN_MAP[domain]]

    # 真子域匹配（必须以 `.<key>` 结尾，而非 `<key>` 前缀）
    for suffix, profile_name in _DOMAIN_MAP.items():
        if domain.endswith('.' + suffix):
            return _PROFILES[profile_name]

    return None


def get_imap_smtp(email_addr: str) -> tuple[str, str]:
    """返回 (imap_server, smtp_server)，兼容原有 detect_server 接口。"""
    profile = detect_server(email_addr)
    if profile:
        return profile.imap_host, profile.smtp_host
    domain = email_addr.split('@')[-1].lower()
    return f'imap.{domain}', f'smtp.{domain}'


def get_smtp_config(email_addr: str) -> tuple[str, int]:
    """返回 (smtp_host, smtp_port)，替代 EmailClient.SMTP_SERVERS 和 get_smtp_server()。"""
    profile = detect_server(email_addr)
    if profile:
        return profile.smtp_host, profile.smtp_port
    domain = email_addr.split('@')[-1].lower()
    return f'smtp.{domain}', 587
