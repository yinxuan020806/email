# -*- coding: utf-8 -*-
"""
不同协议 / 邮件提供商的文件夹名称映射。
"""

from __future__ import annotations

from typing import Literal

FolderKey = Literal["inbox", "junk", "sent", "drafts", "deleted"]


FOLDER_MAP: dict[str, dict[str, str]] = {
    "graph": {
        "inbox": "inbox", "junk": "junkemail",
        "sent": "sentitems", "drafts": "drafts", "deleted": "deleteditems",
    },
    "outlook": {
        "inbox": "inbox", "junk": "junkemail",
        "sent": "sentitems", "drafts": "drafts", "deleted": "deleteditems",
    },
    "imap": {
        "inbox": "INBOX", "junk": "Junk",
        "sent": "Sent", "drafts": "Drafts", "deleted": "Deleted",
    },
    "imap_gmail": {
        "inbox": "INBOX", "junk": "[Gmail]/Spam",
        "sent": "[Gmail]/Sent Mail", "drafts": "[Gmail]/Drafts",
        "deleted": "[Gmail]/Trash",
    },
    "imap_qq": {
        "inbox": "INBOX", "junk": "Junk",
        "sent": "Sent Messages", "drafts": "Drafts", "deleted": "Deleted Messages",
    },
    "imap_163": {
        "inbox": "INBOX", "junk": "垃圾邮件",
        "sent": "已发送", "drafts": "草稿箱", "deleted": "已删除",
    },
}


def imap_folder_for(email_addr: str, folder_key: str) -> str:
    """根据邮箱域名挑 IMAP 文件夹映射表。"""
    domain = email_addr.split("@")[-1].lower()
    if "gmail" in domain:
        mapping = FOLDER_MAP["imap_gmail"]
    elif "qq.com" in domain or "foxmail" in domain:
        mapping = FOLDER_MAP["imap_qq"]
    elif "163.com" in domain or "126.com" in domain:
        mapping = FOLDER_MAP["imap_163"]
    else:
        mapping = FOLDER_MAP["imap"]
    return mapping.get(folder_key, folder_key)


def graph_folder_for(api_type: str, folder_key: str) -> str:
    """Graph / Outlook REST 共用同一套文件夹名（lowercase well-known name）。"""
    table = FOLDER_MAP.get(api_type, FOLDER_MAP["graph"])
    return table.get(folder_key, folder_key)
