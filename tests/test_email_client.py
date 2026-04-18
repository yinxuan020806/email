# -*- coding: utf-8 -*-
"""EmailClient Facade 路由判断测试（不依赖网络）。"""

from __future__ import annotations

from core.email_client import EmailClient
from core.folder_map import imap_folder_for, graph_folder_for


def test_outlook_with_oauth_initializes_token_manager():
    c = EmailClient(
        "user@outlook.com", "",
        client_id="cid", refresh_token="rt",
    )
    assert c._token_manager is not None  # noqa: SLF001
    assert c._graph is not None          # noqa: SLF001  Graph 备用通道
    # IMAP 应携带 token_manager 走 XOAUTH2
    assert c._imap.token_manager is c._token_manager  # noqa: SLF001


def test_gmail_uses_imap_password_even_with_oauth_args():
    """非 Outlook 域名，即使提供 client_id 也走 IMAP 密码登录。"""
    c = EmailClient(
        "user@gmail.com", "pwd",
        client_id="cid", refresh_token="rt",
    )
    assert c._graph is None              # noqa: SLF001
    assert c._token_manager is None      # noqa: SLF001
    assert c._imap.token_manager is None # noqa: SLF001


def test_outlook_without_oauth_falls_back_to_imap_password():
    c = EmailClient("user@outlook.com", "pwd")
    assert c._graph is None          # noqa: SLF001
    assert c._token_manager is None  # noqa: SLF001


def test_oauth_writes_route_to_imap_when_no_readwrite_scope():
    """token 仅有 IMAP/SMTP scope 时，删除/标记应路由到 IMAP，避免 Graph 403。"""
    c = EmailClient(
        "user@outlook.com", "",
        client_id="cid", refresh_token="rt",
    )
    # 模拟 token_manager 已刷新过但只有 IMAP scope
    c._token_manager._access_token = "fake"  # noqa: SLF001
    c._token_manager._expires_at = 9_999_999_999  # noqa: SLF001
    c._token_manager.scopes = [  # noqa: SLF001
        "https://outlook.office.com/IMAP.AccessAsUser.All",
        "https://outlook.office.com/SMTP.Send",
    ]
    assert c._can_use_graph_for_writes() is False  # noqa: SLF001


def test_oauth_writes_route_to_graph_when_readwrite_scope_present():
    c = EmailClient(
        "user@outlook.com", "",
        client_id="cid", refresh_token="rt",
    )
    c._token_manager._access_token = "fake"  # noqa: SLF001
    c._token_manager._expires_at = 9_999_999_999  # noqa: SLF001
    c._token_manager.scopes = ["Mail.ReadWrite"]  # noqa: SLF001
    assert c._can_use_graph_for_writes() is True  # noqa: SLF001


def test_folder_map_gmail():
    assert imap_folder_for("user@gmail.com", "junk") == "[Gmail]/Spam"
    assert imap_folder_for("user@gmail.com", "sent") == "[Gmail]/Sent Mail"


def test_folder_map_qq():
    assert imap_folder_for("u@qq.com", "sent") == "Sent Messages"


def test_folder_map_163():
    assert imap_folder_for("u@163.com", "junk") == "垃圾邮件"


def test_folder_map_outlook_imap_default():
    assert imap_folder_for("u@outlook.com", "inbox") == "INBOX"


def test_folder_map_unknown_key_passthrough():
    assert imap_folder_for("u@gmail.com", "unknown") == "unknown"


def test_graph_folder_map():
    assert graph_folder_for("graph", "junk") == "junkemail"
    assert graph_folder_for("outlook", "deleted") == "deleteditems"
