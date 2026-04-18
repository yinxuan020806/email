# -*- coding: utf-8 -*-
"""
OAuth2 授权助手 - 通过系统浏览器手动完成 Microsoft OAuth2 授权。

使用 Thunderbird 公开 client_id（仅供本地工具使用），最终通过 refresh_token
访问 IMAP / SMTP / Outlook REST。
"""

from __future__ import annotations

import logging
import os
import urllib.parse
import webbrowser
import secrets
from typing import Optional, Tuple

import certifi
import requests


logger = logging.getLogger(__name__)


# Thunderbird 公开 client_id，仅供个人本地工具使用；生产环境应自行注册 Azure 应用
# 并通过环境变量 EMAIL_OAUTH_CLIENT_ID 覆盖。
THUNDERBIRD_CLIENT_ID = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"


def get_default_client_id() -> str:
    """优先取环境变量 EMAIL_OAUTH_CLIENT_ID，否则用 Thunderbird 公开 ID。"""
    return os.getenv("EMAIL_OAUTH_CLIENT_ID", "").strip() or THUNDERBIRD_CLIENT_ID


def get_redirect_uri() -> str:
    """允许通过 EMAIL_OAUTH_REDIRECT_URI 覆盖回调地址（自托管 Azure 应用时常用）。"""
    return os.getenv("EMAIL_OAUTH_REDIRECT_URI", "").strip() or "https://localhost"


SCOPES = (
    "offline_access",
    "https://outlook.office.com/IMAP.AccessAsUser.All",
    "https://outlook.office.com/SMTP.Send",
)

TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"

# 兼容旧引用
REDIRECT_URI = get_redirect_uri()
DEFAULT_CLIENT_ID = get_default_client_id()


class OAuth2Helper:
    """轻量 OAuth2 助手：生成授权 URL、用 code 换 refresh_token。"""

    def __init__(self, client_id: Optional[str] = None) -> None:
        self.client_id = client_id or get_default_client_id()
        self.redirect_uri = get_redirect_uri()

    def get_auth_url(self, email: str = "") -> str:
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "response_mode": "query",
            "scope": " ".join(SCOPES),
            "state": secrets.token_urlsafe(16),
        }
        if email:
            params["login_hint"] = email
        return f"{AUTH_URL}?{urllib.parse.urlencode(params)}"

    def open_browser(self, email: str = "") -> str:
        url = self.get_auth_url(email)
        try:
            webbrowser.open(url)
        except Exception as exc:
            logger.warning("Failed to open browser: %s", exc)
        return url

    def exchange_code_for_token(
        self, redirect_url: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """从重定向 URL 中提取 code，调用 token 端点换取 refresh_token。

        Returns:
            (client_id, refresh_token, error_message)
        """
        try:
            parsed = urllib.parse.urlparse(redirect_url)
            qs = urllib.parse.parse_qs(parsed.query)
            if "code" not in qs:
                return None, None, "URL 中未找到授权码"

            data = {
                "client_id": self.client_id,
                "code": qs["code"][0],
                "redirect_uri": self.redirect_uri,
                "grant_type": "authorization_code",
                "scope": " ".join(SCOPES),
            }
            resp = requests.post(TOKEN_URL, data=data, timeout=30, verify=certifi.where())
            if resp.status_code != 200:
                err = resp.json().get("error_description", resp.text)
                return None, None, f"获取 Token 失败: {err}"
            refresh_token = resp.json().get("refresh_token")
            if not refresh_token:
                return None, None, "服务器未返回 refresh_token"
            return self.client_id, refresh_token, None
        except requests.RequestException as exc:
            logger.exception("OAuth2 网络异常")
            return None, None, f"网络错误: {exc}"
        except Exception as exc:
            logger.exception("OAuth2 解析异常")
            return None, None, f"授权过程出错: {exc}"
