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

    def get_auth_url(self, email: str = "", state: Optional[str] = None) -> str:
        """构造 Microsoft OAuth2 授权 URL。

        ``state`` 留空会随机生成（向后兼容老调用）。生产代码应**显式**传入
        服务端记录的 state（绑定到当前登录会话），并在 ``/api/oauth2/exchange``
        中校验 redirect_url 中返回的 state 与服务端记录一致，防止：
        - CSRF：攻击者诱导受害者完成授权后把 RT 绑到攻击者账号；
        - 跨标签污染：用户连续打开两次授权流时混用 code。
        服务端记录可以是短期内存（见 ``web_app._pending_oauth_states``）或
        签名 cookie。
        """
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "response_mode": "query",
            "scope": " ".join(SCOPES),
            "state": state or secrets.token_urlsafe(16),
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
                # 微软在 5xx / WAF 拦截时可能返回 HTML 或空响应，resp.json() 会抛 ValueError
                try:
                    err = resp.json().get("error_description", resp.text)
                except ValueError:
                    err = (resp.text or f"HTTP {resp.status_code}")[:300]
                return None, None, f"获取 Token 失败: {err}"
            try:
                payload = resp.json()
            except ValueError:
                return None, None, "Token 端点返回了非 JSON 响应"
            refresh_token = payload.get("refresh_token")
            if not refresh_token:
                return None, None, "服务器未返回 refresh_token"
            return self.client_id, refresh_token, None
        except requests.RequestException as exc:
            logger.exception("OAuth2 网络异常")
            return None, None, f"网络错误: {exc}"
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            # ValueError: parse_qs / urlparse 收到畸形 URL（含控制字符等）
            # KeyError / IndexError: qs 缺少 code
            # TypeError: redirect_url 不是 str
            # 其它未列出的 Exception 让它向上抛，由 FastAPI 落在 500 + 完整堆栈日志，
            # 这样运维能看到真正的代码 bug，而不是被一个 "授权过程出错: ..." 字符串遮蔽。
            logger.exception("OAuth2 解析异常")
            return None, None, f"授权过程出错: {type(exc).__name__}"
