# -*- coding: utf-8 -*-
"""
Microsoft OAuth2 access_token 获取 / 刷新封装。

复用同一个 access_token 直到过期；并在服务器返回新的 refresh_token 时通过回调
持久化（防止 sliding refresh token 失效）。
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Optional, Tuple

import certifi
import requests

from core.oauth2_helper import TOKEN_URL


logger = logging.getLogger(__name__)


# Token 过期时间提前量（秒），用于减少边界期失败
TOKEN_EXPIRY_BUFFER = 60


class TokenManager:
    """单账号 OAuth token 管理。"""

    def __init__(
        self,
        client_id: str,
        refresh_token: str,
        on_token_refresh: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.client_id = client_id
        self.refresh_token = refresh_token
        self._on_refresh = on_token_refresh

        self._access_token: Optional[str] = None
        self._expires_at: float = 0.0
        self.api_type: str = "graph"  # "graph" | "outlook"
        self.scopes: list[str] = []   # 上次刷新拿到的 scope 列表

    def has_scope(self, fragment: str) -> bool:
        """模糊匹配 scope（如 'Mail.ReadWrite' / 'IMAP' / 'SMTP'）。"""
        return any(fragment.lower() in s.lower() for s in self.scopes)

    def get(self) -> Tuple[Optional[str], str]:
        """返回 (access_token, message)。失败时第一项为 None。"""
        if not self.client_id or not self.refresh_token:
            return None, "缺少 client_id 或 refresh_token"

        now = time.time()
        if self._access_token and now < self._expires_at - TOKEN_EXPIRY_BUFFER:
            return self._access_token, "缓存命中"

        return self._refresh()

    def _refresh(self) -> Tuple[Optional[str], str]:
        try:
            resp = requests.post(
                TOKEN_URL,
                data={
                    "client_id": self.client_id,
                    "refresh_token": self.refresh_token,
                    "grant_type": "refresh_token",
                },
                timeout=30,
                verify=certifi.where(),
            )
        except requests.RequestException as exc:
            logger.exception("OAuth2 token 端点访问失败")
            return None, f"网络错误: {exc}"

        if resp.status_code != 200:
            try:
                err = resp.json().get("error_description", resp.text)
            except ValueError:
                err = resp.text
            return None, f"OAuth2 错误: {err}"

        data = resp.json()
        self._access_token = data.get("access_token")
        self._expires_at = time.time() + int(data.get("expires_in", 3600))

        # 服务端可能滚动签发新的 refresh_token
        new_rt = data.get("refresh_token")
        if new_rt and new_rt != self.refresh_token:
            self.refresh_token = new_rt
            if self._on_refresh:
                try:
                    self._on_refresh(self.client_id, new_rt)
                except Exception:
                    logger.exception("持久化新 refresh_token 失败")

        scope = data.get("scope", "") or ""
        self.scopes = [s for s in scope.split() if s]
        self.api_type = "outlook" if "outlook.office.com" in scope else "graph"

        return self._access_token, "获取成功"
