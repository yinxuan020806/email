# -*- coding: utf-8 -*-
"""
Microsoft OAuth2 access_token 获取 / 刷新封装。

复用同一个 access_token 直到过期；并在服务器返回新的 refresh_token 时通过回调
持久化（防止 sliding refresh token 失效）。
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Tuple

import certifi
import requests
from requests.adapters import HTTPAdapter

from core.oauth2_helper import TOKEN_URL


logger = logging.getLogger(__name__)


# Token 过期时间提前量（秒），用于减少边界期失败
TOKEN_EXPIRY_BUFFER = 60


# ── 进程级共享 HTTP Session ─────────────────────────────────
# requests.Session 默认带 connection pooling，能复用 TLS 连接，避免每次请求重新
# 握手（约 100-300ms）。oauth_token / graph_client 共享同一个 session。
SESSION = requests.Session()
_adapter = HTTPAdapter(pool_connections=20, pool_maxsize=50, max_retries=0)
SESSION.mount("https://", _adapter)
SESSION.mount("http://", _adapter)


# ── 进程级 access_token 缓存 ────────────────────────────────
# 之前每次 web 请求都创建新 EmailClient → 新 TokenManager → access_token 缓存为空，
# 每次都要去 Microsoft 跨海刷新一次 (~500-1000ms)，这是最大隐藏开销。
# 这里按 (client_id, refresh_token) 维度做进程级缓存，所有请求共享。

@dataclass
class _CachedToken:
    access_token: str
    expires_at: float
    scopes: list = field(default_factory=list)
    api_type: str = "graph"
    refresh_token: str = ""   # 服务端可能滚动签发新 RT


_TOKEN_CACHE: dict[tuple[str, str], _CachedToken] = {}
_TOKEN_LOCK = threading.Lock()


def _cache_key(client_id: str, refresh_token: str) -> tuple[str, str]:
    """用 hash 而不是明文 RT 当 key，避免内存里持有完整副本。"""
    rt_hash = hashlib.sha256(refresh_token.encode()).hexdigest()[:16]
    return (client_id, rt_hash)


class TokenManager:
    """单账号 OAuth token 管理（进程级共享缓存）。"""

    def __init__(
        self,
        client_id: str,
        refresh_token: str,
        on_token_refresh: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.client_id = client_id
        self.refresh_token = refresh_token
        # 缓存 key 始终用最初构造时的 RT，避免服务端滚动签发新 RT 后导致
        # 后续基于 DB 旧 RT 构造的 TokenManager 缓存 miss
        self._initial_refresh_token = refresh_token
        self._on_refresh = on_token_refresh

        # 仍然保留实例级字段以保持向后兼容（has_scope / api_type 访问者）
        self._access_token: Optional[str] = None
        self._expires_at: float = 0.0
        self.api_type: str = "graph"
        self.scopes: list[str] = []

        # 启动时尝试从全局缓存恢复
        self._try_warm_from_cache()

    def _cache_key(self) -> tuple[str, str]:
        return _cache_key(self.client_id, self._initial_refresh_token)

    def _apply_cache_entry(self, entry: "_CachedToken") -> None:
        self._access_token = entry.access_token
        self._expires_at = entry.expires_at
        self.scopes = list(entry.scopes)
        self.api_type = entry.api_type
        if entry.refresh_token and entry.refresh_token != self.refresh_token:
            self.refresh_token = entry.refresh_token

    def _try_warm_from_cache(self) -> None:
        if not self.client_id or not self._initial_refresh_token:
            return
        with _TOKEN_LOCK:
            entry = _TOKEN_CACHE.get(self._cache_key())
        if entry and time.time() < entry.expires_at - TOKEN_EXPIRY_BUFFER:
            self._apply_cache_entry(entry)

    def has_scope(self, fragment: str) -> bool:
        """模糊匹配 scope（如 'Mail.ReadWrite' / 'IMAP' / 'SMTP'）。"""
        return any(fragment.lower() in s.lower() for s in self.scopes)

    def get(self) -> Tuple[Optional[str], str]:
        """返回 (access_token, message)。失败时第一项为 None。"""
        if not self.client_id or not self.refresh_token:
            return None, "缺少 client_id 或 refresh_token"

        now = time.time()

        # 先看进程级缓存（其他 EmailClient 实例可能已经刷新过）
        with _TOKEN_LOCK:
            entry = _TOKEN_CACHE.get(self._cache_key())
        if entry and now < entry.expires_at - TOKEN_EXPIRY_BUFFER:
            self._apply_cache_entry(entry)
            return self._access_token, "缓存命中(进程级)"

        return self._refresh()

    def _refresh(self) -> Tuple[Optional[str], str]:
        try:
            resp = SESSION.post(
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

        # 写回进程级缓存（key 用初始 RT，便于其他用旧 RT 构造的实例命中）
        with _TOKEN_LOCK:
            _TOKEN_CACHE[self._cache_key()] = _CachedToken(
                access_token=self._access_token,
                expires_at=self._expires_at,
                scopes=list(self.scopes),
                api_type=self.api_type,
                refresh_token=self.refresh_token,
            )

        return self._access_token, "获取成功"


def clear_token_cache() -> int:
    """运维/测试用。返回清掉的条目数。"""
    with _TOKEN_LOCK:
        n = len(_TOKEN_CACHE)
        _TOKEN_CACHE.clear()
    return n
