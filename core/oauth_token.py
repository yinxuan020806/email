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
    """进程级 access_token 缓存条目。

    设计上**故意不缓存** ``refresh_token``：
    - RT 是服务端最高敏字段，进程内多副本会扩大 coredump / 内存取证风险
    - DB 才是 RT 的唯一可信来源；TokenManager 构造时已从 DB 读取了最新 RT
    - 多 worker 之间的 RT 同步靠 DB（``update_account_oauth``），不依赖进程缓存

    旧版多了 ``refresh_token: str`` 字段，让 worker B 可以从缓存中读到
    worker A 刷新得到的新 RT，但这只是性能优化（少一次 DB 读），代价是
    敏感数据在内存里多一处持有点。本轮按"安全优先于微优化"重新权衡。
    """
    access_token: str
    expires_at: float
    scopes: list = field(default_factory=list)
    api_type: str = "graph"


_TOKEN_CACHE: dict[tuple[str, str], _CachedToken] = {}
_TOKEN_LOCK = threading.Lock()

# Per-key refresh 锁：相同 (client_id, rt_hash) 同时刷新只放一个线程过去打 token
# 端点，其它等待者在锁释放后直接读缓存。避免被 Microsoft 风控 / 部分服务商拒收
# 重复请求。锁本身的获取受 _REFRESH_LOCKS_GUARD 保护。
_REFRESH_LOCKS: dict[tuple[str, str], threading.Lock] = {}
_REFRESH_LOCKS_GUARD = threading.Lock()


def _cache_key(client_id: str, refresh_token: str) -> tuple[str, str]:
    """用 hash 而不是明文 RT 当 key，避免内存里持有完整副本。

    用完整 SHA-256 hex（64 字符）。旧版截到 16 字符（64 bit），按生日攻击
    估算 ~2^32 个不同 RT 后碰撞概率显著上升 —— 服务运行多年累计 RT 量
    并不一定低于这个量级（每次 OAuth 刷新若服务端滚动签发新 RT 都会落库）。
    碰撞会让两个 RT 错误共享 access_token 缓存与 refresh 锁，最坏情况下
    一个用户的请求会拿到另一个用户的 access_token。完整 hex 把碰撞概率
    压到天文数字，开销只是 dict key 多 48 字节，可忽略。
    """
    rt_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    return (client_id, rt_hash)


def _get_refresh_lock(key: tuple[str, str]) -> threading.Lock:
    """惰性创建该 key 的 refresh 锁（singleflight 模式）。"""
    with _REFRESH_LOCKS_GUARD:
        lk = _REFRESH_LOCKS.get(key)
        if lk is None:
            lk = threading.Lock()
            _REFRESH_LOCKS[key] = lk
        return lk


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
        """把进程级缓存条目同步到当前实例。

        缓存条目不再持有 ``refresh_token`` —— 见 ``_CachedToken`` docstring。
        因此这里也不再做"用缓存里的新 RT 覆盖实例 RT"的同步逻辑。
        每个实例的 RT 由构造它的调用方（通常是 ``EmailClient(refresh_token=...)``）
        从 DB 读出来传入；DB 才是 RT 唯一真相。
        """
        self._access_token = entry.access_token
        self._expires_at = entry.expires_at
        self.scopes = list(entry.scopes)
        self.api_type = entry.api_type

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
        """返回 (access_token, message)。失败时第一项为 None。

        缓存检查顺序（按廉价度从高到低）：
        1. 实例级 ``self._access_token`` —— 同一个 ``EmailClient`` 在一次 batch
           检测里被复用时无锁直读；也允许测试通过 ``c._token_manager._access_token =
           ...`` 注入（perf commit 后曾被忽视，是 baseline 失败的根源）
        2. 进程级 ``_TOKEN_CACHE`` —— 跨 ``EmailClient`` 实例共享，仅持锁读字典
        3. 都 miss → 走 ``_refresh()``，内部用 per-key lock + double-check 保证
           同一 RT 的 N 个并发只放一个去打 token endpoint
        """
        if not self.client_id or not self.refresh_token:
            return None, "缺少 client_id 或 refresh_token"

        now = time.time()

        # 实例级（最廉价路径，无锁）
        if (
            self._access_token
            and now < self._expires_at - TOKEN_EXPIRY_BUFFER
        ):
            return self._access_token, "缓存命中(实例级)"

        # 进程级
        with _TOKEN_LOCK:
            entry = _TOKEN_CACHE.get(self._cache_key())
        if entry and now < entry.expires_at - TOKEN_EXPIRY_BUFFER:
            self._apply_cache_entry(entry)
            return self._access_token, "缓存命中(进程级)"

        return self._refresh()

    def _refresh(self) -> Tuple[Optional[str], str]:
        """singleflight：同一 (client_id, RT) 的并发刷新只放一个线程过去。

        N 个 web 请求同时 cache miss 时若不去重，会在 ~10ms 内连发 N 次
        token 请求；Microsoft 对同 RT 短时大量 refresh 会风控（observed
        invalid_grant 误报），影响真正可用率。
        """
        key = self._cache_key()
        lock = _get_refresh_lock(key)
        with lock:
            # double-check：可能在排队等锁时另一线程已刷过
            now = time.time()
            with _TOKEN_LOCK:
                entry = _TOKEN_CACHE.get(key)
            if entry and now < entry.expires_at - TOKEN_EXPIRY_BUFFER:
                self._apply_cache_entry(entry)
                return self._access_token, "缓存命中(并发去重)"

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
                # 微软在 5xx / WAF 拦截时可能返回 HTML / 空体，resp.json() 会抛
                try:
                    err = resp.json().get("error_description", resp.text)
                except ValueError:
                    err = (resp.text or f"HTTP {resp.status_code}")[:300]
                return None, f"OAuth2 错误: {err}"

            try:
                data = resp.json()
            except ValueError:
                return None, "Token 端点返回了非 JSON 响应"
            self._access_token = data.get("access_token")
            self._expires_at = time.time() + int(data.get("expires_in", 3600))

            # 服务端可能滚动签发新 refresh_token。持久化失败时**绝不**
            # 把新 RT 写到内存缓存里，原因：
            # - DB 仍是旧 RT，下次刷新仍用旧 RT；微软对 sliding RT 是
            #   "新 RT 颁发 = 旧 RT 立即失效"，下一次刷新会拿到 invalid_grant
            # - 如果此时缓存里写了"新 RT 已生效"的状态，其他 worker 命中
            #   该缓存就会延续这个错误前提，让运维更难定位
            # - 相反，写缓存失败让缓存暂时只存 access_token，下次过期触发
            #   刷新时会再走一遍此路径，要么持久化恢复（DB 恢复正常），
            #   要么连续失败（运维通过 ERROR 日志感知）
            new_rt = data.get("refresh_token")
            persisted_ok = True
            if new_rt and new_rt != self.refresh_token:
                if self._on_refresh:
                    try:
                        self._on_refresh(self.client_id, new_rt)
                        self.refresh_token = new_rt
                    except Exception:
                        logger.error(
                            "持久化新 refresh_token 失败（保留旧 RT、跳过缓存写入）。"
                            "本次 access_token 已可用；下次刷新仍用旧 RT，可能因服务端"
                            "已将旧 RT 视为已用而失败，需运维介入恢复 DB 后用户重新登录。",
                            exc_info=True,
                        )
                        persisted_ok = False
                else:
                    # 没有持久化回调（单元测试或单进程场景）：仅更新内存
                    self.refresh_token = new_rt

            scope = data.get("scope", "") or ""
            self.scopes = [s for s in scope.split() if s]
            self.api_type = "outlook" if "outlook.office.com" in scope else "graph"

            # 持久化失败时不写进程级缓存（避免其他 worker 看到"新 RT 已生效"
            # 的错觉）；本次返回的 access_token 仍可用
            if persisted_ok:
                with _TOKEN_LOCK:
                    _TOKEN_CACHE[key] = _CachedToken(
                        access_token=self._access_token,
                        expires_at=self._expires_at,
                        scopes=list(self.scopes),
                        api_type=self.api_type,
                    )

            return self._access_token, "获取成功"


def clear_token_cache() -> int:
    """运维/测试用。返回清掉的条目数。

    同时清空 ``_REFRESH_LOCKS`` —— 否则该字典会随历史 RT 数无限累积
    （每个 unique RT 一个永不释放的 ``threading.Lock``），长期运行进程会
    缓慢吃内存。这里在清缓存时一并 reset，符合"重置整套 token 状态"语义。
    """
    with _TOKEN_LOCK:
        n = len(_TOKEN_CACHE)
        _TOKEN_CACHE.clear()
    with _REFRESH_LOCKS_GUARD:
        _REFRESH_LOCKS.clear()
    return n


def evict_expired_token_cache(now: Optional[float] = None) -> int:
    """仅删除已过期的缓存条目，保留仍有效的。

    适合后台定期任务调用（例如启动时 / 每小时），避免 ``_TOKEN_CACHE`` 随
    账号量线性增长。同时 GC 对应的 ``_REFRESH_LOCKS`` 项，避免内存泄漏。
    返回被清除的条数。
    """
    if now is None:
        now = time.time()
    expired_keys: list[tuple[str, str]] = []
    with _TOKEN_LOCK:
        for k, v in list(_TOKEN_CACHE.items()):
            if v.expires_at <= now:
                expired_keys.append(k)
                _TOKEN_CACHE.pop(k, None)
    if expired_keys:
        with _REFRESH_LOCKS_GUARD:
            for k in expired_keys:
                _REFRESH_LOCKS.pop(k, None)
    return len(expired_keys)
