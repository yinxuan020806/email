# -*- coding: utf-8 -*-
"""
登录失败限流（in-memory，进程内有效）。

策略：
- 同一 (username + ip) 在 ``WINDOW`` 秒窗口内失败超过 ``MAX_FAILS`` 次则锁定。
- 锁定持续 ``LOCK_DURATION`` 秒，期间所有尝试一律拒绝。
- 登录成功立刻清空对应键，避免误锁定。

限制：
- 进程重启会丢失计数（不持久化）。生产环境多副本部署需换成 Redis。
- 不抗"分布式撞库"，但能挡日常脚本暴破。
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional, Tuple


WINDOW = 15 * 60          # 计数窗口：15 分钟
MAX_FAILS = 5             # 窗口内允许的失败次数
LOCK_DURATION = 15 * 60   # 触发后锁定时长：15 分钟


@dataclass
class _Entry:
    fails: Deque[float] = field(default_factory=deque)
    locked_until: float = 0.0


class LoginRateLimiter:
    """线程安全的内存限流器。

    自我维护策略：
    - 每隔 ``GC_INTERVAL`` 秒清理一次 ``_store``，删除"既无 lock 也无 valid fails"的死 entry，
      防止攻击者用大量随机 (username, ip) 组合让进程内存膨胀（DoS）。
    - GC 在 ``check / record_failure`` 路径中惰性触发，无需额外线程。
    """

    GC_INTERVAL: float = 60.0  # 最低 GC 间隔（秒）

    def __init__(
        self,
        max_fails: int = MAX_FAILS,
        window: int = WINDOW,
        lock_duration: int = LOCK_DURATION,
    ) -> None:
        self.max_fails = max_fails
        self.window = window
        self.lock_duration = lock_duration
        self._store: Dict[Tuple[str, str], _Entry] = {}
        self._lock = threading.Lock()
        self._last_gc: float = time.time()

    @staticmethod
    def _key(username: str, ip: str) -> Tuple[str, str]:
        return ((username or "").strip().lower(), (ip or "0.0.0.0").strip())

    def _maybe_gc_locked(self, now: float) -> None:
        """**调用方必须已持有 self._lock**。

        惰性 GC：超过 ``GC_INTERVAL`` 秒未清理时，扫一遍丢掉死 entry。
        死 entry = 锁定已结束 + 计数窗口内无失败记录。
        """
        if now - self._last_gc < self.GC_INTERVAL:
            return
        cutoff = now - self.window
        dead: list = []
        for k, e in self._store.items():
            still_locked = e.locked_until > now
            has_recent_fail = any(ts >= cutoff for ts in e.fails)
            if not still_locked and not has_recent_fail:
                dead.append(k)
        for k in dead:
            self._store.pop(k, None)
        self._last_gc = now

    def check(self, username: str, ip: str) -> Tuple[bool, int]:
        """检查是否允许尝试。返回 (allowed, retry_after_seconds)。"""
        now = time.time()
        key = self._key(username, ip)
        with self._lock:
            self._maybe_gc_locked(now)
            entry = self._store.get(key)
            if not entry:
                return True, 0
            if entry.locked_until > now:
                return False, int(entry.locked_until - now) + 1
            return True, 0

    def record_failure(self, username: str, ip: str) -> Tuple[bool, int]:
        """记录一次失败。返回 (locked_now, retry_after_seconds)。"""
        now = time.time()
        key = self._key(username, ip)
        with self._lock:
            self._maybe_gc_locked(now)
            entry = self._store.setdefault(key, _Entry())
            cutoff = now - self.window
            while entry.fails and entry.fails[0] < cutoff:
                entry.fails.popleft()
            entry.fails.append(now)
            if len(entry.fails) >= self.max_fails:
                entry.locked_until = now + self.lock_duration
                entry.fails.clear()
                return True, self.lock_duration
            return False, 0

    def record_success(self, username: str, ip: str) -> None:
        """登录成功：清空该键的计数。"""
        key = self._key(username, ip)
        with self._lock:
            self._store.pop(key, None)

    def reset(self) -> None:
        """测试或运维场景一键清空。"""
        with self._lock:
            self._store.clear()
            self._last_gc = time.time()

    def remaining_attempts(self, username: str, ip: str) -> Optional[int]:
        """返回剩余可尝试次数；锁定中返回 None。"""
        now = time.time()
        key = self._key(username, ip)
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                return self.max_fails
            if entry.locked_until > now:
                return None
            cutoff = now - self.window
            valid = sum(1 for ts in entry.fails if ts >= cutoff)
            return max(0, self.max_fails - valid)

    def size(self) -> int:
        """返回当前跟踪的会话数（测试 / 运维可见）。"""
        with self._lock:
            return len(self._store)


login_limiter = LoginRateLimiter()
