# -*- coding: utf-8 -*-
"""前台多维度限流。

策略：
- ``IP``：1 分钟 5 次 / 1 小时 30 次
- ``email``：1 小时 10 次（无视 IP，防对单邮箱密集打码）
- ``凭据失败``：连续 N 次失败 → 锁定 IP 1 小时（基于内存）

落库限流（IP / email 维度）由 ``CodeReceiverDB.count_queries_in_window`` 提供
持久化、跨进程一致的计数；失败锁定走内存（可接受重启后清空）。
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional


# 各窗口阈值（环境变量 CRX_RATE_* 可覆盖）
DEFAULT_IP_PER_MIN = 5
DEFAULT_IP_PER_HOUR = 30
DEFAULT_EMAIL_PER_HOUR = 10
DEFAULT_FAIL_LOCK_THRESHOLD = 3
DEFAULT_FAIL_LOCK_DURATION = 3600


class RateLimitDecision:
    __slots__ = ("allowed", "retry_after", "reason")

    def __init__(self, allowed: bool, retry_after: int = 0, reason: str = "") -> None:
        self.allowed = allowed
        self.retry_after = retry_after
        self.reason = reason


@dataclass
class _FailEntry:
    fails: Deque[float] = field(default_factory=deque)
    locked_until: float = 0.0


class FailureLocker:
    """登录失败锁定器（内存）。"""

    def __init__(
        self,
        threshold: int = DEFAULT_FAIL_LOCK_THRESHOLD,
        lock_duration: int = DEFAULT_FAIL_LOCK_DURATION,
        window: int = 600,
    ) -> None:
        self.threshold = threshold
        self.lock_duration = lock_duration
        self.window = window
        self._store: Dict[str, _FailEntry] = {}
        self._lock = threading.Lock()

    def is_locked(self, ip: str) -> tuple[bool, int]:
        # 用 monotonic 而非 wall clock，避免 NTP 跳变影响锁定窗口
        now = time.monotonic()
        with self._lock:
            entry = self._store.get(ip)
            if not entry or entry.locked_until <= now:
                return False, 0
            return True, int(entry.locked_until - now) + 1

    def record_failure(self, ip: str) -> None:
        now = time.monotonic()
        with self._lock:
            entry = self._store.setdefault(ip, _FailEntry())
            cutoff = now - self.window
            while entry.fails and entry.fails[0] < cutoff:
                entry.fails.popleft()
            entry.fails.append(now)
            if len(entry.fails) >= self.threshold:
                entry.locked_until = now + self.lock_duration
                entry.fails.clear()

    def record_success(self, ip: str) -> None:
        with self._lock:
            self._store.pop(ip, None)


class RateLimiter:
    """组合 DB 持久化计数 + 内存失败锁的限流器。"""

    def __init__(
        self,
        db,  # CodeReceiverDB
        ip_per_min: int = DEFAULT_IP_PER_MIN,
        ip_per_hour: int = DEFAULT_IP_PER_HOUR,
        email_per_hour: int = DEFAULT_EMAIL_PER_HOUR,
        failure_locker: Optional[FailureLocker] = None,
    ) -> None:
        self._db = db
        self.ip_per_min = ip_per_min
        self.ip_per_hour = ip_per_hour
        self.email_per_hour = email_per_hour
        self.failure_locker = failure_locker or FailureLocker()

    def check(self, ip: str, email: str) -> RateLimitDecision:
        # 1) 失败锁定（内存）
        locked, retry = self.failure_locker.is_locked(ip)
        if locked:
            return RateLimitDecision(False, retry, "凭据多次失败，IP 已被临时封禁")

        # 2) IP 1 分钟窗口
        n = self._db.count_queries_in_window(60, ip=ip)
        if n >= self.ip_per_min:
            return RateLimitDecision(False, 60, f"IP 1 分钟内已达 {self.ip_per_min} 次上限")

        # 3) IP 1 小时窗口
        n = self._db.count_queries_in_window(3600, ip=ip)
        if n >= self.ip_per_hour:
            return RateLimitDecision(False, 3600, f"IP 1 小时内已达 {self.ip_per_hour} 次上限")

        # 4) email 1 小时窗口
        if email:
            n = self._db.count_queries_in_window(3600, email=email)
            if n >= self.email_per_hour:
                return RateLimitDecision(False, 3600, f"该邮箱 1 小时内已达 {self.email_per_hour} 次上限")

        return RateLimitDecision(True, 0, "")

    def record_failure(self, ip: str) -> None:
        self.failure_locker.record_failure(ip)

    def record_success(self, ip: str) -> None:
        self.failure_locker.record_success(ip)
