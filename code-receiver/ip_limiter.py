# -*- coding: utf-8 -*-
"""前台多维度限流。

策略：
- ``IP``：1 分钟 5 次 / 1 小时 30 次
- ``email``：1 小时 10 次（无视 IP，防对单邮箱密集打码）
- ``凭据失败``：连续 N 次失败 → 锁定 IP 1 小时（基于 ``code_query_log``
  里 ``error_kind='auth_failed'`` 计数，跨进程一致）

两层叠加防绕过：
- **DB 计数（落库）** —— 跨进程持久化，重启 / 多副本可见
- **In-flight 计数（内存）** —— 在请求 ``begin``～``end`` 之间累加。
  路由的 DB 落库在 ``finally`` 才发生，纯靠 DB count 在并发下会让
  N 个请求"同时通过"阈值检查；in-flight 计数补足这段窗口。
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Optional


logger = logging.getLogger(__name__)


# 各窗口阈值（环境变量 CRX_RATE_* 可覆盖）
#
# 历次调整：
#  - 2026-05 一期默认（5/min, 30/hour, 10邮箱/hour, 3 次锁 1h）
#    实际使用反馈：单用户日常多次刷新拿验证码就被卡 1 小时，自己都没法用。
#  - 2026-05 二期放宽到当前值，思路：
#    * IP/min 30：每 2 秒一次明显是机器人才会触发，正常用户够用
#    * IP/hour 300：1 小时内 5 次/分钟，正常用户难触达
#    * email/hour 60：单邮箱每分钟最多 1 次，刷新拿最新验证码完全够
#    * 失败锁 600 秒：输错凭据 5 次锁 10 分钟，不是 1 小时——用户输错能快速恢复
#    * 失败窗口 300 秒：5 分钟内累计 5 次才锁，正常人不会
DEFAULT_IP_PER_MIN = 30
DEFAULT_IP_PER_HOUR = 300
DEFAULT_EMAIL_PER_HOUR = 60
DEFAULT_FAIL_LOCK_THRESHOLD = 5
DEFAULT_FAIL_LOCK_DURATION = 600
DEFAULT_FAIL_WINDOW = 300

# 前置失败的 error_kind：这些请求**没真正发起 IMAP 拉取**，不应该消耗
# IP/hour、IP/min、email/hour 这些"成本型"配额——否则用户输错邮箱、
# 触发一次人机校验失败、查到一个未加入白名单的邮箱，就把自己 1 小时锁住，
# 体验非常差。这些前置失败仍然会写入 code_query_log（用于审计），但
# count_queries_in_window 里被排除。
#
# 注意：``auth_failed`` **不在**排除列表里——凭据失败必须计入失败锁定，
# 否则攻击者可以无限对单个邮箱试 OAuth refresh。
PREFLIGHT_ERROR_KINDS: tuple[str, ...] = (
    "parse",                # 输入格式错误
    "byo_disabled",         # byo 路径已下线（含 ----）
    "not_authorized",       # 邮箱不在接码白名单（兼容老日志）
    "not_authorized_no_owner_user",   # 站长用户名错（部署级问题）
    "not_authorized_no_account",      # 站长名下没这个邮箱（用户拼错 / 没导入）
    "not_authorized_not_public",      # 邮箱在但管理端没点"加入接码"
    "not_authorized_category_mismatch",  # 分类不允许（账号属于其他分组）
    "not_authorized_unknown",         # 诊断 SQL 异常
    "no_extractor",         # 该分类没有提取规则（站长配置错）
    "turnstile_missing",    # 用户没填人机校验
    "turnstile_failed",     # 人机校验失败
    "turnstile_upstream",   # CF siteverify 服务异常
)


class RateLimitDecision:
    __slots__ = ("allowed", "retry_after", "reason")

    def __init__(self, allowed: bool, retry_after: int = 0, reason: str = "") -> None:
        self.allowed = allowed
        self.retry_after = retry_after
        self.reason = reason


@dataclass
class _InflightGauge:
    """简单的 in-flight 计数器（per-key 整数，begin +1 / end -1）。

    用于补足 DB 落库的"finally 滞后窗口"——若不补足，N 个并发请求都会读到
    同样的旧 DB count 并全部通过限流。这是 race condition 的关键修复。

    异常路径漏调 ``end`` 会导致计数泄漏，靠进程重启清零；接受少量泄漏。
    """

    _counts: Dict[str, int] = None  # type: ignore
    _lock: threading.Lock = None  # type: ignore

    def __post_init__(self) -> None:
        self._counts = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> int:
        with self._lock:
            return self._counts.get(key, 0)

    def increase(self, key: str) -> None:
        with self._lock:
            self._counts[key] = self._counts.get(key, 0) + 1

    def decrease(self, key: str) -> None:
        with self._lock:
            cur = self._counts.get(key, 0)
            if cur <= 1:
                self._counts.pop(key, None)
            else:
                self._counts[key] = cur - 1


class FailureLocker:
    """凭据失败锁定。

    实现已从「内存 deque」迁移到「DB ``code_query_log`` 的
    ``error_kind='auth_failed'`` 行计数」，让 ``record_failure`` 写
    ``add_query_log(success=False, error_kind='auth_failed')`` 后所有
    进程 / 副本都能看到一致的失败计数（重启不再清空）。

    判定语义：``last_window`` 秒内 ``auth_failed`` 计数 ≥ ``threshold``
    且最近一次失败距今 < ``lock_duration`` → 锁定。
    """

    def __init__(
        self,
        db,
        threshold: int = DEFAULT_FAIL_LOCK_THRESHOLD,
        lock_duration: int = DEFAULT_FAIL_LOCK_DURATION,
        window: int = DEFAULT_FAIL_WINDOW,
    ) -> None:
        self._db = db
        self.threshold = threshold
        self.lock_duration = lock_duration
        self.window = window

    def is_locked(self, ip: str) -> tuple[bool, int]:
        """如果 ``window`` 秒内失败计数 ≥ threshold，返回剩余锁定秒数。

        用最近 ``lock_duration`` 秒作为"最近一次失败"的最大可能区间，
        命中 ``threshold`` 后，回退按"最近一次失败时间 + lock_duration"算
        retry_after；为节省一次查询，简化为返回 lock_duration（保守上界）。
        """
        try:
            n = self._db.count_auth_failures(ip=ip, window_seconds=self.window)
        except Exception:
            logger.exception("count_auth_failures 异常 — 退化为放行（不锁）")
            return False, 0
        if n >= self.threshold:
            return True, self.lock_duration
        return False, 0

    def record_failure(self, ip: str) -> None:
        """触发条件由调用方保证（``_is_auth_failure(err_text) is True``）；
        这里只是兼容旧调用签名，实际写库由路由的 ``add_query_log`` 完成。
        留空避免破坏调用点。"""

    def record_success(self, ip: str) -> None:
        """同上：DB 路径下"清除失败计数"= 时间窗口外自然过期。
        留空避免破坏调用点。"""


class RateLimiter:
    """组合 DB 计数 + 内存 in-flight + DB 失败锁的限流器。"""

    def __init__(
        self,
        db,
        ip_per_min: int = DEFAULT_IP_PER_MIN,
        ip_per_hour: int = DEFAULT_IP_PER_HOUR,
        email_per_hour: int = DEFAULT_EMAIL_PER_HOUR,
        failure_locker: Optional[FailureLocker] = None,
    ) -> None:
        self._db = db
        self.ip_per_min = ip_per_min
        self.ip_per_hour = ip_per_hour
        self.email_per_hour = email_per_hour
        self.failure_locker = failure_locker or FailureLocker(db)
        self._inflight_ip = _InflightGauge()
        self._inflight_email = _InflightGauge()

    def begin(self, ip: str, email: str = "") -> RateLimitDecision:
        """开始一次请求；若被限流返回 ``allowed=False``。

        通过 ``begin`` 即在 in-flight 内存计数 +1（IP / email 两个槽位），
        必须配合 ``end`` 在请求结束时 -1，否则会泄漏配额。

        判定 = DB 已落库的请求数 + 内存中正在进行中的请求数。

        DB 计数排除 ``PREFLIGHT_ERROR_KINDS``：用户因输错邮箱、人机校验失败
        等"还没到 IMAP 那一步"的请求不消耗配额，避免误操作把自己锁 1 小时。
        """
        excluded = list(PREFLIGHT_ERROR_KINDS)

        # 1) 失败锁定（auth_failed 计数走独立路径，不受 excluded 影响）
        locked, retry = self.failure_locker.is_locked(ip)
        if locked:
            return RateLimitDecision(False, retry, "credentials_locked")

        # 2) IP 1 分钟窗口：仍排除 preflight，但 1 分钟阈值小，主要拦短时刷量
        n_db = self._db.count_queries_in_window(
            60, ip=ip, exclude_error_kinds=excluded
        )
        n_inflight = self._inflight_ip.get(_ip_min_key(ip))
        if n_db + n_inflight >= self.ip_per_min:
            return RateLimitDecision(False, 60, "ip_per_min")

        # 3) IP 1 小时窗口（DB + inflight 合计）
        n_db = self._db.count_queries_in_window(
            3600, ip=ip, exclude_error_kinds=excluded
        )
        n_inflight = self._inflight_ip.get(_ip_hour_key(ip))
        if n_db + n_inflight >= self.ip_per_hour:
            return RateLimitDecision(False, 3600, "ip_per_hour")

        # 4) email 1 小时窗口
        if email:
            n_db = self._db.count_queries_in_window(
                3600, email=email, exclude_error_kinds=excluded
            )
            n_inflight = self._inflight_email.get(_email_hour_key(email))
            if n_db + n_inflight >= self.email_per_hour:
                return RateLimitDecision(False, 3600, "email_per_hour")

        # 通过：登记 in-flight，调用方必须保证 end() 一定被调用
        self._inflight_ip.increase(_ip_min_key(ip))
        self._inflight_ip.increase(_ip_hour_key(ip))
        if email:
            self._inflight_email.increase(_email_hour_key(email))
        return RateLimitDecision(True, 0, "")

    def end(self, ip: str, email: str = "") -> None:
        """请求结束（无论成功 / 失败）必须调用以释放 in-flight 计数。"""
        self._inflight_ip.decrease(_ip_min_key(ip))
        self._inflight_ip.decrease(_ip_hour_key(ip))
        if email:
            self._inflight_email.decrease(_email_hour_key(email))

    # ── 旧接口兼容 ─────────────────────────────────────────────────

    def check(self, ip: str, email: str) -> RateLimitDecision:
        """旧接口：纯只读判定，不登记 in-flight。

        新调用方应使用 ``begin`` + ``end`` 配对（begin 通过会累加 in-flight），
        ``check`` 仅供测试或外部健康探针无副作用地查询限流状态。

        与 ``begin`` 一致排除 preflight error_kind。
        """
        excluded = list(PREFLIGHT_ERROR_KINDS)
        locked, retry = self.failure_locker.is_locked(ip)
        if locked:
            return RateLimitDecision(False, retry, "credentials_locked")
        n = self._db.count_queries_in_window(
            60, ip=ip, exclude_error_kinds=excluded
        ) + self._inflight_ip.get(_ip_min_key(ip))
        if n >= self.ip_per_min:
            return RateLimitDecision(False, 60, "ip_per_min")
        n = self._db.count_queries_in_window(
            3600, ip=ip, exclude_error_kinds=excluded
        ) + self._inflight_ip.get(_ip_hour_key(ip))
        if n >= self.ip_per_hour:
            return RateLimitDecision(False, 3600, "ip_per_hour")
        if email:
            n = self._db.count_queries_in_window(
                3600, email=email, exclude_error_kinds=excluded
            ) + self._inflight_email.get(_email_hour_key(email))
            if n >= self.email_per_hour:
                return RateLimitDecision(False, 3600, "email_per_hour")
        return RateLimitDecision(True, 0, "")

    def record_failure(self, ip: str) -> None:
        """凭据失败：现走 DB（``add_query_log(error_kind='auth_failed')``
        由路由直接写）。这里仅保留方法名兼容性。"""
        self.failure_locker.record_failure(ip)

    def record_success(self, ip: str) -> None:
        self.failure_locker.record_success(ip)


# ── 内部 key 命名 ─────────────────────────────────────────────────
# 不同窗口用不同 key 命名空间，避免 IP=email 时 key 冲突（虽然 IP 与 email
# 在业务上不会重叠，仍显式分隔安全感更高）。

def _ip_min_key(ip: str) -> str:
    return f"ip60:{ip}"


def _ip_hour_key(ip: str) -> str:
    return f"ip3600:{ip}"


def _email_hour_key(email: str) -> str:
    return f"email3600:{email}"
