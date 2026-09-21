# -*- coding: utf-8 -*-
"""Microsoft Graph / token 端点的进程级限流。

Hotmail / Outlook.com 对**同一出口 IP + 同一 client_id** 短时间访问多个邮箱
非常敏感：每个邮箱首次打开都要 refresh_token + Graph GET，前端 1.5s 节流
拦不住「上一个请求还在飞、下一个已经发出」的并发堆叠。微软此时常返回
503 ErrorServerBusy / 429 ApplicationThrottled，后端再被包装成 HTTP 502，
前端就显示成「反代/网关错误」——邮箱本身往往没问题。

本模块两件事：
1. ``microsoft_slot``：全进程最多 N 路并发打微软，调用之间强制最小间隔。
   可重入（同一线程 Graph 调用内部再 refresh token 不重复占名额）。
2. ``is_ms_throttle_msg``：把 429/503/限流类文案识别成「微软限流」而不是
   反代挂了。
"""

from __future__ import annotations

import os
import re
import threading
import time
from contextlib import contextmanager
from typing import Iterator


# 默认 4 路 + 0.2s 间隔：日常连点几个 Hotmail 基本无感，比无上限仍能挡住
# 「上一个还在飞、下一个已经发出」的堆叠。批量检测也会走这里。
_DEFAULT_MAX = 4
_DEFAULT_INTERVAL = 0.2

_sem: threading.BoundedSemaphore | None = None
_sem_lock = threading.Lock()
_tls = threading.local()
_last_release = 0.0
_last_lock = threading.Lock()


def _max_concurrent() -> int:
    raw = (os.getenv("MS_MAX_CONCURRENT") or "").strip()
    if not raw:
        return _DEFAULT_MAX
    try:
        return max(1, int(raw))
    except ValueError:
        return _DEFAULT_MAX


def _min_interval() -> float:
    raw = (os.getenv("MS_MIN_INTERVAL_SEC") or "").strip()
    if not raw:
        return _DEFAULT_INTERVAL
    try:
        return max(0.0, float(raw))
    except ValueError:
        return _DEFAULT_INTERVAL


def _get_sem() -> threading.BoundedSemaphore:
    global _sem
    with _sem_lock:
        if _sem is None:
            _sem = threading.BoundedSemaphore(_max_concurrent())
        return _sem


def reset_ms_limiter_for_tests() -> None:
    """测试用：丢掉已创建的 semaphore，让下次按当前环境变量重建。"""
    global _sem, _last_release
    with _sem_lock:
        _sem = None
    with _last_lock:
        _last_release = 0.0


@contextmanager
def microsoft_slot() -> Iterator[None]:
    """占用一个「打微软」名额；同线程重入直接放行。"""
    depth = getattr(_tls, "depth", 0)
    if depth > 0:
        _tls.depth = depth + 1
        try:
            yield
        finally:
            _tls.depth -= 1
        return

    sem = _get_sem()
    sem.acquire()
    _tls.depth = 1
    try:
        interval = _min_interval()
        if interval > 0:
            global _last_release
            with _last_lock:
                wait = interval - (time.time() - _last_release)
            if wait > 0:
                time.sleep(wait)
        yield
    finally:
        with _last_lock:
            _last_release = time.time()
        _tls.depth = 0
        sem.release()


# 状态码必须前后不是数字，避免 "15030ms" 误命中 503。
_THROTTLE_RE = re.compile(
    r"(?<!\d)(?:429|503|504)(?!\d)"
    r"|throttl|too many|server ?busy|serverbusy"
    r"|applicationthrottled|mailboxconcurrency"
    r"|errortoomanyrequests|errorserverbussy"
    r"|限流|暂时繁忙",
    re.IGNORECASE,
)


def is_ms_throttle_msg(msg: str) -> bool:
    """上游错误文案是否像 Microsoft Graph / token 限流或 503 繁忙。"""
    m = (msg or "").strip()
    if not m:
        return False
    return _THROTTLE_RE.search(m) is not None


THROTTLE_USER_MSG = (
    "微软接口限流（短时间打开了太多邮箱，不是这个邮箱坏了）。"
    "请等几秒再点刷新。"
)
"""给前端看的限流说明。邮箱本身通常仍然可用。"""
