"""
Helper HTTP 客户端
======================

走 HTTP 长轮询，不依赖 WebSocket。这样 Helper 在任何 ASGI/WSGI 部署
后端面前都能跑通。

主线程
- ``_run_loop``：register → 循环 ``poll-task`` → 收到 task 就丢线程池跑 handler
- ``_heartbeat_loop``：每 20s 发一次 heartbeat 保活

任务执行线程
- 调 ``handlers.run_handler``
- 通过 ``log(message, level)`` 回调批量缓冲日志，每 ~500ms flush 一次到
  ``/api/helper/task-log``（避免每条日志一次 HTTP）
- 跑完 POST ``/api/helper/task-result``

重连策略
- 网络异常 / 服务端 401 needs_register → 立即 register 一次
- 401 但 token 失效（持续 401/403）→ 退避 30s 再尝试
- 连接 / register 失败 → 指数退避 1 → 2 → 4 → 8 → 16 → 30s
"""
from __future__ import annotations

import enum
import logging
import threading
import time
from typing import Callable, Optional

import requests

from helper import __version__
from helper.config import HelperConfig
from helper.handlers import run_handler

logger = logging.getLogger(__name__)


class ConnState(enum.Enum):
    OFFLINE = "offline"
    CONNECTING = "connecting"
    CONNECTED = "connected"


_RECONNECT_MIN = 1
_RECONNECT_MAX = 30
_HEARTBEAT_INTERVAL = 20    # 秒
_LOG_FLUSH_INTERVAL = 0.5    # 秒
_HTTP_TIMEOUT_SHORT = 15     # 普通短请求
_HTTP_TIMEOUT_LONG = 35      # 长轮询 (poll_block 25s + 余量)

# task-result 重试参数：跑了 5 分钟的改密任务，如果上报恰好碰上网络抖一下
# 就丢，server 端 _pending 会一直空等到 dispatch timeout 才知道失败 ——
# 用户阻塞 5 分钟才看到「超时」但邮箱端密码已经改过了。这里加 3 次指数
# 退避，把"已完成但回执发不出去"这一类失败的窗口收到几秒内。
_TASK_RESULT_RETRIES = 3
_TASK_RESULT_BACKOFF_MIN = 1.0
_TASK_RESULT_BACKOFF_MAX = 8.0


class HelperClient:
    """长轮询客户端 + 任务执行调度。"""

    def __init__(
        self,
        config: HelperConfig,
        status_callback: Optional[Callable[[ConnState, str], None]] = None,
    ):
        self.config = config
        self._status_cb = status_callback or (lambda s, msg: None)
        self._session = requests.Session()
        self._stop = threading.Event()
        self._loop_thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._state = ConnState.OFFLINE
        self._helper_id: Optional[str] = None
        self._poll_block_seconds = 25
        self._last_error: str = ""

    # ── 状态 ───────────────────────────────────────────────────

    @property
    def state(self) -> ConnState:
        return self._state

    @property
    def helper_id(self) -> Optional[str]:
        return self._helper_id

    @property
    def last_error(self) -> str:
        return self._last_error

    def _set_state(self, state: ConnState, msg: str = "") -> None:
        if self._state != state:
            self._state = state
            logger.info(
                "[helper] 状态变更 → %s%s",
                state.value, f" ({msg})" if msg else "",
            )
        try:
            self._status_cb(state, msg)
        except Exception:  # noqa: BLE001
            pass

    # ── 启停 ───────────────────────────────────────────────────

    def start(self) -> None:
        if self._loop_thread and self._loop_thread.is_alive():
            return
        # 自动 install default handlers：测试脚本 / 嵌入式场景从不走 main.py 时
        # 也能直接 client.start() 就跑通 4 个 mailbox action（stub or real）。
        # ``install_default_handlers`` 内部用 try/except 包裹，缺依赖时只 warning。
        try:
            from helper.handlers import install_default_handlers
            install_default_handlers()
        except Exception as e:  # noqa: BLE001
            logger.warning("[helper] install_default_handlers 失败: %s", e)
        self._stop.clear()
        self._loop_thread = threading.Thread(
            target=self._run_loop, name="helper-client", daemon=True,
        )
        self._loop_thread.start()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, name="helper-heartbeat", daemon=True,
        )
        self._heartbeat_thread.start()

    def shutdown(self, join_timeout: float = 3.0) -> None:
        """请求停止 helper 客户端线程。

        ``self._session.close()`` 会让正在跑的 long-polling ``requests.get``
        立刻抛 ConnectionError 返回 —— 但极少数情况下底层 socket close 不及时
        （Windows TCP 状态机），join 可能超时。本方法**不保证**线程一定退出，
        调用方（``helper/main.py``）会在 join 之后通过 ``os._exit(0)`` 兜底
        强杀进程，让任何残留线程一并随进程退出。
        """
        self._stop.set()
        try:
            self._session.close()
        except Exception:  # noqa: BLE001
            pass
        loop_alive = False
        hb_alive = False
        if self._loop_thread:
            self._loop_thread.join(timeout=join_timeout)
            loop_alive = self._loop_thread.is_alive()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=join_timeout)
            hb_alive = self._heartbeat_thread.is_alive()
        if loop_alive or hb_alive:
            msg = (
                f"已请求停止（join 超时 {join_timeout}s 后线程仍在退出："
                f"loop={loop_alive} hb={hb_alive}，依赖进程退出兜底）"
            )
            self._set_state(ConnState.OFFLINE, msg)
        else:
            self._set_state(ConnState.OFFLINE, "已停止")

    # ── HTTP 工具 ──────────────────────────────────────────────

    def _url(self, path: str) -> str:
        base = self.config.server_url.rstrip("/")
        return base + path

    def _post(
        self, path: str, json: Optional[dict] = None,
        timeout: float = _HTTP_TIMEOUT_SHORT,
        with_helper_id: bool = True,
    ) -> tuple[Optional[dict], Optional[int]]:
        headers = {}
        if with_helper_id and self._helper_id:
            headers["X-Helper-Id"] = self._helper_id
        try:
            r = self._session.post(
                self._url(path), json=json or {}, timeout=timeout,
                headers=headers,
            )
        except requests.RequestException:
            return None, None
        try:
            data = r.json()
        except ValueError:
            data = {
                "success": False,
                "error": r.text[:200] if r.text else "non-json",
            }
        return data, r.status_code

    def _get(
        self, path: str, params: Optional[dict] = None,
        timeout: float = _HTTP_TIMEOUT_LONG,
        with_helper_id: bool = True,
    ) -> tuple[Optional[dict], Optional[int]]:
        headers = {}
        if with_helper_id and self._helper_id:
            headers["X-Helper-Id"] = self._helper_id
        try:
            r = self._session.get(
                self._url(path), params=params or {}, timeout=timeout,
                headers=headers,
            )
        except requests.RequestException:
            return None, None
        try:
            data = r.json()
        except ValueError:
            data = {
                "success": False,
                "error": r.text[:200] if r.text else "non-json",
            }
        return data, r.status_code

    # ── 主循环 ─────────────────────────────────────────────────

    def _run_loop(self) -> None:
        backoff = _RECONNECT_MIN
        while not self._stop.is_set():
            self._set_state(ConnState.CONNECTING, self.config.server_url)

            ok = self._do_register()
            if not ok:
                self._set_state(ConnState.OFFLINE, self._last_error)
                if self._stop.wait(backoff):
                    break
                backoff = min(backoff * 2, _RECONNECT_MAX)
                continue

            backoff = _RECONNECT_MIN
            self._poll_loop()
            # poll_loop 退出 = helper_id 失效或服务器无响应
            if not self._stop.is_set():
                if self._stop.wait(backoff):
                    break
                backoff = min(backoff * 2, _RECONNECT_MAX)

    def _do_register(self) -> bool:
        token = self.config.token
        if not token:
            self._last_error = "本地未保存 token，请在 Web 面板「邮箱助手」页面点「🚀 启动助手」"
            logger.error("[helper] %s", self._last_error)
            return False

        import sys as _sys
        body = {
            "token": token,
            "version": __version__,
            "platform": _sys.platform,
        }
        data, http_status = self._post(
            "/api/helper/register", body, with_helper_id=False,
        )
        if data is None:
            self._last_error = "无法连接服务器（网络 / DNS / 防火墙）"
            return False
        if http_status != 200 or not data.get("success"):
            self._last_error = data.get("error") or f"HTTP {http_status}"
            logger.error("[helper] register 失败: %s", self._last_error)
            return False

        self._helper_id = data.get("helper_id") or ""
        self._poll_block_seconds = int(data.get("poll_block_seconds") or 25)
        self._set_state(
            ConnState.CONNECTED, f"helper_id={self._helper_id}",
        )
        logger.info(
            "[helper] 注册成功 helper_id=%s server_time=%s",
            self._helper_id, data.get("server_time"),
        )
        return True

    def _poll_loop(self) -> None:
        """阻塞长轮询取任务并执行；失败 / helper_id 失效时返回，由外层重连。"""
        while not self._stop.is_set():
            params = {
                "helper_id": self._helper_id or "",
                "timeout": str(self._poll_block_seconds),
            }
            data, http_status = self._get(
                "/api/helper/poll-task", params, timeout=_HTTP_TIMEOUT_LONG,
            )

            if data is None:
                if self._stop.wait(2):
                    return
                continue

            if http_status == 401 and data.get("needs_register"):
                logger.info("[helper] helper_id 失效，需要重新注册")
                self._helper_id = None
                self._set_state(ConnState.CONNECTING, "需要重新注册")
                return

            if http_status != 200 or not data.get("success"):
                self._last_error = data.get("error") or f"HTTP {http_status}"
                logger.warning(
                    "[helper] poll-task 失败: %s", self._last_error,
                )
                if self._stop.wait(2):
                    return
                continue

            tasks = data.get("tasks") or []
            for task in tasks:
                if self._stop.is_set():
                    return
                self._spawn_task(task)

    def _spawn_task(self, msg: dict) -> None:
        """每个 task 一个独立线程跑（启动浏览器可能很耗时）。"""
        if msg.get("type") != "task":
            return
        t = threading.Thread(
            target=self._run_task, args=(msg,), daemon=True,
            name=f"helper-task-{msg.get('task_id')}",
        )
        t.start()

    def _run_task(self, msg: dict) -> None:
        task_id = msg.get("task_id") or ""
        action = msg.get("action") or ""
        params = msg.get("params") or {}
        if not task_id or not action:
            return

        log_buffer: list[dict] = []
        log_lock = threading.Lock()
        flush_stop = threading.Event()

        def push(message: str, level: str = "info") -> None:
            with log_lock:
                log_buffer.append({
                    "message": str(message), "level": str(level),
                })

        def _flush() -> None:
            with log_lock:
                if not log_buffer:
                    return
                batch = list(log_buffer)
                log_buffer.clear()
            self._post(
                "/api/helper/task-log",
                {"task_id": task_id, "logs": batch},
                timeout=_HTTP_TIMEOUT_SHORT,
            )

        def flush_loop() -> None:
            while not flush_stop.is_set():
                if flush_stop.wait(_LOG_FLUSH_INTERVAL):
                    break
                _flush()
            _flush()

        flusher = threading.Thread(
            target=flush_loop, daemon=True,
            name=f"helper-log-{task_id}",
        )
        flusher.start()

        push(f"开始执行 {action}", "info")
        try:
            result = run_handler(action, params, push)
        except Exception as e:  # noqa: BLE001
            logger.exception("[helper] action=%s 异常", action)
            result = {
                "success": False,
                "error": f"{type(e).__name__}: {e}",
            }

        push(
            f"完成 {action}: success={result.get('success')}",
            "info" if result.get("success") else "error",
        )
        flush_stop.set()
        flusher.join(timeout=2)

        body = {"task_id": task_id, **result}
        body.setdefault("success", False)
        self._post_task_result_with_retry(body)

    def _post_task_result_with_retry(self, body: dict) -> bool:
        """上报 task-result + 指数退避重试。

        服务端 ``submit_result`` 接收成功的 happy path 只有一种：HTTP 200 +
        ``data.get("success") is True``。我们把 helper 自己执行任务的结果
        ``success`` 字段塞在 body 里，但 ``submit_result`` 的回执 (``data``)
        里 ``success`` 表示"服务端接受 / 写入 result_q 成功"——和任务本身
        success 区分。这里只对服务端层面 ``success`` 做重试判定。

        触发重试的场景：网络异常（``data is None``）、HTTP 5xx、HTTP 401 +
        ``needs_register``（短暂的 helper_id 失效，外层正在重连）。

        遇到 HTTP 401/needs_register 时立刻清空 helper_id，主循环会感知并
        重新 register，再回来重试 ``task-result``。
        """
        task_id = body.get("task_id") or "?"
        backoff = _TASK_RESULT_BACKOFF_MIN
        for attempt in range(_TASK_RESULT_RETRIES + 1):
            data, status_code = self._post(
                "/api/helper/task-result", body,
                timeout=_HTTP_TIMEOUT_SHORT,
            )
            if data is not None and status_code == 200 and data.get("success"):
                if attempt > 0:
                    logger.info(
                        "[helper] task-result %s 第 %d 次重试成功",
                        task_id, attempt,
                    )
                return True

            if status_code == 401 and isinstance(data, dict) and data.get(
                "needs_register"
            ):
                logger.warning(
                    "[helper] task-result %s 收到 401，helper_id 失效；"
                    "暂存到下次注册后再试",
                    task_id,
                )
                self._helper_id = None
                return False

            if attempt >= _TASK_RESULT_RETRIES:
                logger.warning(
                    "[helper] task-result %s 重试 %d 次后仍失败 "
                    "(status=%s data=%s)，放弃上报。"
                    "服务端 _pending 将在 dispatch timeout 后回收。",
                    task_id, _TASK_RESULT_RETRIES, status_code,
                    (data or {}).get("error") if isinstance(data, dict) else "?",
                )
                return False

            logger.warning(
                "[helper] task-result %s 第 %d 次失败 status=%s，"
                "%.1fs 后重试",
                task_id, attempt + 1, status_code, backoff,
            )
            if self._stop.wait(backoff):
                return False
            backoff = min(backoff * 2, _TASK_RESULT_BACKOFF_MAX)
        return False

    def _heartbeat_loop(self) -> None:
        while not self._stop.is_set():
            if self._stop.wait(_HEARTBEAT_INTERVAL):
                return
            if self._state != ConnState.CONNECTED or not self._helper_id:
                continue
            self._post(
                "/api/helper/heartbeat", {},
                timeout=_HTTP_TIMEOUT_SHORT,
            )


__all__ = ("HelperClient", "ConnState")
