"""
任务处理器（action 分发表）
==============================

每个 handler 签名: ``(params: dict, log: Callable[[str, str], None]) -> dict``

返回的 dict 会作为 ``task_result`` 的载荷被 ``client.py`` 包装后回传。
建议返回 ``{"success": bool, "data": ..., "error": ...}``。

为什么 handler 自己拿 ``log`` 而不是 print：
- ``client.py`` 给的 ``log`` 实际是把消息打成 ``{"type":"task_log",...}`` 推回
  服务器，让 Web 面板的 SSE 实时日志流能看到 Helper 这边的执行进度。
"""
from __future__ import annotations

import logging
import sys
from typing import Callable

logger = logging.getLogger(__name__)

LogFn = Callable[[str, str], None]
Handler = Callable[[dict, LogFn], dict]


# ── v0.1：内置连通性测试 action ────────────────────────────────


def _action_echo(params: dict, log: LogFn) -> dict:
    log(f"echo 收到 params={params}", "info")
    return {"success": True, "data": {"echoed": params}}


def _action_ping(_params: dict, _log: LogFn) -> dict:
    import time
    return {"success": True, "data": {"pong": int(time.time())}}


def _action_version(_params: dict, log: LogFn) -> dict:
    """返回 helper 版本号 + Python / 平台信息。"""
    from helper import __version__
    info = {
        "helper_version": __version__,
        "python_version": sys.version.split()[0],
        "platform": sys.platform,
        "frozen": bool(getattr(sys, "frozen", False)),
    }
    log(f"version: {info}", "info")
    return {"success": True, "data": info}


# ── 注册表 ────────────────────────────────────────────────────


ACTION_HANDLERS: dict[str, Handler] = {
    "echo": _action_echo,
    "ping": _action_ping,
    "version": _action_version,
}


def register_action(name: str, handler: Handler) -> None:
    """允许外部模块（如 actions/mailbox.py）注册新 action。"""
    ACTION_HANDLERS[name] = handler


def get_handler(action: str) -> Handler | None:
    return ACTION_HANDLERS.get(action)


def list_actions() -> list[str]:
    return sorted(ACTION_HANDLERS.keys())


def run_handler(action: str, params: dict, log: LogFn) -> dict:
    """统一调用入口：未注册的 action / 抛异常 都回成 success=False。"""
    handler = ACTION_HANDLERS.get(action)
    if handler is None:
        return {"success": False, "error": f"Helper 不支持 action: {action}"}
    try:
        result = handler(params or {}, log)
    except Exception as e:  # noqa: BLE001
        logger.exception("[helper] action=%s 执行异常", action)
        return {"success": False, "error": f"{type(e).__name__}: {e}"}
    if not isinstance(result, dict):
        return {"success": True, "data": result}
    result.setdefault("success", True)
    return result


# ── Stage 2 邮箱业务 handler（懒加载） ────────────────────────


def install_default_handlers() -> None:
    """主 client 启动时调用一次，注册邮箱相关 handler。

    用 try/except 包裹：缺 DrissionPage / 在 Linux 上跑（仅作开发调试），
    部分 handler 不可用，但不影响 echo / ping / 整体进程启动。
    """
    try:
        from helper.actions import mailbox as _mb  # noqa: F401
        register_action("open_mailbox", _mb.action_open_mailbox)
        register_action("get_ms_token", _mb.action_get_ms_token)
        register_action(
            "change_email_password", _mb.action_change_email_password,
        )
        register_action(
            "bind_recovery_email", _mb.action_bind_recovery_email,
        )
        logger.info("[helper] 邮箱相关 handler 注册成功")
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "[helper] 邮箱 handler 注册失败（缺依赖？）: %s", e,
        )
