"""
Helper 端日志桥接（从 cursor-manager services/auth_service.py 中 add_log 抽离）

设计目标
--------
``core.outlook_service`` 与 ``core.password_change_service`` 内部用 ``add_log``
推送实时进度。原参考项目里 ``add_log`` 走的是 server SSE 队列；本项目里
这些代码同样会被 **helper 进程** 加载（helper EXE 把 core/ 整目录打包），
所以 ``add_log`` 要：

- 在 helper 进程里：被 ``helper/actions/mailbox.py`` 的 ``log_redirect``
  context manager monkey-patch 成调 ``log(message, level)`` 回调 → 通过
  HTTP ``POST /api/helper/task-log`` 推回 server，server 收到后再
  broadcast 到 SSE 给前端 Modal 实时显示
- 在 server 进程里（如果运维真在本机 Windows 上跑 server）：直接调
  ``helper_registry.broadcast_log``。但本项目主流是 server 在 Linux、
  helper 在 Windows，server 直接调 outlook_service 走不通（被 IS_HEADLESS_ENV
  拒）所以不会用到这条路径

默认实现：仅 print + logger.info（极简兜底）。helper 启动时由
``log_redirect`` 替换为真实推送函数。
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def add_log(message: str, level: str = "info") -> None:
    """日志推送入口（默认实现 = 控制台 + logger）。

    ``helper/actions/mailbox.py`` 的 ``log_redirect`` 会在任务执行期间临时
    把本模块的 ``add_log`` 替换成调 helper 客户端的 ``log()`` 回调，让消息
    通过 HTTP 推回 server 并最终到达前端 Modal。
    """
    level_lower = (level or "info").lower()
    if level_lower == "error":
        logger.error("[helper-bridge] %s", message)
    elif level_lower in {"warning", "warn"}:
        logger.warning("[helper-bridge] %s", message)
    else:
        logger.info("[helper-bridge] %s", message)


def close_all_kept_login_browsers() -> dict:
    """占位实现 — 参考项目 auth_service 里管理"密码登录后保留的浏览器实例"。

    本项目仅做邮箱自动化，不复用该机制；helper 退出时 ``tray._release_browsers_quietly``
    会调本函数，这里只返回空统计避免 import 时报错。
    """
    return {"closed": 0, "failed": 0}


__all__ = ("add_log", "close_all_kept_login_browsers")
