"""
Helper 端的邮箱相关 action
==========================

action 列表
- ``open_mailbox``           启动 Chromium、自动登录 Outlook 并保持浏览器打开
- ``get_ms_token``           在已打开的邮箱浏览器中完成 MS OAuth2 → 拿 refresh_token
- ``change_email_password``  在已打开的邮箱浏览器中改 Outlook 密码
- ``bind_recovery_email``    在已打开的邮箱浏览器中绑定辅助邮箱

实现说明
--------
**Stage 1（当前）**：本文件仅提供 stub —— 4 个 action 调用一律返回
``success=False, error="功能尚未实现，请等待 Stage 2 浏览器自动化模块上线"``。

**Stage 2（后续）**：会移植 DrissionPage 浏览器自动化代码（约 3000 行）
到 ``core/outlook_service.py``，本文件内的 action 改成调用真正的服务。

为什么这样设计：3000+ 行浏览器自动化代码移植量大、容易引入 bug；先用
stub 跑通整个分发链路（Web 面板 → server → helper → action → 回传），
保证用户能看到完整 UI 与连通性，再分阶段落 Outlook 业务。
"""
from __future__ import annotations

import logging
from typing import Callable

logger = logging.getLogger(__name__)

LogFn = Callable[[str, str], None]


_STAGE1_NOTICE = (
    "邮箱浏览器自动化（DrissionPage + Outlook 登录）尚未在 Stage 1 移植。"
    "Helper 已连通，action 分发链路工作正常；下个版本会启用此功能。"
)


def _stub(action_name: str, params: dict, log: LogFn) -> dict:
    email = (params.get("email") or "").strip()
    log(f"[stub] 收到 {action_name} 请求 email={email}", "warning")
    log(_STAGE1_NOTICE, "warning")
    return {
        "success": False,
        "error": _STAGE1_NOTICE,
        "stage": 1,
        "action": action_name,
        "echo_params": {
            k: v for k, v in (params or {}).items()
            if k not in ("email_password", "new_password")
        },
    }


def action_open_mailbox(params: dict, log: LogFn) -> dict:
    """启动 Chromium、自动登录 Outlook 并保持浏览器打开。

    入参: ``email``, ``email_password``
    返回 (Stage 2): ``{"success": True, "data": {"opened": True}}``
    """
    if not params.get("email"):
        return {"success": False, "error": "缺少 email"}
    if not params.get("email_password"):
        return {"success": False, "error": "缺少 email_password"}
    return _stub("open_mailbox", params, log)


def action_get_ms_token(params: dict, log: LogFn) -> dict:
    """在已打开的邮箱浏览器中完成 MS OAuth2 → 拿 refresh_token。

    入参: ``email``
    返回 (Stage 2):
        ``{"success": True, "data": {"client_id": ..., "refresh_token": ...}}``
    """
    if not params.get("email"):
        return {"success": False, "error": "缺少 email"}
    return _stub("get_ms_token", params, log)


def action_change_email_password(params: dict, log: LogFn) -> dict:
    """在已打开的邮箱浏览器中改 Outlook 密码。

    入参: ``email``, ``email_password``, ``new_password``
    """
    if not params.get("email"):
        return {"success": False, "error": "缺少 email"}
    if not params.get("email_password"):
        return {"success": False, "error": "缺少 email_password"}
    if not params.get("new_password"):
        return {"success": False, "error": "缺少 new_password"}
    return _stub("change_email_password", params, log)


def action_bind_recovery_email(params: dict, log: LogFn) -> dict:
    """在已打开的邮箱浏览器中绑定辅助邮箱。

    入参: ``email``, ``alias_suffix?``, ``alias_email?``
    """
    if not params.get("email"):
        return {"success": False, "error": "缺少 email"}
    return _stub("bind_recovery_email", params, log)


__all__ = (
    "action_open_mailbox",
    "action_get_ms_token",
    "action_change_email_password",
    "action_bind_recovery_email",
)
