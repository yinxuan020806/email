"""
Helper 端的邮箱相关 action（Stage 2 实装）
============================================

action 列表
- ``open_mailbox``           启动 Chromium、自动登录 Outlook 并保持浏览器打开
- ``get_ms_token``           在已打开的邮箱浏览器中完成 MS OAuth2 → 拿 refresh_token
- ``change_email_password``  在已打开的邮箱浏览器中改 Outlook 密码
- ``bind_recovery_email``    在已打开的邮箱浏览器中绑定辅助邮箱

实现策略
--------
- 直接复用项目根 ``core/outlook_service.py``。Helper 进程在 Windows 桌面跑，
  ``IS_HEADLESS_ENV`` 守卫不会触发，所有 DrissionPage 浏览器自动化都能正常工作。
- ``core/outlook_service.py`` 内部用 ``core.helper_log_bridge.add_log``
  推日志。在 Helper 进程里这些消息原本只写到本地 logger；通过
  ``log_redirect`` context manager 临时把 ``add_log`` monkey-patch 成调
  helper 的 ``log`` 回调，让消息经 ``POST /api/helper/task-log`` 流回
  server，server 再 broadcast 给 SSE 订阅者，实现端到端实时日志透传。

⚠ 依赖
------
- ``DrissionPage>=4.1,<5``
- ``requests``
- 系统 chromium / chrome 浏览器

如果依赖缺失（用户没装、helper 是源码模式但 venv 不全），import 会失败 →
action 调用直接报错 "邮箱浏览器自动化依赖缺失"。
"""
from __future__ import annotations

import contextlib
import logging
from typing import Callable

logger = logging.getLogger(__name__)

LogFn = Callable[[str, str], None]


@contextlib.contextmanager
def log_redirect(log: LogFn):
    """把 ``core.helper_log_bridge.add_log`` 临时替换成调 ``log(message, level)``。

    顺带把 ``core.outlook_service.add_log`` / ``core.password_change_service.add_log``
    （这两个模块用 ``from core.helper_log_bridge import add_log`` 把名字 cache
    到自己的命名空间）一并替换；context 退出时全部还原。
    """
    targets = []
    try:
        from core import helper_log_bridge as _bridge
        targets.append((_bridge, "add_log", _bridge.add_log))
    except Exception:  # noqa: BLE001
        pass
    try:
        from core import outlook_service as _os
        targets.append((_os, "add_log", _os.add_log))
    except Exception:  # noqa: BLE001
        pass
    try:
        from core import password_change_service as _ps
        targets.append((_ps, "add_log", _ps.add_log))
    except Exception:  # noqa: BLE001
        pass

    def _patched(message, level: str = "info"):
        try:
            log(str(message), str(level or "info"))
        except Exception:  # noqa: BLE001
            pass

    saved = []
    for mod, name, original in targets:
        saved.append((mod, name, original))
        setattr(mod, name, _patched)
    try:
        yield
    finally:
        for mod, name, original in saved:
            try:
                setattr(mod, name, original)
            except Exception:  # noqa: BLE001
                pass


def _import_outlook_service():
    """延迟导入 outlook_service，依赖缺失时给明确报错。"""
    try:
        from core import outlook_service
        return outlook_service, None
    except ImportError as e:
        return None, (
            f"邮箱浏览器自动化依赖缺失：{e}。"
            "请在 helper venv 里跑 ``pip install -r helper/requirements.txt``，"
            "需要 DrissionPage 等浏览器自动化库；或重新打包 .exe。"
        )
    except Exception as e:  # noqa: BLE001
        return None, f"加载 outlook_service 失败：{type(e).__name__}: {e}"


def action_open_mailbox(params: dict, log: LogFn) -> dict:
    """启动 Chromium、自动登录 Outlook 并保持浏览器打开。

    入参: ``email``, ``email_password``
    返回: ``{"success": bool, "data": {"opened": True} | error}``
    """
    email = (params.get("email") or "").strip()
    email_password = params.get("email_password") or ""
    if not email:
        return {"success": False, "error": "缺少 email"}
    if not email_password:
        return {"success": False, "error": "缺少 email_password"}

    log(f"准备打开邮箱 {email}", "info")
    outlook_service, err = _import_outlook_service()
    if err:
        return {"success": False, "error": err}

    with log_redirect(log):
        try:
            result = outlook_service.open_outlook_mailbox(email, email_password)
        except Exception as e:  # noqa: BLE001
            logger.exception("[helper] open_outlook_mailbox 异常")
            return {"success": False, "error": f"{type(e).__name__}: {e}"}

    if not isinstance(result, dict):
        return {"success": True, "data": result}
    return result


def action_get_ms_token(params: dict, log: LogFn) -> dict:
    """在已打开的邮箱浏览器中完成 MS OAuth2 → 拿 refresh_token。

    入参: ``email``
    返回: ``{"success": bool, "data": {"client_id": ..., "refresh_token": ...}}``
    """
    email = (params.get("email") or "").strip()
    if not email:
        return {"success": False, "error": "缺少 email"}

    log(f"准备获取 {email} 的 MS Refresh Token", "info")
    outlook_service, err = _import_outlook_service()
    if err:
        return {"success": False, "error": err}

    with log_redirect(log):
        try:
            result = outlook_service.get_ms_token_from_open_browser(email)
        except Exception as e:  # noqa: BLE001
            logger.exception("[helper] get_ms_token 异常")
            return {"success": False, "error": f"{type(e).__name__}: {e}"}
    if not isinstance(result, dict):
        return {"success": False, "error": "底层返回非 dict"}
    return result


def _extract_imap_config(params: dict) -> dict:
    """把派发任务的 params 中 IMAP / 辅助邮箱后缀字段拎出来。

    用于透传给 ``core.outlook_service`` 里的 ``bind_recovery_email`` /
    ``change_outlook_email_password``。Helper 在 PyInstaller frozen 环境下
    自带的 ``load_config()`` 读不到 web 后端的 ``config.json``，**必须**
    靠这里从派发参数里组合 imap_config 传给底层函数。
    """
    extras: dict = {}
    for k in (
        "recovery_alias_suffix",
        "qq_imap_user",
        "qq_imap_password",
        "qq_imap_host",
        "qq_imap_port",
    ):
        if k not in params:
            continue
        v = params[k]
        if k == "qq_imap_port":
            try:
                v = int(v) if v not in (None, "") else 993
            except (TypeError, ValueError):
                v = 993
        extras[k] = v
    return extras


def action_change_email_password(params: dict, log: LogFn) -> dict:
    """在已打开的邮箱浏览器中改 Outlook 密码。

    入参: ``email``, ``email_password``, ``new_password``
    （可选 IMAP 配置：``qq_imap_user/password/host/port``、``recovery_alias_suffix``）
    """
    email = (params.get("email") or "").strip()
    email_password = params.get("email_password") or ""
    new_password = params.get("new_password") or ""
    if not email or not email_password or not new_password:
        return {
            "success": False,
            "error": "缺少 email / email_password / new_password",
        }

    log(f"准备修改 {email} 的邮箱密码", "info")
    outlook_service, err = _import_outlook_service()
    if err:
        return {"success": False, "error": err}

    extras = _extract_imap_config(params)
    if extras.get("qq_imap_user"):
        # 不要打 password 出来，只透出 user 让用户能确认派发链路通了
        log(
            f"已收到服务器派发的 IMAP 凭据 (qq_imap_user={extras['qq_imap_user']})；"
            "改密中途若跳 proofs/Add 会自动用此凭据接管",
            "info",
        )
    imap_kw: dict = {"imap_config": extras} if extras else {}

    with log_redirect(log):
        try:
            result = outlook_service.change_outlook_email_password(
                email, email_password, new_password,
                **imap_kw,
            )
        except Exception as e:  # noqa: BLE001
            logger.exception("[helper] change_email_password 异常")
            return {"success": False, "error": f"{type(e).__name__}: {e}"}
    if not isinstance(result, dict):
        return {"success": False, "error": "底层返回非 dict"}
    return result


def action_bind_recovery_email(params: dict, log: LogFn) -> dict:
    """在已打开的邮箱浏览器中绑定辅助邮箱。

    入参: ``email``, ``alias_suffix?``, ``alias_email?``
    """
    email = (params.get("email") or "").strip()
    alias_suffix = (params.get("alias_suffix") or "").strip().lstrip("@")
    alias_email = (params.get("alias_email") or "").strip()
    if not email:
        return {"success": False, "error": "缺少 email"}

    log(
        f"准备给 {email} 绑定辅助邮箱"
        f"（后缀={alias_suffix or '默认'}, 别名={alias_email or '自动'}）",
        "info",
    )
    outlook_service, err = _import_outlook_service()
    if err:
        return {"success": False, "error": err}

    extras = _extract_imap_config(params)
    if extras.get("qq_imap_user"):
        log(
            f"已收到服务器派发的 IMAP 凭据 (qq_imap_user={extras['qq_imap_user']})",
            "info",
        )
    else:
        log(
            "⚠ 服务器派发的任务没有附带 qq_imap_user / qq_imap_password；"
            "本机 helper 进程将退回 PyInstaller 内置 config.json（多半为空）",
            "warning",
        )
    imap_kw: dict = {"imap_config": extras} if extras else {}

    with log_redirect(log):
        try:
            result = outlook_service.bind_recovery_email(
                email,
                alias_suffix=alias_suffix,
                alias_email=alias_email,
                **imap_kw,
            )
        except Exception as e:  # noqa: BLE001
            logger.exception("[helper] bind_recovery_email 异常")
            return {"success": False, "error": f"{type(e).__name__}: {e}"}

    if not isinstance(result, dict):
        return {"success": False, "error": "底层返回非 dict"}
    return result


__all__ = (
    "action_open_mailbox",
    "action_get_ms_token",
    "action_change_email_password",
    "action_bind_recovery_email",
    "log_redirect",
)
