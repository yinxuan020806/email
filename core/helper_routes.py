"""
Helper 客户端 HTTP 路由（长轮询模型，FastAPI APIRouter）
=========================================================

为什么不用 WebSocket：见 ``core/helper_registry.py`` 顶部说明。

路由列表
--------

**给 Web 面板调用（带 cookie + xiaoxuan 鉴权）**

- ``POST /api/helper/provision-token`` — 生成新 helper token
- ``GET  /api/helper/status``           — 查询 helper 在线状态
- ``GET  /api/helper/tokens``           — 列出未撤销 token
- ``POST /api/helper/revoke``           — 撤销 token + 踢掉 session
- ``POST /api/helper/dispatch``         — 派发任意 action（调试用）
- ``GET  /api/helper/download-info``    — 列出可下载的 .exe / 安装脚本
- ``GET  /api/helper/logs``             — SSE 实时日志流（订阅 helper 推回的日志）

业务封装：
- ``POST /api/helper/mailbox/open``     — 自动打开 Outlook 邮箱浏览器
- ``POST /api/helper/mailbox/get-token``— 自动 OAuth2 拿 refresh_token
- ``POST /api/helper/mailbox/change-password`` — 自动改邮箱密码
- ``POST /api/helper/mailbox/bind-recovery``   — 自动绑定辅助邮箱

**给 Helper 客户端调用（无 cookie，用 token / X-Helper-Id 鉴权）**

- ``POST /api/helper/register``    — 提交 token，拿 helper_id 注册一条 session
- ``GET  /api/helper/poll-task``   — 长轮询取任务（最多阻塞 25s）
- ``POST /api/helper/task-result`` — 上报任务结果
- ``POST /api/helper/task-log``    — 上报任务日志（可批量）
- ``POST /api/helper/heartbeat``   — 保活心跳

Helper 端点用 ``token / helper_id`` 而非 cookie 鉴权 —— 因为 Helper 是另一台
机器上的进程，没法持有用户 session cookie。这些端点在 ``web_app`` 的安全中
间件外不需要额外豁免（CSRF 防护本项目暂未启用、cookie 由依赖 ``CurrentUser``
强制，所以 helper 端点只是不声明 ``user: dict = CurrentUser`` 即可）。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from core.helper_registry import (
    DEFAULT_TASK_TIMEOUT,
    MIN_HELPER_VERSION,
    POLL_BLOCK_SECONDS,
    _version_ok,
    registry,
    subscribe_logs,
    unsubscribe_logs,
)
from database import helper_token as _tk

logger = logging.getLogger(__name__)


# 这两个值由 web_app.py 在挂载路由前注入。设计上这样做：
# - ``helper_routes`` 不直接 import ``web_app``，避免循环依赖；
# - web_app 启动时调用 ``configure(db, code_owner_username)`` 把它们传进来。
_db = None
_code_owner_username: str = "xiaoxuan"


def configure(db_manager, code_owner_username: str) -> None:
    """供 ``web_app`` 启动时注入数据库 + xiaoxuan 用户名常量。"""
    global _db, _code_owner_username
    _db = db_manager
    _code_owner_username = (code_owner_username or "xiaoxuan").strip() or "xiaoxuan"


SESSION_COOKIE = "email_web_session"


def _client_ip(request: Request) -> str:
    """获取客户端 IP（与 web_app._client_ip 同算法的简化版）。"""
    fwd = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if fwd:
        return fwd
    real = (request.headers.get("x-real-ip") or "").strip()
    if real:
        return real
    return request.client.host if request.client else "unknown"


def _audit(
    request: Request,
    user: dict,
    action: str,
    *,
    target: Optional[str] = None,
    success: bool = True,
    detail: Optional[str] = None,
) -> None:
    """统一写 audit_log；DB 未注入时静默跳过（仅在测试场景）。"""
    if _db is None:
        return
    try:
        _db.log_audit(
            action=action,
            user_id=user.get("id"),
            username=user.get("username"),
            target=(target or "")[:200] or None,
            ip=_client_ip(request),
            user_agent=request.headers.get("user-agent", "")[:200],
            success=success,
            detail=(detail or "")[:500] or None,
        )
    except Exception as e:  # noqa: BLE001
        logger.warning("写 audit_log 失败 action=%s: %s", action, e)


# 仅 xiaoxuan 可访问的端点统一通过这个依赖判定。
def require_owner(
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict:
    """登录 + 必须是 ``CODE_OWNER_USERNAME`` 才能用 helper 功能。"""
    if _db is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Helper 模块未初始化",
        )
    user = _db.get_session_user(session_token or "")
    if not user:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "未登录或会话已过期",
            headers={"WWW-Authenticate": "Cookie"},
        )
    if user["username"] != _code_owner_username:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "邮箱助手功能仅站长可用",
        )
    return user


helper_router = APIRouter(prefix="/api/helper", tags=["helper"])


# ── Pydantic 模型 ───────────────────────────────────────────────


class ProvisionTokenRequest(BaseModel):
    label: Optional[str] = Field(default=None, max_length=128)


class RevokeRequest(BaseModel):
    token: Optional[str] = Field(default=None, max_length=128)
    all: bool = False


class DispatchRequest(BaseModel):
    action: str = Field(min_length=1, max_length=64)
    params: dict = Field(default_factory=dict)
    timeout: int = Field(default=DEFAULT_TASK_TIMEOUT, ge=1, le=600)


class MailboxOpenRequest(BaseModel):
    """登录 Outlook 邮箱。

    两种入参方式（任选其一）：
    - ``account_id``：从账号表中自动取出 email + 邮箱密码（推荐，前端表格按钮用）
    - ``email`` + ``email_password``：显式传值（手工调试 / 不在账号表中时用）
    """
    account_id: Optional[int] = Field(default=None, ge=1)
    email: Optional[str] = Field(default=None, max_length=256)
    email_password: Optional[str] = Field(default=None, max_length=512)
    timeout: int = Field(default=180, ge=10, le=600)


class MailboxGetTokenRequest(BaseModel):
    """获取 Outlook refresh_token。

    两种入参方式（任选其一）：
    - ``account_id``：从账号表自动取出 email（推荐）
    - ``email``：显式传值
    """
    account_id: Optional[int] = Field(default=None, ge=1)
    email: Optional[str] = Field(default=None, max_length=256)
    group: Optional[str] = Field(default=None, max_length=64)
    timeout: int = Field(default=180, ge=10, le=600)


class MailboxChangePasswordRequest(BaseModel):
    """修改 Outlook 密码。新密码至少 8 位。

    ``account_id`` 优先；后端会自动取该账号的 email 与当前密码，
    改密成功后**会更新 DB 中的密码字段**。
    """
    account_id: Optional[int] = Field(default=None, ge=1)
    email: Optional[str] = Field(default=None, max_length=256)
    email_password: Optional[str] = Field(default=None, max_length=512)
    new_password: str = Field(min_length=8, max_length=512)
    timeout: int = Field(default=300, ge=10, le=600)


class MailboxBindRecoveryRequest(BaseModel):
    """绑定辅助邮箱。

    ``account_id`` 优先；后端自动取出 email 与当前密码（密码用于在被强制
    二次验证时给 Helper）。
    """
    account_id: Optional[int] = Field(default=None, ge=1)
    email: Optional[str] = Field(default=None, max_length=256)
    alias_suffix: Optional[str] = Field(default=None, max_length=64)
    alias_email: Optional[str] = Field(default=None, max_length=256)
    timeout: int = Field(default=300, ge=10, le=600)


class HelperRegisterRequest(BaseModel):
    token: str = Field(min_length=16, max_length=256)
    version: str = Field(default="", max_length=32)
    platform: str = Field(default="", max_length=64)


class HelperTaskResultRequest(BaseModel):
    task_id: str = Field(min_length=1, max_length=64)
    # 其它字段（success / data / error / ...）让 Helper 自由填，
    # 通过 ``request.json()`` 拿原始 dict 转发。这里只校验 task_id 必填。


class HelperTaskLogEntry(BaseModel):
    message: str = Field(default="", max_length=4096)
    level: str = Field(default="info", max_length=16)


class HelperTaskLogRequest(BaseModel):
    task_id: Optional[str] = Field(default=None, max_length=64)
    message: Optional[str] = Field(default=None, max_length=4096)
    level: Optional[str] = Field(default="info", max_length=16)
    logs: Optional[list[HelperTaskLogEntry]] = None


# ── Web 面板路由（受 cookie + xiaoxuan 保护） ────────────────────


@helper_router.post("/provision-token")
def provision_token(
    req: ProvisionTokenRequest,
    request: Request,
    user: dict = Depends(require_owner),
) -> dict:
    """生成一个新的 helper token。

    防御：每用户最多 ``MAX_TOKENS_PER_USER`` 个未撤销 token；超出直接 400
    并附明确文案，引导用户去 Help 页清理旧 token。
    """
    label = (req.label or "").strip() or None
    try:
        token = _tk.provision_token(owner_id=user["id"], label=label)
    except ValueError as e:
        _audit(
            request, user, "helper_provision_token",
            target=label or "(unlabeled)",
            success=False, detail=str(e)[:200],
        )
        return {"success": False, "error": str(e)}
    _audit(
        request, user, "helper_provision_token",
        target=label or "(unlabeled)",
        detail=f"token=...{token[-8:]}",
    )
    return {
        "success": True,
        "token": token,
        "label": label,
        "ttl_seconds": _tk.DEFAULT_TTL_SECONDS,
    }


@helper_router.get("/status")
def helper_status(user: dict = Depends(require_owner)) -> dict:
    """前端轮询：返回当前 helper 在线情况。

    增量字段（v0.1.1）：
    - ``min_helper_version``：服务端期望的最低 helper 版本
    - ``version_ok``：当前 helper.version 是否满足 ``min_helper_version``
    """
    info = registry.status(owner_id=user["id"])
    info["min_helper_version"] = MIN_HELPER_VERSION
    if info.get("online"):
        info["version_ok"] = _version_ok(info.get("version") or "")
    return {"success": True, **info}


@helper_router.get("/tokens")
def list_tokens(user: dict = Depends(require_owner)) -> dict:
    """列出当前用户所有未撤销 token（脱敏后返回）。"""
    items = _tk.list_tokens(owner_id=user["id"], include_revoked=False)
    redacted = []
    for it in items:
        t = it.get("token") or ""
        redacted.append({
            **it,
            "token": (t[:12] + "..." + t[-4:]) if len(t) > 20 else t,
        })
    return {"success": True, "tokens": redacted}


@helper_router.post("/revoke")
def revoke(
    req: RevokeRequest,
    request: Request,
    user: dict = Depends(require_owner),
) -> dict:
    """撤销 token。

    - 不传参数 → 撤销当前在线 Helper 的 token
    - 传 ``token`` → 撤销指定 token（必须归当前用户）
    - 传 ``all=true`` → 撤销当前用户全部 token
    """
    owner_id = user["id"]
    if req.all:
        n = _tk.revoke_all(owner_id=owner_id)
        sess = registry.get_online(owner_id=owner_id)
        if sess:
            registry.unregister(sess.helper_id)
        _audit(
            request, user, "helper_revoke",
            target="*all*", detail=f"revoked={n}",
        )
        return {"success": True, "revoked": n}

    token = (req.token or "").strip()
    if not token:
        sess = registry.get_online(owner_id=owner_id)
        if not sess:
            return {"success": False, "error": "当前没有在线 Helper"}
        token = sess.token

    ok = _tk.revoke_token(token, owner_id=owner_id)
    if ok:
        # 把对应 session 踢掉
        for hid, sess in list(registry._sessions.items()):  # noqa: SLF001
            if sess.token == token:
                registry.unregister(hid)
    _audit(
        request, user, "helper_revoke",
        target=f"...{token[-8:]}",
        success=ok,
        detail=f"revoked={1 if ok else 0}",
    )
    return {"success": ok, "revoked": 1 if ok else 0}


@helper_router.get("/download-info")
def download_info(user: dict = Depends(require_owner)) -> dict:
    """告诉前端服务器上是否已有打包好的 Helper .exe / 安装脚本。"""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    static_dir = os.path.join(base_dir, "static", "helper")
    out = {
        "success": True,
        "exe": None,
        "install_script": None,
        "uninstall_script": None,
    }
    candidates = {
        "exe": ("EmailHelper.exe", "/static/helper/EmailHelper.exe"),
        "install_script": ("install.ps1", "/static/helper/install.ps1"),
        "uninstall_script": ("uninstall.ps1", "/static/helper/uninstall.ps1"),
    }
    for key, (fname, url) in candidates.items():
        path = os.path.join(static_dir, fname)
        if os.path.isfile(path):
            try:
                size = os.path.getsize(path)
            except OSError:
                size = None
            out[key] = {"url": url, "size": size}
    return out


# /api/helper/dispatch 允许的 action 白名单：
# - 连通性测试（与 ALWAYS_ALLOWED_ACTIONS 对齐）
# - 4 个邮箱业务（与 helper.handlers.install_default_handlers 注册的对齐）
# 限制目的：dispatch 是开放接口，可以收任意 ``action`` 字符串；如果不限制，
# 前端误传 / 攻击者构造的奇怪 action 也能进 helper outbox 队列、消耗任务超时
# 名额（每个 dispatch 都阻塞一个线程池 worker）。白名单挡住这些边缘情况。
_DISPATCH_ALLOWED_ACTIONS = frozenset({
    "echo", "ping", "version",
    "open_mailbox", "get_ms_token",
    "change_email_password", "bind_recovery_email",
})


@helper_router.post("/dispatch")
async def dispatch(
    req: DispatchRequest,
    request: Request,
    user: dict = Depends(require_owner),
) -> dict:
    """手工把任意 action 派给在线 Helper（调试 + 业务路由复用）。

    阻塞调用 ``registry.dispatch``，必须包 ``run_in_threadpool`` 防止
    阻塞 asyncio event loop。

    安全：仅允许 ``_DISPATCH_ALLOWED_ACTIONS`` 里的 action 通过。业务接口
    （mailbox/*）走专门的路由不受此限。
    """
    if req.action not in _DISPATCH_ALLOWED_ACTIONS:
        _audit(request, user, "helper_dispatch",
               target=req.action, success=False,
               detail="action_not_allowed")
        return {
            "success": False,
            "error": f"不允许的 action：{req.action}。"
                     f"允许列表：{sorted(_DISPATCH_ALLOWED_ACTIONS)}",
        }
    # params 大小防护：单 dispatch 不应该塞大对象进 helper outbox（避免大对象
    # 在内存中常驻 + 序列化耗 CPU）
    if isinstance(req.params, dict) and len(req.params) > 32:
        return {
            "success": False,
            "error": f"params 字段过多（{len(req.params)} > 32）",
        }
    result = await run_in_threadpool(
        registry.dispatch,
        req.action, req.params, req.timeout, user["id"],
    )
    # echo / ping / version 是连通性测试，写 audit 会刷屏，跳过
    if req.action not in {"echo", "ping", "version"}:
        _audit(request, user, f"helper_dispatch_{req.action}",
               target=str(req.params)[:200],
               success=bool(result.get("success")),
               detail=f"task_id={result.get('task_id', '?')}")
    return result


class CancelTaskRequest(BaseModel):
    task_id: str = Field(min_length=1, max_length=64)


@helper_router.post("/cancel-task")
def cancel_task(
    req: CancelTaskRequest, user: dict = Depends(require_owner),
) -> dict:
    """取消正在执行 / 等待结果的任务。

    实际效果：等结果的 dispatch 调用立即用 ``cancelled=True`` 返回 → 前端
    Modal 立刻关闭。Helper 那边任务**仍会跑完**（HTTP 长轮询不能中断已派的
    task），但用户不再被卡住。已派 task 的 result 会被丢弃。
    """
    ok = registry.cancel_task(user["id"], req.task_id)
    if ok:
        registry.broadcast_log(
            user["id"],
            f"🛑 用户请求取消任务 task_id={req.task_id}",
            "warning",
        )
    return {"success": ok, "task_id": req.task_id}


# ── 邮箱业务封装 ────────────────────────────────────────────────


def _resolve_account_credentials(
    owner_id: int,
    account_id: Optional[int],
    email: Optional[str],
    email_password: Optional[str],
) -> tuple[Optional[str], Optional[str], Optional[dict]]:
    """根据 ``account_id`` 从账号表取出 email + password；或直接用入参。

    返回 ``(email, password, error_payload)``：
    - ``error_payload`` 非 None 时直接作为 400 响应体返回。
    - account_id 指向不存在的账号 → 返回 ``code="stale_account_id"`` 让前端
      自动 ``loadAccounts()`` 刷新表格（与 cursor-manager 0.1.10 的修复一致）。
    """
    if account_id is not None:
        if _db is None:
            return None, None, {"success": False, "error": "数据库未初始化"}
        acc = _db.get_account(owner_id, account_id)
        if not acc:
            return None, None, {
                "success": False,
                "error": f"账号不存在: id={account_id}",
                "code": "stale_account_id",
                "stale_account_id": account_id,
            }
        return (
            (acc.email or "").strip().lower(),
            acc.password or "",
            None,
        )

    eml = (email or "").strip().lower()
    if not eml:
        return None, None, {
            "success": False,
            "error": "必须提供 account_id 或 email",
        }
    return eml, email_password or "", None


def _audit_mailbox_op(
    request: Request, user: dict, action: str, email: str, result: dict,
) -> None:
    """4 个 mailbox/* 接口完成后统一写一条 audit log。"""
    ok = bool(result.get("success"))
    detail_parts = [f"task_id={result.get('task_id', '?')}"]
    if not ok and result.get("error"):
        detail_parts.append(f"err={str(result['error'])[:120]}")
    if result.get("offline"):
        detail_parts.append("offline")
    if result.get("cancelled"):
        detail_parts.append("cancelled")
    if result.get("needs_helper_upgrade"):
        detail_parts.append(f"upgrade_required>={result.get('min_version')}")
    _audit(
        request, user, action,
        target=email, success=ok,
        detail=",".join(detail_parts),
    )


@helper_router.post("/mailbox/open")
async def mailbox_open(
    req: MailboxOpenRequest,
    request: Request,
    user: dict = Depends(require_owner),
) -> dict:
    """让 Helper 在本地启动浏览器、自动登录 Outlook 邮箱并保持打开。"""
    email, password, err = _resolve_account_credentials(
        user["id"], req.account_id, req.email, req.email_password,
    )
    if err:
        _audit(request, user, "helper_mailbox_open",
               target=str(req.account_id or req.email or "?"),
               success=False, detail=err.get("error", "")[:200])
        return err
    if not password:
        _audit(request, user, "helper_mailbox_open", target=email,
               success=False, detail="missing_password")
        return {"success": False, "error": "缺少邮箱密码（账号未保存或未提供）"}

    result = await run_in_threadpool(
        registry.dispatch,
        "open_mailbox",
        {"email": email, "email_password": password},
        req.timeout,
        user["id"],
    )
    _audit_mailbox_op(request, user, "helper_mailbox_open", email, result)
    return result


@helper_router.post("/mailbox/get-token")
async def mailbox_get_token(
    req: MailboxGetTokenRequest,
    request: Request,
    user: dict = Depends(require_owner),
) -> dict:
    """让 Helper 在已打开的邮箱里完成 MS OAuth → 拿 refresh_token + 落库。

    若提供 ``account_id``：更新该账号的 client_id / refresh_token。
    若仅提供 ``email``：作为新账号（或同 email 已存在的账号）添加 / 更新。
    """
    email, _password, err = _resolve_account_credentials(
        user["id"], req.account_id, req.email, None,
    )
    if err:
        _audit(request, user, "helper_mailbox_get_token",
               target=str(req.account_id or req.email or "?"),
               success=False, detail=err.get("error", "")[:200])
        return err

    result = await run_in_threadpool(
        registry.dispatch,
        "get_ms_token",
        {"email": email},
        req.timeout,
        user["id"],
    )
    if not result.get("success"):
        _audit_mailbox_op(request, user, "helper_mailbox_get_token", email, result)
        return result

    data = result.get("data") or {}
    client_id = (data.get("client_id") or "").strip()
    refresh_token = (data.get("refresh_token") or "").strip()
    if not client_id or not refresh_token:
        ret = {
            "success": False,
            "error": "Helper 返回的 client_id / refresh_token 缺失",
            "data": data,
            "task_id": result.get("task_id"),
        }
        _audit_mailbox_op(request, user, "helper_mailbox_get_token", email, ret)
        return ret

    if _db is None:
        return {"success": False, "error": "数据库未初始化"}

    if req.account_id is not None:
        ok = _db.update_account_oauth(
            user["id"], req.account_id, client_id, refresh_token,
        )
        ret = (
            {"success": True, "email": email, "updated": True,
             "task_id": result.get("task_id")}
            if ok else
            {"success": False, "error": "更新已有账号失败",
             "task_id": result.get("task_id")}
        )
        _audit_mailbox_op(request, user, "helper_mailbox_get_token", email, ret)
        return ret

    existing = _db.get_account_by_email(user["id"], email)
    if existing:
        ok = _db.update_account_oauth(
            user["id"], existing.id, client_id, refresh_token,
        )
        ret = (
            {"success": True, "email": email, "updated": True,
             "task_id": result.get("task_id")}
            if ok else
            {"success": False, "error": "更新已有账号失败",
             "task_id": result.get("task_id")}
        )
        _audit_mailbox_op(request, user, "helper_mailbox_get_token", email, ret)
        return ret

    group = (req.group or "默认分组").strip() or "默认分组"
    ok, msg = _db.add_account(
        user["id"], email, "", group,
        client_id=client_id, refresh_token=refresh_token,
    )
    if not ok:
        ret = {"success": False, "error": f"添加账号失败: {msg}",
               "task_id": result.get("task_id")}
        _audit_mailbox_op(request, user, "helper_mailbox_get_token", email, ret)
        return ret
    ret = {"success": True, "email": email, "updated": False,
           "task_id": result.get("task_id")}
    _audit_mailbox_op(request, user, "helper_mailbox_get_token", email, ret)
    return ret


@helper_router.post("/mailbox/change-password")
async def mailbox_change_password(
    req: MailboxChangePasswordRequest,
    request: Request,
    user: dict = Depends(require_owner),
) -> dict:
    """让 Helper 在已打开的邮箱里自动改 Outlook 密码。

    成功后**自动把新密码写回 DB 中该账号的 password 字段**，避免后续登录
    用旧密码失败。
    """
    email, password, err = _resolve_account_credentials(
        user["id"], req.account_id, req.email, req.email_password,
    )
    if err:
        _audit(request, user, "helper_mailbox_change_password",
               target=str(req.account_id or req.email or "?"),
               success=False, detail=err.get("error", "")[:200])
        return err
    if not password:
        _audit(request, user, "helper_mailbox_change_password", target=email,
               success=False, detail="missing_password")
        return {"success": False, "error": "缺少当前密码（账号未保存或未提供）"}

    result = await run_in_threadpool(
        registry.dispatch,
        "change_email_password",
        {
            "email": email,
            "email_password": password,
            "new_password": req.new_password,
        },
        req.timeout,
        user["id"],
    )
    if result.get("success") and _db is not None and req.account_id is not None:
        try:
            _db.update_account_password(user["id"], req.account_id, req.new_password)
        except Exception as e:  # noqa: BLE001
            logger.exception("改密成功但更新 DB 失败 account_id=%s: %s",
                             req.account_id, e)
            result["db_update_failed"] = str(e)
    _audit_mailbox_op(request, user, "helper_mailbox_change_password", email, result)
    return result


# ── 批量 helper 操作（SSE 流式） ────────────────────────────────


class BatchMailboxRequest(BaseModel):
    """批量 helper 操作请求。

    - ``action``：``open_mailbox`` / ``get_ms_token`` / ``bind_recovery_email``
      （``change_email_password`` 不支持批量 —— 一次性给所有账号设同一密码
      在生产场景几乎没意义，且容易误操作）
    - ``account_ids``：要操作的账号 ID 列表
    - ``timeout``：单个任务的超时（默认 180s）
    - 串行执行，每完成一个就 yield 一条 SSE progress 事件
    """
    action: str = Field(min_length=1, max_length=64)
    account_ids: list[int] = Field(min_length=1, max_length=200)
    timeout: int = Field(default=180, ge=10, le=600)


_BATCH_ALLOWED_ACTIONS = frozenset({
    "open_mailbox",
    "get_ms_token",
    "bind_recovery_email",
})


@helper_router.post("/batch/mailbox")
async def batch_mailbox(
    req: BatchMailboxRequest,
    request: Request,
    user: dict = Depends(require_owner),
) -> StreamingResponse:
    """串行批量调一个 mailbox action 给一组账号，SSE 流回进度。

    设计取舍：串行（不是并发）—— 因为本地 Helper 只有一个 Chromium 实例池，
    并发 N 个 open_mailbox 会让浏览器抢资源、Outlook 风控触发更猛。
    """
    if req.action not in _BATCH_ALLOWED_ACTIONS:
        return StreamingResponse(
            iter([
                _sse({
                    "type": "done", "success": 0, "fail": 1,
                    "error": f"批量不支持 action: {req.action}",
                })
            ]),
            media_type="text/event-stream", headers=_SSE_HEADERS,
        )

    owner_id = user["id"]
    total = len(req.account_ids)

    # 批量审计聚合策略（v0.1.3）：
    # - 入口写 1 条 "helper_batch_<action>_start" 审计（含总数）
    # - 仅**失败**的账号单独写一条审计（便于运维定位）；成功的不写，避免
    #   N=200 时每跑一个写一条 → 总共 200 条 helper_batch_* 记录把表炸了
    # - 完成写 1 条 "helper_batch_<action>_done" 含 success/fail/total
    _audit(
        request, user, f"helper_batch_{req.action}_start",
        target=f"accounts={total}",
        detail=f"timeout={req.timeout}",
    )

    async def generate():
        success_cnt = 0
        fail_cnt = 0
        aborted = False
        try:
            for idx, aid in enumerate(req.account_ids):
                if await request.is_disconnected():
                    aborted = True
                    break

                if _db is None:
                    acc = None
                else:
                    acc = _db.get_account(owner_id, aid)
                if not acc:
                    fail_cnt += 1
                    _audit(
                        request, user, f"helper_batch_{req.action}",
                        target=f"account_id={aid}",
                        success=False, detail="stale_account_id",
                    )
                    yield _sse({
                        "type": "progress",
                        "current": idx + 1, "total": total,
                        "account_id": aid, "email": "?",
                        "success": False,
                        "error": "账号不存在或已删除",
                        "code": "stale_account_id",
                    })
                    continue

                email = (acc.email or "").strip().lower()
                params: dict = {"email": email}
                if req.action in {"open_mailbox", "change_email_password"}:
                    params["email_password"] = acc.password or ""

                result = await run_in_threadpool(
                    registry.dispatch,
                    req.action, params, req.timeout, owner_id,
                )

                if (
                    req.action == "get_ms_token"
                    and result.get("success")
                    and _db is not None
                ):
                    data = result.get("data") or {}
                    client_id = (data.get("client_id") or "").strip()
                    refresh_token = (data.get("refresh_token") or "").strip()
                    if client_id and refresh_token:
                        try:
                            _db.update_account_oauth(
                                owner_id, aid, client_id, refresh_token,
                            )
                        except Exception as e:  # noqa: BLE001
                            logger.exception(
                                "批量 get_ms_token 落库失败 aid=%s: %s",
                                aid, e,
                            )
                            result["db_update_failed"] = str(e)

                ok = bool(result.get("success"))
                if ok:
                    success_cnt += 1
                else:
                    fail_cnt += 1
                    # 仅失败时单独写审计
                    _audit_mailbox_op(
                        request, user, f"helper_batch_{req.action}",
                        email, result,
                    )

                yield _sse({
                    "type": "progress",
                    "current": idx + 1, "total": total,
                    "account_id": aid,
                    "email": email,
                    "success": ok,
                    "error": result.get("error") or "",
                    "task_id": result.get("task_id"),
                    "needs_helper_upgrade": result.get("needs_helper_upgrade", False),
                })
        finally:
            # 不管正常完成还是 abort，都写一条汇总（让 audit_log 可追溯）
            _audit(
                request, user, f"helper_batch_{req.action}_done",
                target=f"accounts={total}",
                success=(fail_cnt == 0 and not aborted),
                detail=(
                    f"success={success_cnt},fail={fail_cnt},"
                    f"total={total},aborted={'1' if aborted else '0'}"
                ),
            )

        yield _sse({
            "type": "done",
            "success": success_cnt, "fail": fail_cnt,
            "total": total,
        })

    return StreamingResponse(
        generate(), media_type="text/event-stream", headers=_SSE_HEADERS,
    )


def _sse(payload: dict) -> str:
    """与 web_app._sse 同款的 SSE 行编码。"""
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


@helper_router.post("/mailbox/bind-recovery")
async def mailbox_bind_recovery(
    req: MailboxBindRecoveryRequest,
    request: Request,
    user: dict = Depends(require_owner),
) -> dict:
    """让 Helper 在已打开的邮箱里自动绑定辅助邮箱。"""
    email, _password, err = _resolve_account_credentials(
        user["id"], req.account_id, req.email, None,
    )
    if err:
        _audit(request, user, "helper_mailbox_bind_recovery",
               target=str(req.account_id or req.email or "?"),
               success=False, detail=err.get("error", "")[:200])
        return err

    params: dict = {"email": email}
    if req.alias_suffix:
        params["alias_suffix"] = req.alias_suffix
    if req.alias_email:
        params["alias_email"] = req.alias_email
    result = await run_in_threadpool(
        registry.dispatch,
        "bind_recovery_email",
        params,
        req.timeout,
        user["id"],
    )
    _audit_mailbox_op(request, user, "helper_mailbox_bind_recovery", email, result)
    return result


# ── 实时日志 SSE ────────────────────────────────────────────────


_SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",
    "X-Content-Type-Options": "nosniff",
}


@helper_router.get("/logs")
async def helper_logs(
    request: Request, user: dict = Depends(require_owner),
) -> StreamingResponse:
    """订阅 helper 推回的实时日志。

    用 SSE：浏览器 ``EventSource`` 自动重连，单向流，比 WebSocket 简单太多。
    每个连接独占一个 queue.Queue；用户关闭页面 → ``request.is_disconnected``
    迅速返回 True，generate() 在 finally 中 unsubscribe。
    """
    owner_id = user["id"]
    q = subscribe_logs(owner_id)
    logger.info("[helper] SSE 订阅 owner_id=%d", owner_id)

    async def generate():
        try:
            # 入场时立刻推一条空 retry，让浏览器知道连接已建立
            yield "retry: 5000\n\n"
            while True:
                if await request.is_disconnected():
                    break
                # queue.get 是阻塞的；用 to_thread 释放 event loop
                try:
                    payload = await asyncio.wait_for(
                        run_in_threadpool(q.get, True, 15.0),
                        timeout=16.0,
                    )
                except (asyncio.TimeoutError, Exception):
                    # 15s 没消息 → 推一条 keepalive 给浏览器，避免被反代当 idle 切
                    yield ": keepalive\n\n"
                    continue
                if not payload or payload.get("type") == "_disconnect":
                    break
                yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
        finally:
            unsubscribe_logs(owner_id, q)
            logger.info("[helper] SSE 断开 owner_id=%d", owner_id)

    return StreamingResponse(
        generate(), media_type="text/event-stream", headers=_SSE_HEADERS,
    )


# ── Helper 客户端路由（鉴权方式：token / helper_id） ────────────


def _helper_id_from_request(request: Request) -> Optional[str]:
    """X-Helper-Id header 或 query string 取 helper_id。"""
    hid = request.headers.get("x-helper-id") or request.query_params.get("helper_id")
    return hid.strip() if hid else None


@helper_router.post("/register")
def helper_register(req: HelperRegisterRequest) -> dict:
    """Helper 客户端注册：提交 {token, version, platform}，返回 {helper_id}。"""
    sess, err = registry.register(req.token.strip(), req.version, req.platform)
    if err or not sess:
        return JSONResponse(
            {"success": False, "error": err or "注册失败"},
            status_code=401,
        )
    return {
        "success": True,
        "helper_id": sess.helper_id,
        "server_time": int(time.time()),
        "poll_block_seconds": POLL_BLOCK_SECONDS,
    }


@helper_router.get("/poll-task")
async def helper_poll_task(
    request: Request,
    timeout: float = Query(default=POLL_BLOCK_SECONDS, ge=0, le=60),
) -> JSONResponse:
    """Helper 长轮询：阻塞最多 ``POLL_BLOCK_SECONDS`` 秒，期间有任务就返回。"""
    helper_id = _helper_id_from_request(request)
    if not helper_id:
        return JSONResponse(
            {"success": False, "error": "缺少 helper_id"}, status_code=400,
        )
    sess = registry.get(helper_id)
    if not sess:
        return JSONResponse(
            {
                "success": False,
                "error": "helper_id 失效，请重新 register",
                "needs_register": True,
            },
            status_code=401,
        )

    sess.touch()
    # drain 是阻塞的；放到线程池里跑
    tasks = await run_in_threadpool(sess.drain, float(timeout))
    sess.touch()
    return JSONResponse({"success": True, "tasks": tasks})


@helper_router.post("/task-result")
async def helper_task_result(request: Request) -> JSONResponse:
    """Helper 上报任务结果。"""
    helper_id = _helper_id_from_request(request)
    if not helper_id:
        return JSONResponse(
            {"success": False, "error": "缺少 helper_id"}, status_code=400,
        )

    try:
        msg = await request.json()
        if not isinstance(msg, dict):
            raise ValueError("body must be object")
    except (ValueError, json.JSONDecodeError):
        return JSONResponse(
            {"success": False, "error": "请求体不是合法 JSON"}, status_code=400,
        )

    if not msg.get("task_id"):
        return JSONResponse(
            {"success": False, "error": "缺少 task_id"}, status_code=400,
        )

    ok = registry.submit_result(helper_id, msg)
    if not ok:
        if not registry.get(helper_id):
            return JSONResponse(
                {
                    "success": False,
                    "error": "helper_id 失效",
                    "needs_register": True,
                },
                status_code=401,
            )
    return JSONResponse({"success": True, "accepted": ok})


@helper_router.post("/task-log")
async def helper_task_log(request: Request) -> JSONResponse:
    """Helper 上报任务实时日志（单条 message+level，或 logs=[{...}] 批量）。"""
    helper_id = _helper_id_from_request(request)
    if not helper_id:
        return JSONResponse(
            {"success": False, "error": "缺少 helper_id"}, status_code=400,
        )

    try:
        msg = await request.json()
        if not isinstance(msg, dict):
            raise ValueError
    except (ValueError, json.JSONDecodeError):
        return JSONResponse(
            {"success": False, "error": "请求体不是合法 JSON"}, status_code=400,
        )

    ok = registry.submit_log(helper_id, msg)
    if not ok and not registry.get(helper_id):
        return JSONResponse(
            {
                "success": False,
                "error": "helper_id 失效",
                "needs_register": True,
            },
            status_code=401,
        )
    return JSONResponse({"success": True})


@helper_router.post("/heartbeat")
def helper_heartbeat(request: Request) -> JSONResponse:
    """Helper 保活心跳。空 body 即可。"""
    helper_id = _helper_id_from_request(request)
    if not helper_id:
        return JSONResponse(
            {"success": False, "error": "缺少 helper_id"}, status_code=400,
        )
    ok = registry.heartbeat(helper_id)
    if not ok:
        return JSONResponse(
            {
                "success": False,
                "error": "helper_id 失效",
                "needs_register": True,
            },
            status_code=401,
        )
    return JSONResponse({"success": True, "server_time": int(time.time())})


__all__ = ("helper_router", "configure", "require_owner")
