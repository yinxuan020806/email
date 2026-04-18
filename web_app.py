# -*- coding: utf-8 -*-
"""
邮箱管家 Web 版 - FastAPI 后端（多用户隔离）。

启动:
    python web_app.py
    # 或
    uvicorn web_app:app --host 127.0.0.1 --port 8000

环境变量:
    EMAIL_WEB_HOST       - 监听地址 (默认 127.0.0.1，仅本地)
    EMAIL_WEB_PORT       - 监听端口 (默认 8000)
    EMAIL_WEB_CORS       - 额外允许的跨域来源 (逗号分隔)，默认仅同源
    EMAIL_WEB_SSL_KEY    - 可选 TLS 私钥路径
    EMAIL_WEB_SSL_CERT   - 可选 TLS 证书路径
    EMAIL_WEB_COOKIE_TTL - 会话 cookie 有效期（秒），默认 7 天
    EMAIL_WEB_DISABLE_REGISTER - 1 表示禁止新用户注册
    EMAIL_DATA_DIR       - 数据目录 (默认 ./data，容器场景挂载到 /data)
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import urllib.parse
from typing import List, Optional

import certifi
import requests as req_lib
from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.auth import (  # noqa: E402
    hash_password,
    normalize_username,
    validate_password,
    validate_username,
    verify_password,
)
from core.email_client import EmailClient  # noqa: E402
from core.models import Account  # noqa: E402
from core.oauth2_helper import OAuth2Helper, TOKEN_URL  # noqa: E402
from core.rate_limit import login_limiter  # noqa: E402
from core.security_check import emit_warnings  # noqa: E402
from database.db_manager import (  # noqa: E402
    ALLOWED_SETTING_KEYS,
    DatabaseManager,
    get_data_dir,
)

logging.basicConfig(
    level=os.getenv("EMAIL_WEB_LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("email_web")


# ── App & 中间件 ────────────────────────────────────────────────

app = FastAPI(title="邮箱管家 Web", version="3.0.0")

_extra_cors = [s.strip() for s in os.getenv("EMAIL_WEB_CORS", "").split(",") if s.strip()]
if _extra_cors:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_extra_cors,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# ── 静态资源 ────────────────────────────────────────────────────

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# ── 数据库 ──────────────────────────────────────────────────────

db = DatabaseManager()

# ── 配置 ────────────────────────────────────────────────────────

SESSION_COOKIE = "email_web_session"
COOKIE_TTL = int(os.getenv("EMAIL_WEB_COOKIE_TTL", str(7 * 24 * 3600)))
DISABLE_REGISTER = os.getenv("EMAIL_WEB_DISABLE_REGISTER", "").strip() in {"1", "true", "yes"}

# SPA 路由前缀：未匹配到 /api、/static 时如果是这些路径，返回 index.html
SPA_PATHS = {"/login", "/register", "/dashboard", "/settings", "/oauth"}


def _client_ip(request: Request) -> str:
    """获取客户端真实 IP，支持反代场景的 X-Forwarded-For。"""
    xff = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if xff:
        return xff
    real = request.headers.get("x-real-ip", "").strip()
    if real:
        return real
    return request.client.host if request.client else "unknown"


def _is_https(request: Request) -> bool:
    """判断当前请求是否为 HTTPS（识别反向代理场景）。"""
    if request.url.scheme == "https":
        return True
    proto = request.headers.get("x-forwarded-proto", "").lower()
    return "https" in proto


# ── 鉴权依赖 ────────────────────────────────────────────────────


def get_current_user(
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict:
    """从 cookie 中解析当前登录用户；未登录或会话过期返回 401。"""
    user = db.get_session_user(session_token or "")
    if not user:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "未登录或会话已过期",
            headers={"WWW-Authenticate": "Cookie"},
        )
    return user


CurrentUser = Depends(get_current_user)

# ── 模型 ────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class ImportRequest(BaseModel):
    text: str
    group: str = "默认分组"
    skip_duplicate: bool = True

    @field_validator("group")
    @classmethod
    def _trim_group(cls, v: str) -> str:
        return (v or "").strip() or "默认分组"


class DeleteAccountsRequest(BaseModel):
    ids: List[int] = Field(min_length=1, max_length=10000)


class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)

    @field_validator("name")
    @classmethod
    def _non_blank(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("分组名不能为空")
        return v


class GroupRename(BaseModel):
    new_name: str = Field(min_length=1, max_length=64)

    @field_validator("new_name")
    @classmethod
    def _non_blank(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("分组名不能为空")
        return v


class GroupUpdate(BaseModel):
    group: str

    @field_validator("group")
    @classmethod
    def _trim(cls, v: str) -> str:
        return (v or "").strip() or "默认分组"


class RemarkUpdate(BaseModel):
    remark: str = Field(default="", max_length=500)


class SendEmailRequest(BaseModel):
    to: str
    subject: str
    body: str
    cc: Optional[str] = None


class BatchCheckRequest(BaseModel):
    account_ids: List[int] = Field(min_length=1, max_length=10000)


class BatchSendRequest(BaseModel):
    account_ids: List[int] = Field(min_length=1, max_length=10000)
    to: str = Field(min_length=1, max_length=4000)
    subject: str = Field(min_length=1, max_length=998)  # RFC 2822 line limit
    body: str = Field(default="", max_length=1024 * 1024)  # 1 MiB


class SettingUpdate(BaseModel):
    key: str
    value: str


class MarkReadRequest(BaseModel):
    email_id: str
    folder: str = "inbox"
    is_read: bool = True


class DeleteEmailRequest(BaseModel):
    email_id: str
    folder: str = "inbox"


class ExportRequest(BaseModel):
    """导出账号需要二次密码确认。"""
    password: str = Field(min_length=1, max_length=256)
    group: Optional[str] = None
    include_group: bool = True   # True 时每行末尾追加 ----组名（便于回导入恢复）
    separator: str = "newline"   # "newline" 一行一个；"dollar" 用 $$ 拼接成单行


# ── Helpers ─────────────────────────────────────────────────────


def account_to_dict(acc: Account) -> dict:
    """Account → 给前端的 dict（含密码，仅在本地受信任环境下使用）。"""
    return {
        "id": acc.id,
        "email": acc.email,
        "password": acc.password,
        "group": acc.group_name,
        "status": acc.status,
        "type": acc.account_type,
        "imap_server": acc.imap_server,
        "imap_port": acc.imap_port,
        "smtp_server": acc.smtp_server,
        "smtp_port": acc.smtp_port,
        "client_id": acc.client_id,
        "refresh_token": acc.refresh_token,
        "created_at": acc.created_at,
        "last_check": acc.last_check,
        "has_aws_code": bool(acc.has_aws_code),
        "remark": acc.remark,
    }


def get_account_or_404(owner_id: int, account_id: int) -> Account:
    acc = db.get_account(owner_id, account_id)
    if not acc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")
    return acc


def create_client(owner_id: int, acc: Account) -> EmailClient:
    return EmailClient(
        acc.email,
        acc.password,
        acc.imap_server,
        acc.imap_port or 993,
        client_id=acc.client_id,
        refresh_token=acc.refresh_token,
        account_id=acc.id,
        on_token_refresh=lambda aid, cid, rt: db.update_account_oauth(
            owner_id, aid, cid, rt
        ),
    )


def _looks_like_group_name(s: str) -> bool:
    """判断一段字符串是否更像分组名而非 token/email/密码。

    经验规则：
    - 长度 1-64
    - 不含 @ / / + / = 这种 email/base64 标志字符
    - 字符集为字母数字 + 中文 + 常见符号（_-.中文空格）
    """
    if not s:
        return False
    s = s.strip()
    if not s or len(s) > 64:
        return False
    if any(c in s for c in "@/+="):
        return False
    # 任何可见字符都允许，但典型 token 通常很长或含特殊字符；这里再做一次严格判断
    # 拒绝包含太多奇异字符的串
    bad = sum(1 for c in s if not (c.isalnum() or c in "_-. \u4e00-\u9fff" or "\u4e00" <= c <= "\u9fff"))
    if bad > 2:
        return False
    return True


def _parse_one_account(fields: List[str]) -> Optional[dict]:
    """从切好的 ``----`` 字段列表组装一条账号。

    字段语义按字段数判定：

    - 2 段：email, password
    - 3 段：email, password, group  (client_id 不可能单独存在)
    - 4 段：email, password, client_id, refresh_token
    - 5+ 段：email, password, client_id, refresh_token, ...group
      （从尾部向前找第一个像组名的非空字段）

    "像组名"的判定见 ``_looks_like_group_name``。
    """
    fields = [f.strip() for f in fields]
    if not fields or "@" not in fields[0]:
        return None
    data: dict = {"email": fields[0], "password": ""}
    if len(fields) >= 2:
        data["password"] = fields[1]

    n = len(fields)
    if n == 3:
        if fields[2] and _looks_like_group_name(fields[2]):
            data["group"] = fields[2]
    elif n >= 4:
        if fields[2]:
            data["client_id"] = fields[2]
        if fields[3]:
            data["refresh_token"] = fields[3]
        if n >= 5:
            for f in reversed(fields[4:]):
                if _looks_like_group_name(f):
                    data["group"] = f.strip()
                    break
    return data


def parse_import_text(text: str) -> List[dict]:
    """解析批量导入文本。

    支持的格式（每行 / 每段 / 多段一行均可）::

        email----password
        email----password----组名
        email----password----client_id----refresh_token
        email----password----client_id----refresh_token----组名
        email----password----client_id----refresh_token$$--------组名   <- 用户工具常见格式

    分隔符：
    - ``\\n`` 行间
    - ``$$`` 段间（同一行内可多账号 / 也可附加元数据）

    解析策略：每行先按 ``$$`` 切段，遇到不以 email 开头的段视为
    "上一个账号的元数据扩展"，把字段拼接到上一个账号后面，再做组名启发式判断。
    """
    accounts: list[dict] = []
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        return accounts

    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue

        if "$$" in line:
            segments = [s for s in line.split("$$") if s.strip()]
        else:
            segments = [line]

        # 在一行内累积：以 email 开头的段是新账号，其它段追加到上一个
        pending: Optional[List[str]] = None
        line_accounts: list[List[str]] = []
        for seg in segments:
            seg = seg.strip().rstrip("$")
            if not seg:
                continue
            fields = seg.split("----")
            head = fields[0].strip() if fields else ""
            if "@" in head:
                if pending is not None:
                    line_accounts.append(pending)
                pending = fields
            else:
                if pending is None:
                    # 没有上下文的"裸元数据"，跳过
                    continue
                pending.extend(fields)
        if pending is not None:
            line_accounts.append(pending)

        for fields in line_accounts:
            if "----" not in "----".join(fields):
                # 极端情况下 segment 只有一段
                continue
            data = _parse_one_account(fields)
            if data:
                accounts.append(data)

    return accounts


def _set_session_cookie(response: Response, token: str, request: Request) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=COOKIE_TTL,
        httponly=True,
        secure=_is_https(request),
        samesite="lax",
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


# ── Root & Health ───────────────────────────────────────────────


_INDEX_CACHE: dict = {"path": None, "version": "0", "html": None, "mtime": 0.0}


def _compute_static_version() -> str:
    """以 static 目录下关键资源的最大 mtime 作为版本号。

    每次重新部署 docker（COPY static），文件 mtime 变更，version 自动更新，
    浏览器与 Cloudflare 都能识别为新 URL。
    """
    files = ("app.js", "app.css", "i18n.js", "index.html")
    mtimes = []
    for f in files:
        p = os.path.join(STATIC_DIR, f)
        if os.path.exists(p):
            mtimes.append(int(os.path.getmtime(p)))
    return str(max(mtimes)) if mtimes else "0"


def _serve_index() -> Response:
    """返回 index.html，自动注入 ``__STATIC_VERSION__`` 占位符。

    同时设置 no-cache 头，避免 Cloudflare / 浏览器缓存住入口页让用户拉到旧 JS。
    """
    path = os.path.join(STATIC_DIR, "index.html")
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = 0.0

    if _INDEX_CACHE["path"] != path or _INDEX_CACHE["mtime"] != mtime:
        version = _compute_static_version()
        with open(path, "r", encoding="utf-8") as fp:
            html = fp.read().replace("__STATIC_VERSION__", version)
        _INDEX_CACHE.update({
            "path": path, "version": version, "html": html, "mtime": mtime,
        })

    return Response(
        content=_INDEX_CACHE["html"],
        media_type="text/html; charset=utf-8",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.get("/")
async def root() -> Response:
    return _serve_index()


# SPA 前端路由：/login、/register、/dashboard、/settings、/oauth 都返回 index.html
@app.get("/login")
@app.get("/register")
@app.get("/dashboard")
@app.get("/settings")
@app.get("/oauth")
async def spa_routes() -> Response:
    return _serve_index()


@app.get("/api/health")
def health() -> dict:
    return {
        "ok": True,
        "auth_required": True,
        "register_enabled": not DISABLE_REGISTER,
    }


# ── Auth ────────────────────────────────────────────────────────


@app.post("/api/auth/register")
def register(req: RegisterRequest, request: Request, response: Response) -> dict:
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")

    if DISABLE_REGISTER:
        db.log_audit("register", username=req.username, ip=ip, user_agent=ua,
                     success=False, detail="注册已禁用")
        raise HTTPException(status.HTTP_403_FORBIDDEN, "注册已禁用")

    username = normalize_username(req.username)
    ok, msg = validate_username(username)
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg)
    ok, msg = validate_password(req.password)
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg)

    if db.get_user_by_username(username):
        db.log_audit("register", username=username, ip=ip, user_agent=ua,
                     success=False, detail="用户名已存在")
        raise HTTPException(status.HTTP_409_CONFLICT, "用户名已存在")

    user_id = db.create_user(username, hash_password(req.password))
    if not user_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "注册失败")

    token = db.create_session(user_id, ttl_seconds=COOKIE_TTL)
    _set_session_cookie(response, token, request)
    db.log_audit("register", user_id=user_id, username=username,
                 ip=ip, user_agent=ua, success=True)
    return {"ok": True, "username": username}


@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request, response: Response) -> dict:
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")
    username = normalize_username(req.username)

    allowed, retry_after = login_limiter.check(username, ip)
    if not allowed:
        db.log_audit("login", username=username, ip=ip, user_agent=ua,
                     success=False, detail=f"已锁定，剩余 {retry_after}s")
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"登录失败次数过多，请 {retry_after // 60} 分钟后再试",
            headers={"Retry-After": str(retry_after)},
        )

    user = db.get_user_by_username(username)
    if not user or not verify_password(req.password, user["password_hash"]):
        locked, lock_secs = login_limiter.record_failure(username, ip)
        remaining = login_limiter.remaining_attempts(username, ip)
        detail = (
            f"已锁定 {lock_secs // 60} 分钟" if locked
            else (f"剩余 {remaining} 次" if remaining is not None else "")
        )
        db.log_audit("login", username=username, ip=ip, user_agent=ua,
                     success=False, detail=detail)
        if locked:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                f"登录失败次数过多，已锁定 {lock_secs // 60} 分钟",
                headers={"Retry-After": str(lock_secs)},
            )
        msg = "用户名或密码错误"
        if remaining is not None and remaining <= 2:
            msg += f"（剩余 {remaining} 次尝试）"
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, msg)

    login_limiter.record_success(username, ip)
    token = db.create_session(user["id"], ttl_seconds=COOKIE_TTL)
    _set_session_cookie(response, token, request)
    db.log_audit("login", user_id=user["id"], username=user["username"],
                 ip=ip, user_agent=ua, success=True)
    return {"ok": True, "username": user["username"]}


@app.post("/api/auth/logout")
def logout(
    request: Request,
    response: Response,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict:
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")
    user_info = db.get_session_user(session_token or "")
    if session_token:
        db.delete_session(session_token)
    _clear_session_cookie(response)
    if user_info:
        db.log_audit("logout", user_id=user_info["id"],
                     username=user_info["username"], ip=ip, user_agent=ua)
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: dict = CurrentUser) -> dict:
    return {"username": user["username"]}


@app.post("/api/auth/change-password")
def change_password(
    req: ChangePasswordRequest,
    request: Request,
    response: Response,
    user: dict = CurrentUser,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict:
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")
    full = db.get_user_by_id(user["id"])
    if not full or not verify_password(req.old_password, full["password_hash"]):
        db.log_audit("change_password", user_id=user["id"],
                     username=user["username"], ip=ip, user_agent=ua,
                     success=False, detail="原密码错误")
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "原密码错误")

    ok, msg = validate_password(req.new_password)
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg)

    db.update_user_password(user["id"], hash_password(req.new_password))
    # 修改密码后注销除当前外的所有会话
    db.cleanup_expired_sessions()
    if session_token:
        db.delete_session(session_token)
    _clear_session_cookie(response)
    db.log_audit("change_password", user_id=user["id"],
                 username=user["username"], ip=ip, user_agent=ua, success=True)
    return {"ok": True}


# ── Accounts ────────────────────────────────────────────────────


@app.get("/api/accounts")
def list_accounts(
    group: Optional[str] = None,
    sort_by: str = "id",
    sort_order: str = "DESC",
    user: dict = CurrentUser,
) -> list[dict]:
    if group and group != "全部":
        accs = db.get_accounts_by_group_sorted(user["id"], group, sort_by, sort_order)
    else:
        accs = db.get_all_accounts_sorted(user["id"], sort_by, sort_order)
    return [account_to_dict(a) for a in accs]


# ⚠️ 注意：以下静态路径必须在 /{account_id} 之前声明，否则会被吞掉。

@app.post("/api/accounts/import")
def import_accounts(
    req: ImportRequest, request: Request, user: dict = CurrentUser
) -> dict:
    accounts = parse_import_text(req.text)
    if not accounts:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "未识别到有效账号")

    existing: set[str] = set()
    if req.skip_duplicate:
        for a in db.get_all_accounts(user["id"]):
            existing.add(a.email.lower())

    success = fail = skipped = 0
    groups_created: set[str] = set()
    for data in accounts:
        email = data["email"]
        if req.skip_duplicate and email.lower() in existing:
            skipped += 1
            continue
        # 单条账号自带的 group 优先级 > 表单选的全局 group
        target_group = (data.get("group") or req.group or "默认分组").strip() or "默认分组"
        if target_group != "默认分组":
            groups_created.add(target_group)
        ok, _msg = db.add_account(
            user["id"],
            email,
            data["password"],
            target_group,
            client_id=data.get("client_id"),
            refresh_token=data.get("refresh_token"),
        )
        if ok:
            success += 1
            existing.add(email.lower())
        else:
            fail += 1
    db.log_audit(
        "import_accounts", user_id=user["id"], username=user["username"],
        ip=_client_ip(request), user_agent=request.headers.get("user-agent", ""),
        target=req.group,
        detail=f"success={success},fail={fail},skipped={skipped},"
               f"groups={','.join(sorted(groups_created))[:200]}",
    )
    return {
        "success": success, "fail": fail, "skipped": skipped,
        "groups_created": sorted(groups_created),
    }


@app.post("/api/accounts/delete")
def delete_accounts(
    req: DeleteAccountsRequest, request: Request, user: dict = CurrentUser
) -> dict:
    deleted = db.delete_accounts(user["id"], req.ids)
    db.log_audit(
        "delete_accounts", user_id=user["id"], username=user["username"],
        ip=_client_ip(request), user_agent=request.headers.get("user-agent", ""),
        target=",".join(map(str, req.ids[:20])) + ("..." if len(req.ids) > 20 else ""),
        detail=f"deleted={deleted},requested={len(req.ids)}",
    )
    return {"deleted": deleted, "requested": len(req.ids)}


# GET /api/accounts/export 已废弃，保留路由以兼容旧前端但要求 POST。
# 新版必须用 POST + 当前账户密码二次确认。
@app.get("/api/accounts/export")
def export_accounts_legacy(user: dict = CurrentUser) -> Response:
    raise HTTPException(
        status.HTTP_405_METHOD_NOT_ALLOWED,
        "GET 已禁用：请使用 POST /api/accounts/export 并提供登录密码以确认导出",
    )


@app.post("/api/accounts/export")
def export_accounts(
    req: ExportRequest, request: Request, user: dict = CurrentUser
) -> PlainTextResponse:
    """导出全部账号明文密码 — 必须二次输入登录密码确认。

    输出格式（``include_group=True`` 默认）::

        email----password----组名
        email----password----client_id----refresh_token----组名

    回导入时会自动还原分组归属。
    """
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")
    full = db.get_user_by_id(user["id"])
    if not full or not verify_password(req.password, full["password_hash"]):
        db.log_audit(
            "export_accounts", user_id=user["id"], username=user["username"],
            ip=ip, user_agent=ua, success=False, detail="二次密码错误",
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "登录密码错误，导出取消")

    if req.group and req.group != "全部":
        accs = db.get_accounts_by_group(user["id"], req.group)
    else:
        accs = db.get_all_accounts(user["id"])
    lines: list[str] = []
    for a in accs:
        parts = [a.email, a.password or ""]
        if a.client_id:
            parts.append(a.client_id)
            parts.append(a.refresh_token or "")
        if req.include_group:
            parts.append(a.group_name or "默认分组")
        lines.append("----".join(parts))

    sep = "$$\n" if req.separator == "dollar" else "\n"
    body = sep.join(lines)

    db.log_audit(
        "export_accounts", user_id=user["id"], username=user["username"],
        ip=ip, user_agent=ua, target=req.group or "全部",
        detail=f"count={len(accs)},include_group={req.include_group},sep={req.separator}",
    )
    return PlainTextResponse(
        body,
        headers={"Content-Disposition": 'attachment; filename="accounts_export.txt"'},
    )


# ── /api/accounts/{account_id} 系列（必须放在静态路径之后）─────


@app.get("/api/accounts/{account_id}")
def get_account(account_id: int, user: dict = CurrentUser) -> dict:
    return account_to_dict(get_account_or_404(user["id"], account_id))


@app.put("/api/accounts/{account_id}/group")
def update_account_group(
    account_id: int, req: GroupUpdate, user: dict = CurrentUser
) -> dict:
    if not db.update_account_group(user["id"], account_id, req.group):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")
    return {"ok": True}


@app.put("/api/accounts/{account_id}/remark")
def update_account_remark(
    account_id: int, req: RemarkUpdate, user: dict = CurrentUser
) -> dict:
    if not db.update_account_remark(user["id"], account_id, req.remark):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")
    return {"ok": True}


# ── Groups ──────────────────────────────────────────────────────


@app.get("/api/groups")
def list_groups(user: dict = CurrentUser) -> list[dict]:
    return [{"id": g[0], "name": g[1]} for g in db.get_all_groups(user["id"])]


@app.post("/api/groups")
def add_group(req: GroupCreate, user: dict = CurrentUser) -> dict:
    if not db.add_group(user["id"], req.name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "分组已存在")
    return {"ok": True}


@app.put("/api/groups/{name}")
def rename_group(name: str, req: GroupRename, user: dict = CurrentUser) -> dict:
    name = urllib.parse.unquote(name)
    if name == "默认分组":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "默认分组不可重命名")
    if not db.group_exists(user["id"], name):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "分组不存在")
    if not db.rename_group(user["id"], name, req.new_name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "新名称已存在或非法")
    return {"ok": True}


@app.delete("/api/groups/{name}")
def delete_group(name: str, user: dict = CurrentUser) -> dict:
    name = urllib.parse.unquote(name)
    if name == "默认分组":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "默认分组不可删除")
    if not db.delete_group(user["id"], name):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "分组不存在")
    return {"ok": True}


# ── Emails ──────────────────────────────────────────────────────


@app.get("/api/accounts/{account_id}/emails")
def get_emails(
    account_id: int,
    folder: str = Query("inbox", pattern="^(inbox|junk|sent|drafts|deleted)$"),
    limit: int = Query(50, ge=1, le=200),
    user: dict = CurrentUser,
) -> dict:
    acc = get_account_or_404(user["id"], account_id)
    client = create_client(user["id"], acc)
    try:
        emails, msg = client.fetch_emails(folder=folder, limit=limit)
    finally:
        client.disconnect()
    for e in emails:
        if e.get("date"):
            e["date"] = e["date"].isoformat()
    return {"emails": emails, "message": msg}


@app.post("/api/accounts/{account_id}/emails/send")
def send_email_api(
    account_id: int, req: SendEmailRequest, user: dict = CurrentUser
) -> dict:
    acc = get_account_or_404(user["id"], account_id)
    client = create_client(user["id"], acc)
    try:
        ok, msg = client.send_email(req.to, req.subject, req.body, req.cc)
    finally:
        client.disconnect()
    return {"success": ok, "message": msg}


@app.post("/api/accounts/{account_id}/check")
def check_single(account_id: int, user: dict = CurrentUser) -> dict:
    acc = get_account_or_404(user["id"], account_id)
    client = create_client(user["id"], acc)
    has_aws = False
    try:
        status_str, msg = client.check_status()
        db.update_account_status(user["id"], account_id, status_str)
        if status_str == "正常":
            try:
                has_aws, _ = client.check_aws_verification_emails(limit=30)
                db.update_aws_code_status(user["id"], account_id, has_aws)
            except Exception:
                logger.exception("AWS 验证码检测异常 acc=%s", account_id)
    finally:
        client.disconnect()
    return {"status": status_str, "message": msg, "has_aws": has_aws}


@app.post("/api/accounts/{account_id}/emails/mark-read")
def mark_read(
    account_id: int, req: MarkReadRequest, user: dict = CurrentUser
) -> dict:
    acc = get_account_or_404(user["id"], account_id)
    client = create_client(user["id"], acc)
    try:
        ok, msg = client.mark_as_read(req.email_id, req.folder, req.is_read)
    finally:
        client.disconnect()
    return {"success": ok, "message": msg}


@app.post("/api/accounts/{account_id}/emails/delete")
def delete_email_api(
    account_id: int, req: DeleteEmailRequest, user: dict = CurrentUser
) -> dict:
    acc = get_account_or_404(user["id"], account_id)
    client = create_client(user["id"], acc)
    try:
        ok, msg = client.delete_email(req.email_id, req.folder)
    finally:
        client.disconnect()
    return {"success": ok, "message": msg}


@app.get("/api/accounts/{account_id}/emails/body")
def get_email_body_api(
    account_id: int,
    email_id: str = Query(..., min_length=1, max_length=2000),
    folder: str = Query("inbox", pattern="^(inbox|junk|sent|drafts|deleted)$"),
    user: dict = CurrentUser,
) -> dict:
    """单独拉取一封邮件的完整正文（用于列表 body 为空时按需获取）。"""
    acc = get_account_or_404(user["id"], account_id)
    client = create_client(user["id"], acc)
    try:
        body, body_type, msg = client.fetch_email_body(email_id, folder)
    finally:
        client.disconnect()
    if body is None:
        return {"success": False, "message": msg, "body": "", "body_type": "text"}
    return {"success": True, "message": msg, "body": body, "body_type": body_type or "text"}


# ── Batch (SSE) ─────────────────────────────────────────────────


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


@app.post("/api/batch/check")
def batch_check(req: BatchCheckRequest, user: dict = CurrentUser) -> StreamingResponse:
    owner_id = user["id"]

    def generate():
        total = len(req.account_ids)
        sc = fc = 0
        for i, aid in enumerate(req.account_ids):
            acc = db.get_account(owner_id, aid)
            if not acc:
                fc += 1
                yield _sse({
                    "type": "progress", "current": i + 1, "total": total,
                    "email": "?", "status": "异常",
                })
                continue
            client = create_client(owner_id, acc)
            has_aws = False
            status_str = "异常"
            try:
                try:
                    status_str, _ = client.check_status()
                except Exception:
                    logger.exception("check_status 异常 acc=%s", aid)
                db.update_account_status(owner_id, aid, status_str)
                if status_str == "正常":
                    sc += 1
                    try:
                        has_aws, _ = client.check_aws_verification_emails(limit=30)
                        db.update_aws_code_status(owner_id, aid, has_aws)
                    except Exception:
                        logger.exception("AWS 检测异常 acc=%s", aid)
                else:
                    fc += 1
            finally:
                client.disconnect()
            yield _sse({
                "type": "progress", "current": i + 1, "total": total,
                "email": acc.email, "status": status_str, "has_aws": has_aws,
            })
        yield _sse({"type": "done", "success": sc, "fail": fc})

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.post("/api/batch/send")
def batch_send(
    req: BatchSendRequest, request: Request, user: dict = CurrentUser
) -> StreamingResponse:
    owner_id = user["id"]
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")

    db.log_audit(
        "batch_send_start", user_id=owner_id, username=user["username"],
        ip=ip, user_agent=ua, target=req.to[:100],
        detail=f"accounts={len(req.account_ids)}",
    )

    def generate():
        total = len(req.account_ids)
        sc = fc = 0
        for i, aid in enumerate(req.account_ids):
            acc = db.get_account(owner_id, aid)
            if not acc:
                fc += 1
                yield _sse({
                    "type": "progress", "current": i + 1, "total": total,
                    "email": "?", "success": False, "message": "Not found",
                })
                continue
            client = create_client(owner_id, acc)
            try:
                ok, msg = client.send_email(req.to, req.subject, req.body)
            finally:
                client.disconnect()
            sc += 1 if ok else 0
            fc += 0 if ok else 1
            yield _sse({
                "type": "progress", "current": i + 1, "total": total,
                "email": acc.email, "success": ok, "message": msg,
            })
        db.log_audit(
            "batch_send_done", user_id=owner_id, username=user["username"],
            ip=ip, user_agent=ua, target=req.to[:100],
            detail=f"success={sc},fail={fc}",
        )
        yield _sse({"type": "done", "success": sc, "fail": fc})

    return StreamingResponse(generate(), media_type="text/event-stream")


# ── Audit Log ───────────────────────────────────────────────────


@app.get("/api/audit")
def list_audit_log(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    only_self: bool = Query(True),
    action: Optional[str] = Query(None, max_length=64),
    user: dict = CurrentUser,
) -> dict:
    """普通用户只能看自己的审计；预留 only_self=False 供未来超管用。"""
    user_id = user["id"] if only_self else None
    items = db.list_audit(limit=limit, offset=offset, user_id=user_id, action=action)
    return {"items": items, "limit": limit, "offset": offset}


# ── Dashboard ───────────────────────────────────────────────────


@app.get("/api/dashboard")
def get_dashboard(user: dict = CurrentUser) -> dict:
    accs = db.get_all_accounts(user["id"])
    groups_map: dict[str, int] = {}
    statuses: dict[str, int] = {"正常": 0, "异常": 0, "未检测": 0}
    for a in accs:
        groups_map[a.group_name] = groups_map.get(a.group_name, 0) + 1
        statuses[a.status] = statuses.get(a.status, 0) + 1
    return {"total": len(accs), "groups": groups_map, "statuses": statuses}


# ── Settings ────────────────────────────────────────────────────


@app.get("/api/settings")
def get_settings(user: dict = CurrentUser) -> dict:
    uid = user["id"]
    return {
        "theme": db.get_setting(uid, "theme", "light"),
        "language": db.get_setting(uid, "language", "zh"),
        "font_size": db.get_setting(uid, "font_size", "13"),
    }


@app.put("/api/settings")
def update_settings(req: SettingUpdate, user: dict = CurrentUser) -> dict:
    if req.key not in ALLOWED_SETTING_KEYS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"非法的 setting: {req.key}")
    db.set_setting(user["id"], req.key, req.value)
    return {"ok": True}


# ── OAuth2 ──────────────────────────────────────────────────────


@app.get("/api/oauth2/auth-url")
def get_oauth2_url(user: dict = CurrentUser) -> dict:
    return {"url": OAuth2Helper().get_auth_url()}


def _fetch_oauth2_email(client_id: str, refresh_token: str) -> Optional[str]:
    """根据 OAuth2 凭据查询账户邮箱地址。"""
    try:
        resp = req_lib.post(
            TOKEN_URL,
            data={
                "client_id": client_id,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
            timeout=30,
            verify=certifi.where(),
        )
        if resp.status_code != 200:
            return None
        access_token = resp.json().get("access_token")
        headers = {"Authorization": f"Bearer {access_token}"}

        for url, key in (
            ("https://outlook.office.com/api/v2.0/me", "EmailAddress"),
            ("https://graph.microsoft.com/v1.0/me", "mail"),
            ("https://graph.microsoft.com/v1.0/me", "userPrincipalName"),
        ):
            try:
                r = req_lib.get(url, headers=headers, timeout=10, verify=certifi.where())
                if r.status_code == 200:
                    val = r.json().get(key)
                    if val:
                        return val
            except req_lib.RequestException:
                logger.exception("调用 %s 失败", url)
    except req_lib.RequestException:
        logger.exception("OAuth2 token 端点访问失败")
    return None


@app.post("/api/oauth2/exchange")
def exchange_oauth2(body: dict, user: dict = CurrentUser) -> dict:
    redirect_url = body.get("redirect_url", "")
    group = (body.get("group") or "默认分组").strip() or "默认分组"

    helper = OAuth2Helper()
    client_id, refresh_token, error = helper.exchange_code_for_token(redirect_url)
    if error:
        return {"success": False, "error": error}

    email = _fetch_oauth2_email(client_id, refresh_token)
    if not email:
        return {"success": False, "error": "无法获取用户信息"}

    existing = db.get_account_by_email(user["id"], email)
    if existing:
        db.update_account_oauth(user["id"], existing.id, client_id, refresh_token)
    else:
        db.add_account(
            user["id"],
            email,
            "",
            group,
            client_id=client_id,
            refresh_token=refresh_token,
        )
    return {"success": True, "email": email}


# ── 入口 ────────────────────────────────────────────────────────


def main() -> None:
    import uvicorn

    host = os.getenv("EMAIL_WEB_HOST", "127.0.0.1")
    port = int(os.getenv("EMAIL_WEB_PORT", "8000"))
    ssl_keyfile = os.getenv("EMAIL_WEB_SSL_KEY", "").strip() or None
    ssl_certfile = os.getenv("EMAIL_WEB_SSL_CERT", "").strip() or None
    scheme = "https" if ssl_keyfile and ssl_certfile else "http"

    print("=" * 50)
    print(f"  邮箱管家 Web v3.1 (多用户 + 审计)")
    print(f"  访问: {scheme}://{host}:{port}")
    print(f"  注册: {'已禁用' if DISABLE_REGISTER else '开放（首次访问可注册账号）'}")
    if scheme == "https":
        print(f"  TLS:  启用 (cert={ssl_certfile})")
    elif host not in {"127.0.0.1", "localhost", "::1"}:
        print(f"  [WARN] HTTP 明文传输；公网/内网建议设置 EMAIL_WEB_SSL_KEY/CERT 或经由反代")
    print("=" * 50)

    # 启动时打印安全警告（POSIX 平台权限检查 + 主密钥共目录提示）
    try:
        emit_warnings(get_data_dir())
    except Exception:
        logger.exception("启动安全检查失败（忽略）")

    # 清理过期会话与老审计日志
    try:
        n_sess = db.cleanup_expired_sessions()
        n_audit = db.cleanup_old_audit()
        if n_sess or n_audit:
            logger.info("启动清理: 过期会话=%d, 老审计=%d", n_sess, n_audit)
    except Exception:
        logger.exception("启动清理失败（忽略）")

    uvicorn.run(
        app,
        host=host,
        port=port,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        proxy_headers=True,        # 信任反代头
        forwarded_allow_ips="*",   # 让 X-Forwarded-* 生效（如需更严，改成具体 IP）
    )


if __name__ == "__main__":
    main()
