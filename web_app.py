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
from database.db_manager import ALLOWED_SETTING_KEYS, DatabaseManager  # noqa: E402

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


def parse_import_text(text: str) -> List[dict]:
    accounts: list[dict] = []
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if "$$" in text:
        parts = text.split("$$")
    elif "\n" in text:
        parts = text.split("\n")
    else:
        parts = re.split(
            r"\$(?=[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", text
        )
    for part in parts:
        part = part.strip().rstrip("$")
        if not part or "----" not in part:
            continue
        p = part.split("----")
        if len(p) < 2:
            continue
        data = {"email": p[0].strip(), "password": p[1].strip()}
        if len(p) >= 3 and p[2].strip():
            data["client_id"] = p[2].strip()
        if len(p) >= 4 and p[3].strip():
            data["refresh_token"] = p[3].strip()
        if data["email"] and "@" in data["email"]:
            accounts.append(data)
    return accounts


def _set_session_cookie(response: Response, token: str, request: Request) -> None:
    secure = request.url.scheme == "https"
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=COOKIE_TTL,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


# ── Root & Health ───────────────────────────────────────────────


@app.get("/")
async def root() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


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
    if DISABLE_REGISTER:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "注册已禁用")

    username = normalize_username(req.username)
    ok, msg = validate_username(username)
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg)
    ok, msg = validate_password(req.password)
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg)

    if db.get_user_by_username(username):
        raise HTTPException(status.HTTP_409_CONFLICT, "用户名已存在")

    user_id = db.create_user(username, hash_password(req.password))
    if not user_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "注册失败")

    token = db.create_session(user_id, ttl_seconds=COOKIE_TTL)
    _set_session_cookie(response, token, request)
    return {"ok": True, "username": username}


@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request, response: Response) -> dict:
    username = normalize_username(req.username)
    user = db.get_user_by_username(username)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "用户名或密码错误")

    token = db.create_session(user["id"], ttl_seconds=COOKIE_TTL)
    _set_session_cookie(response, token, request)
    return {"ok": True, "username": user["username"]}


@app.post("/api/auth/logout")
def logout(
    response: Response,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict:
    if session_token:
        db.delete_session(session_token)
    _clear_session_cookie(response)
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: dict = CurrentUser) -> dict:
    return {"username": user["username"]}


@app.post("/api/auth/change-password")
def change_password(
    req: ChangePasswordRequest,
    response: Response,
    user: dict = CurrentUser,
    session_token: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict:
    full = db.get_user_by_id(user["id"])
    if not full or not verify_password(req.old_password, full["password_hash"]):
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
def import_accounts(req: ImportRequest, user: dict = CurrentUser) -> dict:
    accounts = parse_import_text(req.text)
    if not accounts:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "未识别到有效账号")

    existing: set[str] = set()
    if req.skip_duplicate:
        for a in db.get_all_accounts(user["id"]):
            existing.add(a.email.lower())

    success = fail = skipped = 0
    for data in accounts:
        email = data["email"]
        if req.skip_duplicate and email.lower() in existing:
            skipped += 1
            continue
        ok, _msg = db.add_account(
            user["id"],
            email,
            data["password"],
            req.group,
            client_id=data.get("client_id"),
            refresh_token=data.get("refresh_token"),
        )
        if ok:
            success += 1
            existing.add(email.lower())
        else:
            fail += 1
    return {"success": success, "fail": fail, "skipped": skipped}


@app.post("/api/accounts/delete")
def delete_accounts(req: DeleteAccountsRequest, user: dict = CurrentUser) -> dict:
    deleted = db.delete_accounts(user["id"], req.ids)
    return {"deleted": deleted, "requested": len(req.ids)}


@app.get("/api/accounts/export")
def export_accounts(
    group: Optional[str] = None, user: dict = CurrentUser
) -> PlainTextResponse:
    if group and group != "全部":
        accs = db.get_accounts_by_group(user["id"], group)
    else:
        accs = db.get_all_accounts(user["id"])
    lines: list[str] = []
    for a in accs:
        parts = [a.email, a.password or ""]
        if a.client_id:
            parts.append(a.client_id)
            if a.refresh_token:
                parts.append(a.refresh_token)
        lines.append("----".join(parts))
    return PlainTextResponse(
        "\n".join(lines),
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
def batch_send(req: BatchSendRequest, user: dict = CurrentUser) -> StreamingResponse:
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
        yield _sse({"type": "done", "success": sc, "fail": fc})

    return StreamingResponse(generate(), media_type="text/event-stream")


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
    print(f"  邮箱管家 Web v3.0 (多用户)")
    print(f"  访问: {scheme}://{host}:{port}")
    print(f"  注册: {'已禁用' if DISABLE_REGISTER else '开放（首次访问可注册账号）'}")
    if scheme == "https":
        print(f"  TLS:  启用 (cert={ssl_certfile})")
    elif host not in {"127.0.0.1", "localhost", "::1"}:
        print(f"  ⚠️  HTTP 明文传输；公网/内网建议设置 EMAIL_WEB_SSL_KEY/CERT")
    print("=" * 50)

    uvicorn.run(
        app,
        host=host,
        port=port,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
    )


if __name__ == "__main__":
    main()
