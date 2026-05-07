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

import asyncio
import inspect
import json
import logging
import os
import re
import sys
import threading
import time
import urllib.parse
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

import anyio
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
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    PlainTextResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from starlette.types import Scope
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
from core.rate_limit import (  # noqa: E402
    IP_LOGIN_LIMITER_KEY,
    REGISTER_LIMITER_KEY,
    ip_login_limiter,
    login_limiter,
    register_limiter,
)
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

# 后台周期清理：管理端历史只在 ``main()`` 启动那一刻清理一次过期会话 /
# 老审计 / 老接码日志 / 过期 token，长期跑的进程在两次重启之间没有任何
# 自维护，audit_log 与 sessions 表会持续累积。接码前台早就有 ``_cleanup_loop``
# 一日一跑；这里把同一思路搬过来，避免运维事故型部署（如永远不重启）。
#
# 频率 24h：审计 / 会话 / 查询日志的保留窗口都按"天"算（90 / 30 天），
# 一日一跑足以追上累积；更频繁会徒增 DB 写压力。
_CLEANUP_INTERVAL_SEC = 24 * 3600


async def _periodic_cleanup() -> None:
    """后台周期任务：清理过期会话 / 老审计 / 老接码查询日志 / 过期 token 缓存
    / 跨用户的 OAuth 暂存桶。

    任何步骤异常都仅 ``logger.exception`` 记录，不让单步失败拖垮整个 loop。
    被 ``cancel()`` 后立即退出。注意：``asyncio.sleep`` 是天然的 cancellation point。
    """
    from core.oauth_token import evict_expired_token_cache  # noqa: WPS433
    while True:
        try:
            await asyncio.sleep(_CLEANUP_INTERVAL_SEC)
        except asyncio.CancelledError:
            return
        try:
            n_sess = await asyncio.to_thread(db.cleanup_expired_sessions)
            n_audit = await asyncio.to_thread(db.cleanup_old_audit)
            n_qlog = await asyncio.to_thread(db.cleanup_old_code_query_log)
            n_tok = await asyncio.to_thread(evict_expired_token_cache)
            # OAuth 暂存桶 GC：``_gc_pending_oauth`` 操作的是模块级 dict +
            # threading.Lock，纯 CPU 操作不阻塞事件循环（ms 级），无需
            # to_thread；直接同步调用即可。
            n_state, n_cred = _gc_pending_oauth()
            if n_sess or n_audit or n_qlog or n_tok or n_state or n_cred:
                logger.info(
                    "周期清理: 过期会话=%d, 老审计=%d, 老接码日志=%d, "
                    "过期 token=%d, OAuth state=%d, OAuth cred=%d",
                    n_sess, n_audit, n_qlog, n_tok, n_state, n_cred,
                )
        except Exception:
            logger.exception("周期清理异常（已吞掉，下轮再试）")


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    """FastAPI 0.110+ 推荐的 lifespan 入口。

    取代 deprecated 的 ``@app.on_event("startup"|"shutdown")``，让后台任务
    与应用生命周期严格绑定。``finally`` 块确保即使 yield 期间抛异常，
    后台 task 也会被正确取消、避免 stranded coroutine 警告。
    """
    cleanup_task = asyncio.create_task(_periodic_cleanup(), name="periodic_cleanup")
    try:
        yield
    finally:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except (asyncio.CancelledError, Exception):
            # 关停阶段任何异常都不能阻塞进程退出
            pass


# 安全：关闭 ``/docs`` ``/redoc`` ``/openapi.json``。Swagger UI 默认对外暴露
# 全部 API schema、参数类型、返回结构 —— 让攻击者拿到一份"撞库爆破地图"
# （知道哪些路由要 cookie、哪些校验规则、字段长度上限等）。接码前台
# (code-receiver/app.py:157) 早已关掉，管理端历史漏配，这里补齐。
app = FastAPI(
    title="邮箱管家 Web",
    version="3.0.0",
    lifespan=_lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.exception_handler(RequestValidationError)
async def _safe_validation_handler(  # noqa: WPS430
    _request: Request, exc: RequestValidationError,
) -> JSONResponse:
    """安全：覆盖 FastAPI 默认 422 处理器。

    默认 ``RequestValidationError`` 处理器会把出错字段的 ``input``（即用户
    提交的原始值）放进响应 ``detail``。当用户提交的是登录密码、OAuth
    refresh_token、二次密码导出请求等敏感字段时，校验失败会让这些值
    随错误响应原样回显，泄露给浏览器扩展、CDN 日志、企业出口代理等
    任何能看到 HTTP 响应体的环节。

    本处理器只保留 ``loc + msg``，丢弃 ``input``，并把 msg 截到 200 字符
    避免 pydantic 把原值嵌入错误消息。这与接码前台
    (``code-receiver/app.py:_safe_validation_handler``) 共享同一防护。
    """
    safe_errors = []
    for err in exc.errors():
        msg_raw = str(err.get("msg") or "invalid")[:200]
        safe_errors.append({"loc": list(err.get("loc", [])), "msg": msg_raw})
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "请求参数校验失败", "errors": safe_errors},
    )


# 注：此处曾有"假加入接码账号"启动扫描 hook，因字符串中嵌套了未转义的英文双引号
# 与 emoji 字符导致语法错误（启动崩溃）。
# 功能已被 ``database.db_manager`` 的 v5→v6 数据迁移替代——首次升级到 v6 时
# 启动会自动把 ``is_public=1 AND allowed_categories='' AND group_name 不含分类
# 关键字`` 的"假加入"账号统一改成 ``allowed_categories='*'``，让前台立即可查。
# 如需手工排查请直接 SQL：
#   SELECT id,email,group_name,allowed_categories FROM accounts
#    WHERE is_public=1 AND COALESCE(allowed_categories,'')='';


# ── GZip 压缩 ─────────────────────────────────────────────────
# /api/accounts、/api/audit、/api/accounts/{id}/emails 都返回 KB-MB 级 JSON，
# 启用 gzip 后 90% 文本响应能压到原大小的 20-30%。SSE 不受影响（StreamingResponse
# 走 chunked，GZipMiddleware 自身会跳过流式响应避免破坏 SSE 协议）。
# minimum_size=1024 让小响应（健康检查 / 小列表）走原路径，省 CPU。
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=6)

_extra_cors = [s.strip() for s in os.getenv("EMAIL_WEB_CORS", "").split(",") if s.strip()]
if _extra_cors:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_extra_cors,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# ── 全局安全响应头中间件 ──────────────────────────────────────────
# 接码前台 (code-receiver/app.py) 一直就有这套；管理端历史漏配，意味着
# 攻击者可以把管理端嵌入 iframe 做点击劫持、浏览器 MIME-sniff
# 把 application/json 当 HTML 解析、HTTPS 部署没有 HSTS 时被 SSL Strip。
# 用 ``setdefault`` 写入，避免覆盖个别路由（例如 SSE 的 X-Accel-Buffering、
# /api/health 自己设的 Cache-Control）已经精心调好的头。
#
# CSP 规则要点（管理端 SPA + 邮件 iframe sandbox 渲染）：
# - default-src 'self'                  其它资源全部同源
# - img-src 'self' data:                邮件正文偶有 data: 内嵌 inline icon
# - style-src 'self' 'unsafe-inline'    前端 i18n 切换时存在动态 style；
#   暂不强行去除 inline，避免大改前端
# - script-src 'self'                   仅同源脚本，杜绝外站脚本注入
# - frame-src 'self' data:              邮件 iframe 走 srcdoc，受 sandbox 隔离
# - connect-src 'self'                  XHR / SSE 仅同源
# - frame-ancestors 'none'              **核心**：彻底禁止被任何站嵌入 iframe
#   （X-Frame-Options: DENY 是它的旧版兜底，部分老浏览器仍依赖）
# - form-action 'self'                  POST 表单只能提交回同源
# - base-uri 'self'                     杜绝 <base href> 注入劫持相对路径
#
# HSTS 仅在确认 HTTPS 时下发；HTTP 部署下发会让浏览器把当前 host 锁成
# 强制 HTTPS，错误开关 / 域名调整时会陷入"再也访问不到 HTTP" 的死锁。
_CSP_HEADER = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; "
    "frame-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "base-uri 'self'"
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Content-Security-Policy", _CSP_HEADER)
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=()",
    )
    if _is_https(request):
        # max-age=1 年；includeSubDomains 让所有子域同享。不加 ``preload``
        # 避免被 hsts preload list 收录后想下线极难。
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
    return response


# ── 静态资源 ────────────────────────────────────────────────────

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
os.makedirs(STATIC_DIR, exist_ok=True)


class _CachedStaticFiles(StaticFiles):
    """带长缓存头的 StaticFiles 子类。

    入口 ``index.html`` 已经把 ``app.js`` / ``app.css`` / ``i18n.js`` /
    ``icon.png`` 全部以 ``?v=__STATIC_VERSION__`` 形式 cache-bust（见
    ``_compute_static_version``），文件 mtime 一变 query 就刷新，浏览器与
    Cloudflare 都把它当新 URL 拉。这给我们一个等式：
        ``/static/<path>?v=<mtime>`` 对同一份内容是稳定 URL。
    所以把响应标记 ``Cache-Control: public, max-age=31536000, immutable``
    完全安全 —— 哪怕用户改了 app.js 重启容器，新 URL 会立刻刷掉旧缓存。

    例外：响应非 200（404 / 304 / range 等）维持原 ``StaticFiles`` 行为，
    避免把 304 也打上 immutable，引发某些 CDN 异常。
    """

    _CACHE_HEADER = "public, max-age=31536000, immutable"

    async def get_response(self, path: str, scope: Scope):
        response = await super().get_response(path, scope)
        if response.status_code == 200:
            response.headers.setdefault("Cache-Control", self._CACHE_HEADER)
        return response


app.mount("/static", _CachedStaticFiles(directory=STATIC_DIR), name="static")

# ── 数据库 ──────────────────────────────────────────────────────

db = DatabaseManager()

# ── 配置 ────────────────────────────────────────────────────────

SESSION_COOKIE = "email_web_session"
COOKIE_TTL = int(os.getenv("EMAIL_WEB_COOKIE_TTL", str(7 * 24 * 3600)))
DISABLE_REGISTER = os.getenv("EMAIL_WEB_DISABLE_REGISTER", "").strip() in {"1", "true", "yes"}

# 接码业务的"站长用户名"。该用户名下、is_public=1 的账号才会被前台接码端
# (code-receiver) 拉到。同时在管理后台只有该用户能看到 / 调用"加入接码 /
# 移出接码"批量按钮，普通用户连按钮都不会出现，绕过 UI 直接 POST 也会被
# 后端的 username 比对拦下。
# 与 code-receiver/app.py 的 CODE_OWNER_USERNAME 共享同一份命名 / 默认值。
CODE_OWNER_USERNAME = (os.getenv("CODE_OWNER_USERNAME", "xiaoxuan") or "").strip()

# 是否信任反代头（X-Forwarded-For / X-Real-IP / CF-Connecting-IP）
# 默认 False — 直接面向公网时打开会让任意客户端伪造 IP 写进审计日志，污染数据。
# 走 nginx / Caddy / Cloudflare Tunnel 等反代时，**必须**显式设为 1，否则限流/审计
# 全部按反代 IP 计，毫无意义。
TRUST_PROXY = os.getenv("EMAIL_WEB_TRUST_PROXY", "").strip().lower() in {"1", "true", "yes"}

# 批量检测/发送的并发数（IMAP/SMTP 是 IO 密集型，并发能显著提速）
BATCH_CHECK_CONCURRENCY = max(1, int(os.getenv("EMAIL_BATCH_CHECK_CONCURRENCY", "8")))
BATCH_SEND_CONCURRENCY = max(1, int(os.getenv("EMAIL_BATCH_SEND_CONCURRENCY", "4")))


def _client_ip(request: Request) -> str:
    """获取客户端真实 IP。

    仅当 ``EMAIL_WEB_TRUST_PROXY=1`` 时才信任反代头，避免公网直连时的 IP 伪造。
    优先级：CF-Connecting-IP（Cloudflare 强制添加，最可靠）→ X-Forwarded-For 首段 →
    X-Real-IP → request.client.host。
    """
    if TRUST_PROXY:
        cf = (request.headers.get("cf-connecting-ip", "") or "").strip()
        if cf:
            return cf
        xff = (request.headers.get("x-forwarded-for", "") or "").split(",")[0].strip()
        if xff:
            return xff
        real = (request.headers.get("x-real-ip", "") or "").strip()
        if real:
            return real
    return request.client.host if request.client else "unknown"


def _is_https(request: Request) -> bool:
    """判断当前请求是否为 HTTPS（识别反向代理场景）。

    仅当 ``EMAIL_WEB_TRUST_PROXY=1`` 时才看 X-Forwarded-Proto，否则只信任直接连接的 scheme。
    防止匿名客户端伪造 ``X-Forwarded-Proto: https`` 让 cookie 被错误地标记 ``Secure=True``，
    导致部分浏览器在 HTTP 下拒发该 cookie。
    """
    if request.url.scheme == "https":
        return True
    if TRUST_PROXY:
        # 反代可能写多值 (e.g. "https, http")；取首段并精确比 ``=="https"``
        # 旧实现 ``"https" in proto`` 对 ``"http,https-fake"`` / ``"https-foo"``
        # 等怪异值仍会判 True，给攻击者精心构造头注入 cookie 标记 Secure
        # 的可乘之机；精确匹配把这类边界情况彻底切断。
        raw = request.headers.get("x-forwarded-proto", "")
        proto = raw.split(",", 1)[0].strip().lower()
        return proto == "https"
    return False


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
    # 单次最多 2 MiB 文本（约 5-10 万账号行）。无上限时可被恶意 body
    # 撑爆 worker 内存，特别是注册开放且 body 解析也走 worker 的部署。
    text: str = Field(min_length=1, max_length=2 * 1024 * 1024)
    group: str = "默认分组"
    skip_duplicate: bool = True

    @field_validator("group")
    @classmethod
    def _trim_group(cls, v: str) -> str:
        return (v or "").strip() or "默认分组"


class DeleteAccountsRequest(BaseModel):
    ids: List[int] = Field(min_length=1, max_length=10000)


class SetPublicRequest(BaseModel):
    """批量公开 / 取消公开账号（接码白名单）。

    ``allowed_categories`` 留空（None / 空数组）= 由 ``group_name`` 自动推断分类
    （cursor / openai / anthropic / google / github 等关键字命中即放行该分类）；
    ``["*"]`` 表示放行所有分类；显式列举则按白名单分类放行。
    """
    ids: List[int] = Field(min_length=1, max_length=5000)
    is_public: bool
    allowed_categories: Optional[List[str]] = Field(default=None, max_length=16)

    @field_validator("allowed_categories")
    @classmethod
    def _trim_cats(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return None
        cleaned = [(c or "").strip().lower() for c in v if c and c.strip()]
        return cleaned or None


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


# 单次发信最大收件人数（防止把工具变成 spam relay）。
# Outlook / Gmail 个人账号也都按 100 收件人左右限流，超过会触发服务商风控。
MAX_RECIPIENTS_PER_SEND = max(1, int(os.getenv("EMAIL_MAX_RECIPIENTS_PER_SEND", "50")))


def _split_addrs(text: str) -> List[str]:
    """按逗号 / 分号 / 换行切收件人，去空白与重复，保留原大小写。

    顶层先拒绝整体含 ``\\r`` 的输入，防止 SMTP/MIME 头注入：
    恶意输入 ``a@x.com\\r\\nBcc: hidden@attacker.com`` 会被 SMTP 拼成
    ``RCPT TO: <a@x.com>\\r\\nBCC:...``，让本服务变成隐式抄送跳板。
    JSON body 里如果合法地需要换行，应该用逗号/分号显式分隔，``\\r`` 永远是危险信号。
    """
    if not text:
        return []
    if "\r" in text:
        raise ValueError("收件人地址含非法换行字符（CR）")
    seen: set = set()
    out: List[str] = []
    for part in re.split(r"[,\n;]+", text):
        addr = part.strip()
        if not addr:
            continue
        # 双保险：单段地址内不允许残留 CR/LF
        if "\r" in addr or "\n" in addr:
            raise ValueError("收件人地址含非法换行字符")
        key = addr.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(addr)
    return out


def _validate_recipients(value: str) -> str:
    """校验单个收件人字段并返回标准化的逗号分隔字符串。

    标准化的好处：
    - SMTP 客户端拿到的 ``to`` 是去重 + 单一分隔符，不需要再处理 ``;`` / ``\\n``
    - 重发 / 审计日志里看到的 to 字段含义一致
    - 配合 _split_addrs 的 CRLF 检查，杜绝 SMTP 头注入
    """
    addrs = _split_addrs(value)
    if not addrs:
        raise ValueError("缺少有效收件人")
    if len(addrs) > MAX_RECIPIENTS_PER_SEND:
        raise ValueError(
            f"收件人不得超过 {MAX_RECIPIENTS_PER_SEND} 个（当前 {len(addrs)}）"
        )
    return ", ".join(addrs)


def _validate_subject(v: str) -> str:
    """SMTP/MIME Subject 校验：拒绝 ``\\r`` / ``\\n``，对齐收件人 CRLF 防护。

    走 IMAP/SMTP 路径时，``msg["Subject"] = subject`` 会把 ``\\r\\nBcc: ...``
    类输入直接写入邮件头，让恶意用户在 Subject 里追加 BCC / Reply-To 等头，
    把本服务变成隐式抄送跳板。前端正常使用不会产生 CR/LF，因此一刀切拒绝。
    """
    if v is None:
        return v
    if "\r" in v or "\n" in v:
        raise ValueError("主题不得包含换行字符（CR/LF）")
    return v


class SendEmailRequest(BaseModel):
    to: str = Field(min_length=1, max_length=4000)
    subject: str = Field(min_length=1, max_length=998)
    body: str = Field(default="", max_length=1024 * 1024)
    cc: Optional[str] = Field(default=None, max_length=4000)

    @field_validator("to")
    @classmethod
    def _validate_to(cls, v: str) -> str:
        return _validate_recipients(v)

    @field_validator("subject")
    @classmethod
    def _validate_subject_field(cls, v: str) -> str:
        return _validate_subject(v)

    @field_validator("cc")
    @classmethod
    def _validate_cc(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not v.strip():
            return None
        addrs = _split_addrs(v)
        if len(addrs) > MAX_RECIPIENTS_PER_SEND:
            raise ValueError(
                f"抄送不得超过 {MAX_RECIPIENTS_PER_SEND} 个（当前 {len(addrs)}）"
            )
        return ", ".join(addrs)


class BatchCheckRequest(BaseModel):
    account_ids: List[int] = Field(min_length=1, max_length=10000)


class BatchSendRequest(BaseModel):
    account_ids: List[int] = Field(min_length=1, max_length=10000)
    to: str = Field(min_length=1, max_length=4000)
    subject: str = Field(min_length=1, max_length=998)  # RFC 2822 line limit
    body: str = Field(default="", max_length=1024 * 1024)  # 1 MiB

    @field_validator("to")
    @classmethod
    def _validate_to(cls, v: str) -> str:
        # 防 spam relay：单次批量发送的 to 字段最多 N 个收件人；
        # 外层 account_ids 控制"用多少账号去发"，所以总封数仍可达 N×10000。
        return _validate_recipients(v)

    @field_validator("subject")
    @classmethod
    def _validate_subject_field(cls, v: str) -> str:
        return _validate_subject(v)


class SettingUpdate(BaseModel):
    key: str = Field(min_length=1, max_length=64)
    # 设置值长度上限。settings 表所有合法 key 都是短字符串（theme/language/font_size），
    # 没有写大对象需求；上限既能挡住 DoS 写入，也能让 key/value 字段在 SQLite
    # 里保持合理大小，避免一行膨胀拖慢索引与全表扫描。
    value: str = Field(default="", max_length=4096)


class MarkReadRequest(BaseModel):
    email_id: str
    folder: str = "inbox"
    is_read: bool = True


class DeleteEmailRequest(BaseModel):
    email_id: str
    folder: str = "inbox"


class ExportRequest(BaseModel):
    """导出账号需要二次密码确认。

    范围三选一（按优先级）：
    - ``ids`` 非空 → 仅导出列表中指定的账号 ID（前端勾选用）
    - ``group`` 非空且不为"全部" → 仅导出该分组下账号
    - 否则 → 导出当前用户全部账号
    """
    password: str = Field(min_length=1, max_length=256)
    group: Optional[str] = Field(default=None, max_length=64)
    ids: Optional[List[int]] = Field(default=None, max_length=10000)
    include_group: bool = True   # True 时每行末尾追加 ----组名（便于回导入恢复）
    separator: str = "newline"   # "newline" 一行一个；"dollar" 用 $$ 拼接成单行


class OAuth2ExchangeRequest(BaseModel):
    """OAuth2 授权码交换请求模型。

    两阶段提交（与 ``exchange_oauth2`` 一致）：
    - 首次：``redirect_url`` + 可选 ``group``
    - 二次：仅 ``email``，从内存暂存中恢复 client_id / refresh_token / group

    ``redirect_url`` 长度上限 4096 — Microsoft 实际 URL 远小于此，给畸形/恶意
    超大 body 留出明确边界；``email`` 限 256 字符，``group`` 限 64 字符。
    没有用 ``HttpUrl`` 强校验是因为合法 redirect 形如 ``https://localhost/?code=...``
    且本地开发可能含 ``http://localhost``，留给业务层去做协议白名单更灵活。
    """
    redirect_url: Optional[str] = Field(default=None, max_length=4096)
    email: Optional[str] = Field(default=None, max_length=256)
    group: Optional[str] = Field(default=None, max_length=64)


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


def _clear_session_cookie(response: Response, request: Optional[Request] = None) -> None:
    """删除会话 cookie。

    某些浏览器（特别是 Safari / 部分 Chrome 版本）要求 ``delete_cookie`` 的属性集
    （path / domain / secure / samesite）与 ``set_cookie`` 严格一致，否则不会
    覆写原 cookie。这里为 delete 补上与 set 同款的属性集，保证注销 / 改密后
    cookie 真的被清除。
    """
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        secure=_is_https(request) if request is not None else False,
        httponly=True,
        samesite="lax",
    )


# ── Root & Health ───────────────────────────────────────────────


# index.html 解析后的字符串缓存。每条 server 进程一份，按 (path, mtime) 失效。
# 加 _INDEX_LOCK 是因为：FastAPI / Starlette 在 ThreadPoolExecutor 上跑同步 def 路由，
# 两个并发请求可能同时进入 _serve_index → 同时读写 _INDEX_CACHE。
# CPython GIL 让 dict.update 是原子的，但读到的中间态（mtime 已更新但 html 还是旧的）
# 会让浏览器拿到错位的版本号 + 旧 HTML，cache-busting 失败。
_INDEX_CACHE: dict = {"path": None, "version": "0", "html": None, "mtime": 0.0}
_INDEX_LOCK = threading.Lock()


def _compute_static_version() -> str:
    """以 static 目录下关键资源的最大 mtime 作为版本号。

    每次重新部署 docker（COPY static），文件 mtime 变更，version 自动更新，
    浏览器与 Cloudflare 都能识别为新 URL。
    """
    files = ("app.js", "app.css", "i18n.js", "index.html", "icon.png")
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
        # 静态资源目录损坏 / index.html 被误删时返回明确 503，避免后续
        # open() 触发 FileNotFoundError 让 uvicorn 直接 500（堆栈泄露 + 误诊为代码 bug）
        return Response(
            content="服务暂不可用：缺少前端入口文件 index.html\n",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            media_type="text/plain; charset=utf-8",
        )

    with _INDEX_LOCK:
        if _INDEX_CACHE["path"] != path or _INDEX_CACHE["mtime"] != mtime:
            try:
                version = _compute_static_version()
                with open(path, "r", encoding="utf-8") as fp:
                    html = fp.read().replace("__STATIC_VERSION__", version)
            except OSError as exc:
                logger.exception("读取 index.html 失败: %s", exc)
                return Response(
                    content="服务暂不可用：无法读取前端入口文件\n",
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    media_type="text/plain; charset=utf-8",
                )
            _INDEX_CACHE.update({
                "path": path, "version": version, "html": html, "mtime": mtime,
            })
        cached_html = _INDEX_CACHE["html"]

    return Response(
        content=cached_html,
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


# 版本号解析顺序：环境变量 APP_VERSION > git rev-parse --short=8 HEAD > "dev"
# 本地源码运行时自动读 git，避免显示成 ``vdev`` 这种"开发占位符"看起来像 bug。
# Docker 容器内没有 .git 目录，会回退到环境变量（由 deploy.sh 写 .env 注入）。
from core.version import resolve_app_version  # noqa: E402,WPS433
_APP_VERSION = resolve_app_version(
    repo_root=Path(__file__).resolve().parent,
)


@app.get("/api/health")
def health() -> dict:
    return {
        "ok": True,
        "auth_required": True,
        "register_enabled": not DISABLE_REGISTER,
        "version": _APP_VERSION,
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

    # 注册限流：IP 维度独立桶（10 分钟 10 次失败触发锁定）。
    # 必须放在 PBKDF2 哈希之前，否则攻击者用错密码刷接口仍能耗光 CPU。
    # ``DISABLE_REGISTER=1`` 时 403 路径不走 limiter — 注册关闭场景下接口
    # 总是返回固定错误，不存在"被刷爆"问题，反而走 limiter 会让运维误判。
    allowed, retry_after = register_limiter.check(REGISTER_LIMITER_KEY, ip)
    if not allowed:
        db.log_audit("register", username=req.username, ip=ip, user_agent=ua,
                     success=False, detail=f"注册已锁定，剩余 {retry_after}s")
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"注册尝试次数过多，请 {retry_after // 60} 分钟后再试",
            headers={"Retry-After": str(retry_after)},
        )

    username = normalize_username(req.username)
    ok, msg = validate_username(username)
    if not ok:
        register_limiter.record_failure(REGISTER_LIMITER_KEY, ip)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg)
    ok, msg = validate_password(req.password)
    if not ok:
        register_limiter.record_failure(REGISTER_LIMITER_KEY, ip)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg)

    if db.get_user_by_username(username):
        register_limiter.record_failure(REGISTER_LIMITER_KEY, ip)
        db.log_audit("register", username=username, ip=ip, user_agent=ua,
                     success=False, detail="用户名已存在")
        raise HTTPException(status.HTTP_409_CONFLICT, "用户名已存在")

    user_id = db.create_user(username, hash_password(req.password))
    if not user_id:
        register_limiter.record_failure(REGISTER_LIMITER_KEY, ip)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "注册失败")

    # 注册成功：清空当前 IP 的失败计数，允许后续合法重试不被卡
    register_limiter.record_success(REGISTER_LIMITER_KEY, ip)
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

    # 双层登录限流：
    # - ``login_limiter``  ：(username, ip) 双键，挡"同账号反复试密码"
    # - ``ip_login_limiter``：纯 IP 维度桶，挡"同 IP 横扫多用户名"的分布式撞库
    # 任一触发都拒绝，确保不能用代理池 + 字典轮 username 来绕开双键限流。
    ip_allowed, ip_retry = ip_login_limiter.check(IP_LOGIN_LIMITER_KEY, ip)
    if not ip_allowed:
        db.log_audit("login", username=username, ip=ip, user_agent=ua,
                     success=False, detail=f"IP 已锁定，剩余 {ip_retry}s")
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"登录失败次数过多，请 {ip_retry // 60} 分钟后再试",
            headers={"Retry-After": str(ip_retry)},
        )

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
        # IP 维度独立计失败：双键桶被绕过（用不同 username）时，IP 桶仍累计
        ip_locked, ip_lock_secs = ip_login_limiter.record_failure(
            IP_LOGIN_LIMITER_KEY, ip,
        )
        remaining = login_limiter.remaining_attempts(username, ip)
        detail = (
            f"已锁定 {lock_secs // 60} 分钟" if locked
            else (f"剩余 {remaining} 次" if remaining is not None else "")
        )
        # 已知用户存在 → 把 user_id 写入审计，让用户能在"仅看自己"的审计
        # 列表里看到自己的失败登录记录（旧版漏写 user_id 让用户看不到自己的
        # 失败尝试，给账号被试密码却毫无察觉留了空子）；
        # 用户名拼错 / 不存在 → user_id 留空，避免对未注册用户名做枚举式审计
        known_user_id = user["id"] if user else None
        db.log_audit("login", user_id=known_user_id, username=username,
                     ip=ip, user_agent=ua, success=False, detail=detail)
        # IP 维度先锁优先级 ≥ username 维度（更广的封禁，更明确的告警）
        if ip_locked:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                f"登录失败次数过多，已锁定 {ip_lock_secs // 60} 分钟",
                headers={"Retry-After": str(ip_lock_secs)},
            )
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
    # 登录成功也清掉该 IP 的失败计数；让用户拼错几次密码后成功登录不会
    # 因 IP 桶残留计数被未来误锁
    ip_login_limiter.record_success(IP_LOGIN_LIMITER_KEY, ip)
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
    _clear_session_cookie(response, request)
    if user_info:
        db.log_audit("logout", user_id=user_info["id"],
                     username=user_info["username"], ip=ip, user_agent=ua)
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: dict = CurrentUser) -> dict:
    """返回当前用户身份。

    ``is_owner`` 标识当前用户是否是接码业务站长（CODE_OWNER_USERNAME），
    前端据此控制"加入接码 / 移出接码"按钮和"接码"列的显隐。

    安全：``code_owner_username`` **仅在请求者本身就是站长时**才回显真实值。
    旧版无差别返回，让任意已注册用户登录后都能拿到站长用户名 → 针对该
    用户名做精确字典撞库（管理端登录限流是 (username, ip) 双键，
    分布式代理池下仍能慢速尝试）。本字段对非 owner 永远是空串，
    保证字段存在但无信息泄露。
    """
    is_owner = user["username"] == CODE_OWNER_USERNAME
    return {
        "username": user["username"],
        "is_owner": is_owner,
        "code_owner_username": CODE_OWNER_USERNAME if is_owner else "",
    }


@app.post("/api/auth/change-password")
def change_password(
    req: ChangePasswordRequest,
    request: Request,
    response: Response,
    user: dict = CurrentUser,
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
    # 改密后必须把该用户的所有会话清空（含当前），强制重新登录。
    # 之前仅 cleanup_expired_sessions（只删过期），未踢"已被偷过去的有效 cookie"。
    killed = db.delete_user_sessions(user["id"])
    db.cleanup_expired_sessions()
    _clear_session_cookie(response, request)
    db.log_audit(
        "change_password", user_id=user["id"], username=user["username"],
        ip=ip, user_agent=ua, success=True,
        detail=f"sessions_revoked={killed}",
    )
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
        # 旧实现走 ``get_all_accounts``，会把整张账号表（含 N 个 Fernet
        # 密文 password / refresh_token）全部解密一次只为读 email 字段；
        # N=10000 时是 ~2 万次 Fernet 操作，几乎是 import 接口的全部 CPU。
        # ``get_existing_emails`` 只 ``SELECT LOWER(email)``，O(N) 但常数极小。
        existing = db.get_existing_emails(user["id"])

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


def _require_code_owner(user: dict) -> None:
    """接码白名单管理：仅 CODE_OWNER_USERNAME 用户可调用，其它一律 403。

    数据库层的 ``set_account_public`` 自带 ``owner_id`` 隔离 — 即便普通
    用户绕过 UI 直接 POST 也只能改自己名下的账号；但站长邮箱在管理端没必要
    给普通用户暴露这一功能（产品定义就是"只有 xiaoxuan 才能玩接码"），所以
    在 API 层提前 403 拒绝，避免前端按钮被绕过 / 普通用户误触。
    """
    if (user.get("username") or "") != CODE_OWNER_USERNAME:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "仅站长可使用接码白名单功能"
        )


@app.get("/api/accounts/public-ids")
def list_public_account_ids(user: dict = CurrentUser) -> dict:
    """返回当前用户名下已加入接码白名单的账号 id 列表。

    前端据此给账号表格的"接码"列渲染徽章。普通用户调用也不会报错，只是
    返回空列表（普通用户名下不会有 is_public=1 的账号被接码端使用）。
    """
    if (user.get("username") or "") != CODE_OWNER_USERNAME:
        return {"ids": []}
    with db._connect() as conn:  # noqa: SLF001
        cur = conn.execute(
            "SELECT id FROM accounts WHERE owner_id = ? AND is_public = 1",
            (user["id"],),
        )
        ids = [int(r[0]) for r in cur.fetchall()]
    return {"ids": ids}


@app.post("/api/accounts/set-public")
def set_accounts_public(
    req: SetPublicRequest, request: Request, user: dict = CurrentUser
) -> dict:
    """批量把账号加入 / 移出接码白名单（仅站长）。

    - ``is_public=True``：加入接码白名单，``code-receiver`` 前台才会接受
      这些邮箱的查询请求；分类按 ``allowed_categories`` 控制（详见
      ``SetPublicRequest`` 的字段说明）。
    - ``is_public=False``：移出白名单，``allowed_categories`` 也会被清空，
      接码端立即拒绝这些邮箱的查询。
    """
    _require_code_owner(user)
    cats = req.allowed_categories
    # 前端"加入接码"按钮不会传 allowed_categories（None），历史会落到
    # "按 group_name 自动推断"——分组名不含 cursor/gpt/... 关键字时
    # 静默失效：UI 显示"已开放"而前台查不到。统一为放行所有分类，
    # 让"加入接码白名单 ⟺ 前台所有分类都能查到"语义一致。
    # is_public=False 时不补 '*'，由 DB 层把 allowed_categories 清空。
    if req.is_public and not cats:
        cats = ["*"]
    updated = 0
    for aid in req.ids:
        if db.set_account_public(
            user["id"], aid, req.is_public, allowed_categories=cats
        ):
            updated += 1
    # audit 详情：明确区分"显式分类列表" / "通配 *" / "清空"。
    # is_public=False 路径下 cats 必为 None（清空），is_public=True 路径下
    # 路由层会把 None 升级为 ['*']，所以正常情况 cats 永远非空。
    cats_label = ",".join(cats) if cats else ("cleared" if not req.is_public else "auto-group")
    db.log_audit(
        "set_account_public", user_id=user["id"], username=user["username"],
        ip=_client_ip(request), user_agent=request.headers.get("user-agent", ""),
        target=",".join(map(str, req.ids[:20])) + ("..." if len(req.ids) > 20 else ""),
        detail=(
            f"is_public={int(req.is_public)},updated={updated},"
            f"requested={len(req.ids)},cats={cats_label}"
        ),
    )
    return {"updated": updated, "requested": len(req.ids), "is_public": req.is_public}


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

    # 二次密码限速：cookie 被劫持 / 浏览器被 XSS 后，攻击者会反复试探登录
    # 密码以图获取明文凭据。复用登录限流器，key=username，让登录与导出共享
    # 同一锁桶。锁定期间登录与导出二次确认均拒绝，强迫人介入。
    username_for_limit = (user.get("username") or "").strip()
    allowed, retry_after = login_limiter.check(username_for_limit, ip)
    if not allowed:
        db.log_audit(
            "export_accounts", user_id=user["id"], username=user["username"],
            ip=ip, user_agent=ua, success=False,
            detail=f"二次密码已锁定，剩余 {retry_after}s",
        )
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"导出操作失败次数过多，请 {retry_after // 60} 分钟后再试",
            headers={"Retry-After": str(retry_after)},
        )

    full = db.get_user_by_id(user["id"])
    if not full or not verify_password(req.password, full["password_hash"]):
        login_limiter.record_failure(username_for_limit, ip)
        db.log_audit(
            "export_accounts", user_id=user["id"], username=user["username"],
            ip=ip, user_agent=ua, success=False, detail="二次密码错误",
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "登录密码错误，导出取消")

    # 二次密码正确：清空错误计数，避免与登录共享计数时被对方拖累
    login_limiter.record_success(username_for_limit, ip)

    # 范围决定（按优先级，三选一）：
    # 1) ids 非空 → 仅导出指定 ID 的账号（owner_id 隔离 + 顺带去重，保留传入顺序）
    # 2) group 非空且不为"全部" → 按分组导出
    # 3) 默认 → 全部账号
    scope_label: str
    ids_summary = ""
    if req.ids:
        ordered_ids: list[int] = []
        seen: set = set()
        for i in req.ids:
            if i not in seen:
                seen.add(i)
                ordered_ids.append(i)
        # 走 SQL ``WHERE owner_id=? AND id IN (...)`` 直接拉取，避免 O(N)
        # 全表加载到内存再过滤
        owned = {a.id: a for a in db.get_accounts_by_ids(user["id"], ordered_ids)}
        accs = [owned[i] for i in ordered_ids if i in owned]
        scope_label = f"selected({len(accs)}/{len(ordered_ids)})"
        # 审计 detail 里记录前 20 个 ids（500 字符限制下足以容纳），事后追溯
        # "导出过哪些账号"用，用 +"..." 表示截断
        head = ordered_ids[:20]
        ids_summary = ",".join(str(i) for i in head) + (
            "..." if len(ordered_ids) > len(head) else ""
        )
    elif req.group and req.group != "全部":
        accs = db.get_accounts_by_group(user["id"], req.group)
        scope_label = req.group
    else:
        accs = db.get_all_accounts(user["id"])
        scope_label = "全部"

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

    detail = (
        f"count={len(accs)},include_group={req.include_group},"
        f"sep={req.separator}"
    )
    if ids_summary:
        detail += f",ids=[{ids_summary}]"
    db.log_audit(
        "export_accounts", user_id=user["id"], username=user["username"],
        ip=ip, user_agent=ua, target=scope_label, detail=detail,
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
    account_id: int, req: GroupUpdate, request: Request, user: dict = CurrentUser
) -> dict:
    if not db.update_account_group(user["id"], account_id, req.group):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")
    db.log_audit(
        "update_account_group", user_id=user["id"], username=user["username"],
        ip=_client_ip(request), user_agent=request.headers.get("user-agent", ""),
        target=str(account_id), detail=f"group={req.group[:64]}",
    )
    return {"ok": True}


@app.put("/api/accounts/{account_id}/remark")
def update_account_remark(
    account_id: int, req: RemarkUpdate, request: Request, user: dict = CurrentUser
) -> dict:
    if not db.update_account_remark(user["id"], account_id, req.remark):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")
    db.log_audit(
        "update_account_remark", user_id=user["id"], username=user["username"],
        ip=_client_ip(request), user_agent=request.headers.get("user-agent", ""),
        target=str(account_id), detail=f"len={len(req.remark)}",
    )
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
    with_body: bool = Query(False),
    user: dict = CurrentUser,
) -> dict:
    """获取邮件列表。

    默认 ``with_body=False`` — 列表里 ``body`` 字段被清空，仅保留
    ``preview``（前 200 字符）。点击单封时由 ``/emails/body`` 按需拉取完整正文。
    这样列表加载快得多（节省 90% 左右带宽），刷新体验丝滑。
    """
    acc = get_account_or_404(user["id"], account_id)
    client = create_client(user["id"], acc)
    try:
        # with_body 直接透传到 GraphClient.fetch_emails，让 Graph 服务端就不返回 body
        # 比"先拉再丢"省了 ~MB 级的传输 + Graph 服务端处理
        emails, msg = client.fetch_emails(folder=folder, limit=limit, with_body=with_body)
    finally:
        client.disconnect()
    for e in emails:
        if e.get("date"):
            e["date"] = e["date"].isoformat()
        if not with_body:
            # IMAP 路径仍可能返回完整 body（无视参数），做一道清理保证带宽节省
            full_body = e.get("body") or ""
            if not e.get("preview"):
                e["preview"] = full_body[:200]
            e["body"] = ""
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
    account_id: int, req: MarkReadRequest, request: Request, user: dict = CurrentUser
) -> dict:
    acc = get_account_or_404(user["id"], account_id)
    client = create_client(user["id"], acc)
    try:
        ok, msg = client.mark_as_read(req.email_id, req.folder, req.is_read)
    finally:
        client.disconnect()
    db.log_audit(
        "mark_email_read", user_id=user["id"], username=user["username"],
        ip=_client_ip(request), user_agent=request.headers.get("user-agent", ""),
        target=str(account_id), success=ok,
        detail=f"folder={req.folder},is_read={int(req.is_read)},msg={(msg or '')[:60]}",
    )
    return {"success": ok, "message": msg}


@app.post("/api/accounts/{account_id}/emails/delete")
def delete_email_api(
    account_id: int, req: DeleteEmailRequest, request: Request, user: dict = CurrentUser
) -> dict:
    acc = get_account_or_404(user["id"], account_id)
    client = create_client(user["id"], acc)
    try:
        ok, msg = client.delete_email(req.email_id, req.folder)
    finally:
        client.disconnect()
    db.log_audit(
        "delete_email", user_id=user["id"], username=user["username"],
        ip=_client_ip(request), user_agent=request.headers.get("user-agent", ""),
        target=str(account_id), success=ok,
        detail=f"folder={req.folder},msg={(msg or '')[:60]}",
    )
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


def _check_one_sync(owner_id: int, aid: int) -> dict:
    """检测单个账号（IO 同步）— 在线程池中运行。"""
    acc = db.get_account(owner_id, aid)
    if not acc:
        return {"email": "?", "status": "异常", "has_aws": False, "found": False}
    client = create_client(owner_id, acc)
    has_aws = False
    status_str = "异常"
    try:
        try:
            status_str, _ = client.check_status()
        except Exception:
            logger.exception("check_status 异常 acc=%s", aid)
        try:
            db.update_account_status(owner_id, aid, status_str)
        except Exception:
            logger.exception("update_account_status 异常 acc=%s", aid)
        if status_str == "正常":
            try:
                has_aws, _ = client.check_aws_verification_emails(limit=30)
                db.update_aws_code_status(owner_id, aid, has_aws)
            except Exception:
                logger.exception("AWS 检测异常 acc=%s", aid)
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
    return {"email": acc.email, "status": status_str, "has_aws": has_aws, "found": True}


def _send_one_sync(owner_id: int, aid: int, to: str, subject: str, body: str) -> dict:
    """单账号发信（IO 同步）— 在线程池中运行。

    异常 message 截断到 200 字符并仅保留异常类名 + 摘要，避免把
    带敏感路径 / 邮箱凭据 / 完整堆栈细节的 SMTP 库异常透传给前端。
    完整堆栈仍由 logger.exception 写到本地日志便于运维取证。
    """
    acc = db.get_account(owner_id, aid)
    if not acc:
        return {"email": "?", "success": False, "message": "Not found"}
    client = create_client(owner_id, acc)
    try:
        ok, msg = client.send_email(to, subject, body)
    except Exception as exc:
        logger.exception("send_email 异常 acc=%s", aid)
        # 仅暴露异常类型给前端，避免把 SMTP 服务商返回的错误细节
        # （可能含目标邮箱、内部策略、内部地址等敏感信息）泄露到浏览器端。
        # 完整 ``str(exc)`` + 堆栈仍写在服务端日志里供运维取证。
        safe_msg = f"异常: {type(exc).__name__}"
        ok, msg = False, safe_msg
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
    return {"email": acc.email, "success": ok, "message": msg}


# SSE 响应头：禁用 nginx / Cloudflare 的代理缓冲，确保进度即时推送给前端；
# 否则反代会等到全部数据收齐才一次性下发，进度条变成"卡 99% 突然完成"。
_SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",        # nginx
    "X-Content-Type-Options": "nosniff",
}


def _detect_run_sync_cancel_kwargs() -> dict:
    """anyio 3.x 用 ``cancellable``，4.x 改名 ``abandon_on_cancel``；做一次版本探测。

    检测 ``anyio.to_thread.run_sync`` 的签名，返回应传的 kwargs，
    让"task.cancel() 后让出"在两个版本下都生效。
    """
    try:
        sig = inspect.signature(anyio.to_thread.run_sync)
    except (TypeError, ValueError):
        return {}
    params = sig.parameters
    if "abandon_on_cancel" in params:
        return {"abandon_on_cancel": True}
    if "cancellable" in params:
        return {"cancellable": True}
    return {}


_RUN_SYNC_CANCEL_KWARGS = _detect_run_sync_cancel_kwargs()


async def _cancel_pending(tasks: list[asyncio.Task]) -> None:
    """取消所有未完成的 task，并等待它们真正结束。

    用于 SSE 生成器在客户端断开 / 异常退出时清理资源，避免 task 在后台继续
    跑 IMAP/SMTP（特别是 batch_send 会继续把邮件发出去无法收回）。

    注意：``anyio.to_thread.run_sync`` 默认不可中断，必须传 ``cancellable``
    （3.x）或 ``abandon_on_cancel``（4.x）才能让 task.cancel() 立刻让出 —
    已经被线程实际执行的同步调用仍会跑完（Python 不允许从外部停线程），
    但不会再消费排队中的任务，最大限度收敛副作用。
    """
    for t in tasks:
        if not t.done():
            t.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


@app.post("/api/batch/check")
async def batch_check(
    req: BatchCheckRequest, request: Request, user: dict = CurrentUser
) -> StreamingResponse:
    """并发检测多个账号，结果按完成顺序流式推送。

    - 并发数由 ``EMAIL_BATCH_CHECK_CONCURRENCY`` 环境变量控制（默认 8）
    - 用 anyio 的线程池包裹同步 IMAP/Graph 调用（``cancellable=True`` 让 task 可被取消）
    - 完成顺序与传入顺序无关；前端用 ``current`` 字段跟踪进度
    - 客户端断开后立即取消未完成 task，避免资源泄露
    """
    owner_id = user["id"]
    total = len(req.account_ids)
    sem = asyncio.Semaphore(BATCH_CHECK_CONCURRENCY)

    async def run_one(aid: int) -> dict:
        async with sem:
            return await anyio.to_thread.run_sync(
                _check_one_sync, owner_id, aid, **_RUN_SYNC_CANCEL_KWARGS,
            )

    async def generate():
        sc = fc = 0
        completed = 0
        tasks = [asyncio.create_task(run_one(aid)) for aid in req.account_ids]
        try:
            for fut in asyncio.as_completed(tasks):
                # 客户端关闭连接（关浏览器 / 切页面）时立刻退出，剩余 task 在 finally 里清理
                if await request.is_disconnected():
                    break
                try:
                    r = await fut
                except asyncio.CancelledError:
                    break
                completed += 1
                if r.get("status") == "正常":
                    sc += 1
                else:
                    fc += 1
                yield _sse({
                    "type": "progress", "current": completed, "total": total,
                    "email": r.get("email", "?"),
                    "status": r.get("status", "异常"),
                    "has_aws": r.get("has_aws", False),
                })
            else:
                yield _sse({"type": "done", "success": sc, "fail": fc})
        finally:
            await _cancel_pending(tasks)

    return StreamingResponse(generate(), media_type="text/event-stream", headers=_SSE_HEADERS)


@app.post("/api/batch/send")
async def batch_send(
    req: BatchSendRequest, request: Request, user: dict = CurrentUser
) -> StreamingResponse:
    """并发批量发信。

    并发度低于 batch_check（默认 4），因为大多数 SMTP 服务商对
    同 IP 高频发送有节流策略，过高并发反而会触发限流/被封号。

    客户端断开（主动取消）时会立刻 cancel 未启动的 task — 已被线程持有的
    `server.sendmail` 仍会发出当前那 N 封（N≤并发数），但**之后排队的不会再启动**。
    """
    owner_id = user["id"]
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")
    total = len(req.account_ids)
    sem = asyncio.Semaphore(BATCH_SEND_CONCURRENCY)

    db.log_audit(
        "batch_send_start", user_id=owner_id, username=user["username"],
        ip=ip, user_agent=ua, target=req.to[:100],
        detail=f"accounts={total},concurrency={BATCH_SEND_CONCURRENCY}",
    )

    async def run_one(aid: int) -> dict:
        async with sem:
            return await anyio.to_thread.run_sync(
                _send_one_sync, owner_id, aid, req.to, req.subject, req.body,
                **_RUN_SYNC_CANCEL_KWARGS,
            )

    async def generate():
        sc = fc = 0
        completed = 0
        tasks = [asyncio.create_task(run_one(aid)) for aid in req.account_ids]
        aborted = False
        try:
            for fut in asyncio.as_completed(tasks):
                if await request.is_disconnected():
                    aborted = True
                    break
                try:
                    r = await fut
                except asyncio.CancelledError:
                    aborted = True
                    break
                completed += 1
                if r.get("success"):
                    sc += 1
                else:
                    fc += 1
                yield _sse({
                    "type": "progress", "current": completed, "total": total,
                    "email": r.get("email", "?"),
                    "success": r.get("success", False),
                    "message": r.get("message", ""),
                })
            else:
                yield _sse({"type": "done", "success": sc, "fail": fc})
        finally:
            await _cancel_pending(tasks)
            db.log_audit(
                "batch_send_done", user_id=owner_id, username=user["username"],
                ip=ip, user_agent=ua, target=req.to[:100],
                detail=(
                    f"success={sc},fail={fc},completed={completed},total={total}"
                    + (",aborted=1" if aborted else "")
                ),
            )

    return StreamingResponse(generate(), media_type="text/event-stream", headers=_SSE_HEADERS)


# ── Audit Log ───────────────────────────────────────────────────


@app.get("/api/audit")
def list_audit_log(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: Optional[str] = Query(None, max_length=64),
    user: dict = CurrentUser,
) -> dict:
    """普通用户只能看自己的审计。

    旧版接受 ``only_self=False`` 让 ``user_id=None`` 落到 ``list_audit``，
    导致**任意已登录用户**都能读全库审计（含其它用户的 IP / UA / 导出
    / 改密等行为）—— 跨用户审计泄露。新版强制只看自己；管理员需求请走
    单独的管理员路由（暂未提供，留作未来 issue）。
    """
    items = db.list_audit(
        limit=limit, offset=offset, user_id=user["id"], action=action,
    )
    return {"items": items, "limit": limit, "offset": offset}


# ── Dashboard ───────────────────────────────────────────────────


@app.get("/api/dashboard")
def get_dashboard(user: dict = CurrentUser) -> dict:
    """仪表盘概览：总数 / 分组分布 / 状态分布。

    旧实现走 ``get_all_accounts`` 全表加载 + Fernet 解密 + Python 侧
    dict 计数；本接口只用聚合数字，password / refresh_token 完全不需要。
    改走 ``get_dashboard_stats`` 的纯 SQL ``GROUP BY`` 后：
    - N=1000 账号：~50ms（含 Fernet）→ ~2ms（仅 SQL 聚合）
    - 减少 N 次 Fernet 解密的内存暴露面
    """
    return db.get_dashboard_stats(user["id"])


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
    """颁发 OAuth2 授权 URL，并把绑定到当前用户的 ``state`` 记入服务端缓存。

    后续 ``/api/oauth2/exchange`` 必须把 redirect_url 中的 state 与服务端
    记录比对一致才能继续，否则视为 CSRF / 绑号尝试拒绝。
    """
    import secrets as _secrets
    state = _secrets.token_urlsafe(24)
    _record_oauth_state(user["id"], state)
    return {"url": OAuth2Helper().get_auth_url(state=state)}


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


# OAuth 凭据"半成品"暂存：refresh_token 已换到、但 _fetch_oauth2_email 失败时
# 用户需要手动补 email 后二次提交。authorization code 是一次性的，丢失后只能
# 重新走整个授权流程；这里在内存里短期保留 refresh_token，避免那次刷新被浪费。
#
# 选择内存而不是 cookie：refresh_token 是高敏字段，不能暴露到前端 JS；放服务端
# 内存里、按 (user_id) 索引、5 分钟自动过期，最安全。
# 单进程多 worker 的 uvicorn 部署下，二次提交可能落到不同 worker → 拿不到缓存，
# 此时 fallback 为返回错误让用户重新授权，体验降级但不会卡住。
_PENDING_OAUTH_TTL = 300.0  # 5 分钟
_pending_oauth: dict[int, tuple[str, str, str, float]] = {}
_pending_oauth_lock = threading.Lock()


# OAuth state 暂存：``/api/oauth2/auth-url`` 生成 state 后写入，
# ``/api/oauth2/exchange`` 校验后弹出。绑定到当前登录用户，TTL 15 分钟。
#
# 防御目标：CSRF 绑号攻击 ——
#   攻击者在自己机器上发起授权流，把生成的 ``code`` 拐到受害者已登录的
#   本服务面板（社工 / 钓鱼链接），如果服务端不校验 state 则会把攻击者
#   的 RT 写到受害者账号；后续受害者的"账号管理"看到一个陌生 OAuth 账号，
#   攻击者通过它读受害者的 IMAP / SMTP。
#
# state 用 ``secrets.token_urlsafe(24)`` 生成，每个用户**最多保留 8 条**最近
# 未使用的 state（覆盖"用户连续点了几次授权按钮"的情况），过期或超过容量
# 后 LRU 淘汰；多 worker 下二次提交可能落到不同 worker，命中失败回退到
# "认 state 失败 → 拒绝交换"，需要用户重新点授权按钮（损失体验换安全）。
_PENDING_STATE_TTL = 900.0  # 15 分钟
_PENDING_STATE_PER_USER = 8
# user_id → list[(state, expires_at)]
_pending_oauth_states: dict[int, list[tuple[str, float]]] = {}
_pending_oauth_states_lock = threading.Lock()


def _record_oauth_state(user_id: int, state: str) -> None:
    """记录新颁发的 state；自动 GC 过期项 + 限制每用户最大条数。"""
    if not state:
        return
    now = time.monotonic()
    with _pending_oauth_states_lock:
        bucket = _pending_oauth_states.setdefault(user_id, [])
        bucket[:] = [(s, t) for (s, t) in bucket if t > now]
        bucket.append((state, now + _PENDING_STATE_TTL))
        if len(bucket) > _PENDING_STATE_PER_USER:
            del bucket[0:len(bucket) - _PENDING_STATE_PER_USER]


def _consume_oauth_state(user_id: int, state: str) -> bool:
    """命中并消费 state；不存在 / 已过期 / 不归当前 user 都返回 False。

    "消费"语义：成功命中后立即移除该 state，防止 replay。
    """
    if not state:
        return False
    now = time.monotonic()
    with _pending_oauth_states_lock:
        bucket = _pending_oauth_states.get(user_id) or []
        idx = -1
        for i, (s, t) in enumerate(bucket):
            if t <= now:
                continue
            if s == state:
                idx = i
                break
        if idx < 0:
            return False
        bucket.pop(idx)
        # 顺手清理过期项，保持 bucket 紧凑
        bucket[:] = [(s, t) for (s, t) in bucket if t > now]
        if not bucket:
            _pending_oauth_states.pop(user_id, None)
        return True


def _gc_pending_oauth() -> tuple[int, int]:
    """全局 GC：扫描所有用户的 OAuth 暂存桶，删除整体过期 / 已无活项的条目。

    必要性：``_record_oauth_state`` 仅在写入"该用户"的桶时清理那个桶，
    ``_consume_oauth_state`` 仅在消费成功后才 ``pop`` 空桶。如果某个用户
    颁发了 state 之后再没回来消费（关浏览器、改主意），他的 user_id 会
    永久占据 dict 一个 entry —— 长期跑的进程下，user_id 不断累积，buckets
    里残留过期项也清不掉，慢速内存泄漏。

    类似地 ``_pending_oauth``（refresh_token 暂存）也只在新写入时局部 GC，
    没人新调用就永远卡着旧条目。

    本函数被 ``_periodic_cleanup`` 一日一次调用，全局扫一遍。
    返回 ``(states_dropped, creds_dropped)`` 用于日志统计。
    """
    now = time.monotonic()
    states_dropped = 0
    creds_dropped = 0

    with _pending_oauth_states_lock:
        empty_users: list[int] = []
        for uid, bucket in _pending_oauth_states.items():
            before = len(bucket)
            bucket[:] = [(s, t) for (s, t) in bucket if t > now]
            states_dropped += before - len(bucket)
            if not bucket:
                empty_users.append(uid)
        for uid in empty_users:
            _pending_oauth_states.pop(uid, None)

    with _pending_oauth_lock:
        expired_users = [
            uid for uid, v in _pending_oauth.items() if v[3] <= now
        ]
        for uid in expired_users:
            _pending_oauth.pop(uid, None)
            creds_dropped += 1

    return states_dropped, creds_dropped


def _extract_state_from_redirect(redirect_url: str) -> Optional[str]:
    """从 redirect URL 的 query 中解析 ``state``；缺失返回 None。"""
    try:
        parsed = urllib.parse.urlparse(redirect_url or "")
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        values = qs.get("state") or []
        return values[0] if values else None
    except (ValueError, TypeError):
        return None


def _pending_oauth_set(user_id: int, client_id: str, refresh_token: str, group: str) -> None:
    now = time.monotonic()
    with _pending_oauth_lock:
        # 顺手清理过期项，避免长期累积
        for k in [k for k, v in _pending_oauth.items() if v[3] <= now]:
            _pending_oauth.pop(k, None)
        _pending_oauth[user_id] = (client_id, refresh_token, group, now + _PENDING_OAUTH_TTL)


def _pending_oauth_pop(user_id: int) -> Optional[tuple[str, str, str]]:
    """取出并删除暂存条目；过期或不存在返回 None。"""
    now = time.monotonic()
    with _pending_oauth_lock:
        entry = _pending_oauth.pop(user_id, None)
    if not entry or entry[3] <= now:
        return None
    return entry[0], entry[1], entry[2]


@app.post("/api/oauth2/exchange")
def exchange_oauth2(req: OAuth2ExchangeRequest, user: dict = CurrentUser) -> dict:
    """OAuth2 授权码换 refresh_token 并落库。

    两阶段提交：
    - 首次：``{redirect_url, group}`` → 后端换 token + 自动取邮箱地址
      若邮箱获取失败，refresh_token 暂存于服务端内存，返回 ``needs_email=True``
    - 二次：``{email}`` → 后端用之前暂存的 token + 用户提供的 email 完成落库

    新增 CSRF 防御：首次调用必须携带先前由 ``/api/oauth2/auth-url`` 颁发并绑定
    到当前 user_id 的 ``state``。校验失败立即拒绝，不消费 authorization code。
    """
    explicit_email = (req.email or "").strip().lower()
    redirect_url = req.redirect_url or ""
    group = (req.group or "默认分组").strip() or "默认分组"

    if explicit_email and not redirect_url:
        # ── 二次提交分支 ──
        pending = _pending_oauth_pop(user["id"])
        if not pending:
            return {
                "success": False,
                "error": "凭据已过期或不存在，请重新点击授权按钮",
            }
        client_id, refresh_token, group = pending
        email = explicit_email
    else:
        # ── 首次分支 ──
        # 先校验 state，避免在 CSRF 场景下白白消费一次性 authorization code
        state = _extract_state_from_redirect(redirect_url)
        if not state:
            return {
                "success": False,
                "error": "授权链接缺少 state 参数；请重新点击授权按钮",
            }
        if not _consume_oauth_state(user["id"], state):
            return {
                "success": False,
                "error": "授权 state 校验失败（可能跨用户/跨标签/已过期）；请重新点击授权按钮",
            }
        helper = OAuth2Helper()
        client_id, refresh_token, error = helper.exchange_code_for_token(redirect_url)
        if error:
            return {"success": False, "error": error}

        email = explicit_email or (_fetch_oauth2_email(client_id, refresh_token) or "")
        if not email:
            # 暂存 refresh_token，让用户手动填 email 后二次提交，避免授权码白白浪费
            _pending_oauth_set(user["id"], client_id, refresh_token, group)
            return {
                "success": False,
                "needs_email": True,
                "error": "无法自动获取邮箱地址，请手动填写邮箱后再次提交（5 分钟内有效）",
            }

    existing = db.get_account_by_email(user["id"], email)
    if existing:
        ok = db.update_account_oauth(user["id"], existing.id, client_id, refresh_token)
        if not ok:
            logger.error("OAuth2 update_account_oauth 失败 user=%s email=%s", user["id"], email)
            return {"success": False, "error": "更新已有账号失败"}
    else:
        ok, msg = db.add_account(
            user["id"],
            email,
            "",
            group,
            client_id=client_id,
            refresh_token=refresh_token,
        )
        if not ok:
            logger.error(
                "OAuth2 add_account 失败 user=%s email=%s msg=%s",
                user["id"], email, msg,
            )
            return {"success": False, "error": f"添加账号失败: {msg}"}
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
    print(f"  反代: {'信任 X-Forwarded-* 头' if TRUST_PROXY else '不信任反代头（公网直连推荐）'}")
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

    # 已有用户但仍开放注册 — 容易被陌生人抢资源，单独警告一次
    try:
        if not DISABLE_REGISTER and db.user_count() > 0:
            warn_lines = (
                "=" * 50,
                "  [WARN] 已检测到至少 1 个注册用户，但注册仍未禁用。",
                "         强烈建议设置 EMAIL_WEB_DISABLE_REGISTER=1 防止陌生人抢用资源。",
                "         例：在 docker-compose.yml 的 environment 区块添加。",
                "=" * 50,
            )
            for line in warn_lines:
                print(line, file=sys.stderr)
    except Exception:
        logger.exception("注册状态检查失败（忽略）")

    # 启动清理（每次重启执行一次，避免长期运行下数据 / 内存无限增长）：
    # - 过期会话：sessions 表
    # - 老审计：audit_log 超过 90 天的删除
    # - 老接码查询日志：code_query_log 超过 30 天的删除（之前漏调用）
    # - 进程级 token 缓存：清掉过期 access_token + 对应 refresh lock
    try:
        from core.oauth_token import evict_expired_token_cache  # noqa: WPS433
        n_sess = db.cleanup_expired_sessions()
        n_audit = db.cleanup_old_audit()
        n_qlog = db.cleanup_old_code_query_log()
        n_tok = evict_expired_token_cache()
        if n_sess or n_audit or n_qlog or n_tok:
            logger.info(
                "启动清理: 过期会话=%d, 老审计=%d, 老接码日志=%d, 过期token=%d",
                n_sess, n_audit, n_qlog, n_tok,
            )
    except Exception:
        logger.exception("启动清理失败（忽略）")

    uvicorn.run(
        app,
        host=host,
        port=port,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        # 仅当显式信任反代时才让 uvicorn 解析 forwarded headers，避免公网直连被伪造
        proxy_headers=TRUST_PROXY,
        forwarded_allow_ips="*" if TRUST_PROXY else "127.0.0.1",
        # 安全：默认 ``Server: uvicorn`` 头会暴露技术栈给攻击者，让他们直接
        # 匹配 uvicorn / FastAPI 已知 CVE 的利用工具。关掉后响应就没有 Server
        # 头（也就避免了"攻击者按 Server 字段做产品探测"这一步）。
        server_header=False,
        # 同样 ``Date`` 头也不必给（部分扫描器把它当指纹）；保留默认即可，
        # 这一行无需改 —— 仅 ``server_header`` 是真正的指纹泄露面。
    )


if __name__ == "__main__":
    main()
