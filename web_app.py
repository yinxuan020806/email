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
import hashlib
import inspect
import json
import logging
import os
import re
import sys
import threading
import time
import urllib.parse
from collections import OrderedDict
from contextlib import asynccontextmanager
from typing import List, Optional

import anyio
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
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send
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
from core.helper_routes import (  # noqa: E402
    configure as configure_helper_routes,
    helper_router,
)
from core.models import Account  # noqa: E402
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
    CODE_RECEIVER_REQUIRE_TOKEN_KEY,
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
    / 长期未用的 helper token。

    任何步骤异常都仅 ``logger.exception`` 记录，不让单步失败拖垮整个 loop。
    被 ``cancel()`` 后立即退出。注意：``asyncio.sleep`` 是天然的 cancellation point。
    """
    from core.oauth_token import evict_expired_token_cache  # noqa: WPS433
    from database.helper_token import purge_expired as purge_helper_tokens  # noqa: WPS433
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
            n_helper = await asyncio.to_thread(purge_helper_tokens)
            if n_sess or n_audit or n_qlog or n_tok or n_helper:
                logger.info(
                    "周期清理: 过期会话=%d, 老审计=%d, 老接码日志=%d, "
                    "过期 token=%d, 过期 helper token=%d",
                    n_sess, n_audit, n_qlog, n_tok, n_helper,
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


# ⚠ 不要把这段改回 ``@app.middleware("http")`` / ``BaseHTTPMiddleware``。
# 实测教训（2026-05-12，evuzdnd.cn 524 事件）：
# BaseHTTPMiddleware 在 SSE / 客户端中途断连 / 路由抛裸异常 三类场景下，
# ``call_next`` 拿不到 response 就抛 ``RuntimeError: No response returned``；
# 该异常会顺着 anyio.TaskGroup 冒到 starlette 顶层，留下没清理干净的
# send/receive 流，**整个 uvicorn event loop 会卡死**——后续所有请求 hang，
# 容器内部 curl 127.0.0.1:8000 都超时，docker healthcheck 失败，Cloudflare
# 100s 等不到 origin 即返 524。详见 encode/starlette#1438。
#
# 纯 ASGI middleware 不走 BaseHTTPMiddleware 的 TaskGroup 路径，仅在
# ``http.response.start`` 这一个 ASGI message 里给 header 加几个字段，
# 不引入额外的异常吞噬层，SSE / 客户端断连场景下也只是把异常透传给上一
# 层（uvicorn 自己能干净处理），不会卡 loop。
class SecurityHeadersMiddleware:
    """给所有 HTTP 响应批量补全安全相关 header（替代 BaseHTTPMiddleware 实现）。

    实现要点：
    - 只 wrap ``http.response.start`` 这一条 ASGI 消息；body 一字不动透传，
      不会破坏 StreamingResponse / SSE。
    - ``MutableHeaders(scope=message)`` 直接操作 ASGI raw headers 列表，
      ``setdefault`` 行为与 ``Response.headers.setdefault`` 一致（已显式设
      过的路由级 header —— 如 SSE 的 ``X-Accel-Buffering: no`` —— 不被覆盖）。
    - HSTS 只在确认 HTTPS 时下发，避免 HTTP 部署被锁死强制 HTTPS。
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    @staticmethod
    def _scope_is_https(scope: Scope) -> bool:
        if scope.get("scheme") == "https":
            return True
        if not TRUST_PROXY:
            return False
        for name, value in scope.get("headers", ()):  # type: ignore[arg-type]
            if name == b"x-forwarded-proto":
                # 与 _is_https 同一规则：多值取首段、精确 ==。
                raw = value.decode("latin-1", errors="ignore")
                proto = raw.split(",", 1)[0].strip().lower()
                return proto == "https"
        return False

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_https = self._scope_is_https(scope)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("Referrer-Policy", "no-referrer")
                headers.setdefault("Content-Security-Policy", _CSP_HEADER)
                headers.setdefault(
                    "Permissions-Policy",
                    "camera=(), microphone=(), geolocation=(), payment=()",
                )
                if is_https:
                    # max-age=1 年；includeSubDomains 让所有子域同享。不加
                    # ``preload`` 避免被 hsts preload list 收录后想下线极难。
                    headers.setdefault(
                        "Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains",
                    )
            await send(message)

        await self.app(scope, receive, send_wrapper)


app.add_middleware(SecurityHeadersMiddleware)


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
    # 历史字段名叫 skip_duplicate；前端现在把它作为"按邮箱去重并覆盖旧凭据"
    # 的开关继续传入，保留字段名避免破坏旧客户端。
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


class AccountCredentialsUpdate(BaseModel):
    password: str = Field(default="", max_length=1024)
    client_id: Optional[str] = Field(default=None, max_length=512)
    refresh_token: Optional[str] = Field(default=None, max_length=8192)

    @field_validator("client_id", "refresh_token")
    @classmethod
    def _trim_optional(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        return v or None


class AccountAccessTokensUpdate(BaseModel):
    access_tokens: dict[str, str] = Field(default_factory=dict)


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


# ── Helpers ─────────────────────────────────────────────────────


def account_to_dict(
    acc: Account,
    *,
    include_refresh_token: bool = True,
    include_access_token: bool = True,
) -> dict:
    """Account → 给前端的 dict（含密码，仅在本地受信任环境下使用）。

    ``include_refresh_token`` 默认 True 保持单条 GET / 详情页的旧行为不变。
    列表接口（``list_accounts``）会显式传 False：
    - refresh_token 平均 200~300 字节，是响应体最大头；移除后 256 账号
      下 JSON 从 ~107KB 降到 ~50KB
    - 列表不需要它（前端只在「复制完整 / 详情」时才用，那两个动作走单条
      GET 现拉），少一次驻留浏览器内存的副本，安全性也好一点

    ``include_access_token`` 控制是否回显接码邮箱凭证：
    - 仅站长（``CODE_OWNER_USERNAME``）调用账号 API 时才应该传 True
    - 普通用户即便绕过 UI 也只能拿到自己名下账号的 password / refresh_token，
      access_token 字段被剥离，避免普通用户误把它当 password 用
    """
    base = {
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
        "created_at": acc.created_at,
        "last_check": acc.last_check,
        "has_aws_code": bool(acc.has_aws_code),
        "remark": acc.remark,
    }
    if include_refresh_token:
        base["refresh_token"] = acc.refresh_token
    if include_access_token:
        # v9 起 Cursor / GPT(OpenAI) 各有独立凭证；旧 access_token 仅做
        # 兼容展示，不再作为接码前台校验依据。
        access_tokens = {
            "cursor": acc.access_token_cursor or "",
            "openai": acc.access_token_openai or "",
        }
        base["access_tokens"] = access_tokens
        base["access_token_cursor"] = access_tokens["cursor"]
        base["access_token_openai"] = access_tokens["openai"]
        base["access_token"] = (
            access_tokens["cursor"]
            or access_tokens["openai"]
            or acc.access_token
            or ""
        )
    return base


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


# SPA 前端路由：/login、/register、/dashboard、/settings、/help 都返回 index.html
@app.get("/login")
@app.get("/register")
@app.get("/dashboard")
@app.get("/settings")
@app.get("/help")
async def spa_routes() -> Response:
    return _serve_index()


# 版本号解析顺序：环境变量 APP_VERSION > core.version.__version__ 常量 > "dev"
# 默认走代码常量 ``__version__``，发版时只需改 ``core/version.py`` 顶部那一行。
from core.version import resolve_app_version  # noqa: E402,WPS433
_APP_VERSION = resolve_app_version()


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


def _accounts_etag(rev: int, group: Optional[str], sort_by: str, sort_order: str) -> str:
    """根据 (rev, group, sort_by, sort_order) 生成弱 ETag。

    - rev 在任意写 accounts 后 +1，从而账号数据变化必然让 ETag 变化
    - group/sort_* 让"切换分组 / 切换排序"也得到不同 ETag（响应内容不同）
    - W/ 弱 ETag：允许 gzip 等中间件做字节级别的等价变换而不影响命中
    - blake2s 8 字节足以避免可预见的碰撞，比 sha256 更轻
    """
    raw = f"{rev}|{group or ''}|{sort_by}|{sort_order}"
    h = hashlib.blake2s(raw.encode("utf-8"), digest_size=8).hexdigest()
    return f'W/"{h}"'


@app.get("/api/accounts")
def list_accounts(
    request: Request,
    response: Response,
    group: Optional[str] = None,
    sort_by: str = "id",
    sort_order: str = "DESC",
    user: dict = CurrentUser,
) -> list[dict]:
    """账号列表。

    带 ETag 协商：当 ``If-None-Match`` 与当前 (rev, group, sort) 派生的
    ETag 一致时直接返回 304，不走 SQL + 解密 + JSON 序列化的整条链路。
    rev 由 ``DatabaseManager`` 在每次 add/update/delete 时原子 +1，
    保证 ETag 与数据强一致。
    """
    rev = db.get_account_rev(user["id"])
    etag = _accounts_etag(rev, group, sort_by, sort_order)
    # private + must-revalidate：
    # - private 让上游/CDN 不会跨用户共享缓存（账号数据是用户私有的）
    # - must-revalidate 让浏览器即便保留了 200 响应体，下一次请求仍必须带
    #   If-None-Match 来验证；命中 304 时浏览器透明地把缓存的响应给 fetch
    cache_control = "private, must-revalidate"
    if_none_match = request.headers.get("if-none-match", "")
    if if_none_match and etag in {tag.strip() for tag in if_none_match.split(",")}:
        # 304 必须保留 ETag + Cache-Control，让客户端把同一 etag 复用到下一次
        return Response(
            status_code=status.HTTP_304_NOT_MODIFIED,
            headers={"ETag": etag, "Cache-Control": cache_control},
        )

    if group and group != "全部":
        accs = db.get_accounts_by_group_sorted(user["id"], group, sort_by, sort_order)
    else:
        accs = db.get_all_accounts_sorted(user["id"], sort_by, sort_order)
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = cache_control
    # 列表里 refresh_token 不返回，前端按需走 /api/accounts/{id} 拉
    # access_token 仅站长可见（前端表格里渲染「凭证」列需要）；普通用户拿不到
    is_owner = user["username"] == CODE_OWNER_USERNAME
    return [
        account_to_dict(
            a, include_refresh_token=False, include_access_token=is_owner,
        )
        for a in accs
    ]


# ⚠️ 注意：以下静态路径必须在 /{account_id} 之前声明，否则会被吞掉。

@app.post("/api/accounts/import")
def import_accounts(
    req: ImportRequest, request: Request, user: dict = CurrentUser
) -> dict:
    accounts = parse_import_text(req.text)
    if not accounts:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "未识别到有效账号")

    existing: dict[str, int] = {}
    if req.skip_duplicate:
        # 旧实现走 ``get_all_accounts``，会把整张账号表（含 N 个 Fernet
        # 密文 password / refresh_token）全部解密一次只为读 email 字段；
        # N=10000 时是 ~2 万次 Fernet 操作，几乎是 import 接口的全部 CPU。
        # ``get_existing_email_ids`` 只读 email + id，不解密任何敏感字段。
        existing = db.get_existing_email_ids(user["id"])

    created = updated = fail = skipped = 0
    groups_created: set[str] = set()
    for data in accounts:
        email = data["email"]
        # 单条账号自带的 group 优先级 > 表单选的全局 group
        target_group = (data.get("group") or req.group or "默认分组").strip() or "默认分组"
        if target_group != "默认分组":
            groups_created.add(target_group)
        email_key = email.lower()
        already_known = email_key in existing
        if req.skip_duplicate:
            ok, _msg, was_created = db.upsert_account_by_email(
                user["id"],
                email,
                data["password"],
                target_group,
                client_id=data.get("client_id"),
                refresh_token=data.get("refresh_token"),
            )
        else:
            ok, _msg = db.add_account(
                user["id"],
                email,
                data["password"],
                target_group,
                client_id=data.get("client_id"),
                refresh_token=data.get("refresh_token"),
            )
            was_created = True
        if ok:
            if req.skip_duplicate and (already_known or not was_created):
                updated += 1
            else:
                created += 1
            existing[email_key] = existing.get(email_key, 0) or -1
        else:
            fail += 1
    success = created + updated
    db.log_audit(
        "import_accounts", user_id=user["id"], username=user["username"],
        ip=_client_ip(request), user_agent=request.headers.get("user-agent", ""),
        target=req.group,
        detail=f"success={success},created={created},updated={updated},"
               f"fail={fail},skipped={skipped},"
               f"groups={','.join(sorted(groups_created))[:200]}",
    )
    return {
        "success": success, "fail": fail, "skipped": skipped,
        "created": created, "updated": updated,
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
            "SELECT id, COALESCE(allowed_categories, '') "
            "FROM accounts WHERE owner_id = ? AND is_public = 1",
            (user["id"],),
        )
        rows = cur.fetchall()
    ids = [int(r[0]) for r in rows]
    categories = {int(r[0]): r[1] for r in rows}
    return {"ids": ids, "categories": categories}


@app.post("/api/accounts/set-public")
def set_accounts_public(
    req: SetPublicRequest, request: Request, user: dict = CurrentUser
) -> dict:
    """批量把账号加入 / 移出接码白名单（仅站长）。

    - ``is_public=True``：加入接码白名单，``code-receiver`` 前台才会接受
      这些邮箱的查询请求；分类按 ``allowed_categories`` 控制（详见
      ``SetPublicRequest`` 的字段说明）。当前开放分类没有凭证时会自动生成：
      Cursor 以 C 开头，GPT/OpenAI 以 G 开头；已有分类凭证保留原值
      （避免一次"加入接码"误把所有分发出去的链接全废）。
    - ``is_public=False``：移出白名单，``allowed_categories`` 也会被清空，
      接码端立即拒绝这些邮箱的查询。``access_token`` 保留——只是失去入口，
      下次重新加入时不必再分发新凭证（如果旋转过，旧分发也仍然失效）。

    返回结构 ``tokens: {id: {category: "新凭证明文"}}``：仅本次调用**新生成**
    的分类凭证才会出现；老凭证不在返回里（站长想看老凭证可以走
    GET /api/accounts/{id} 或表格列）。
    """
    _require_code_owner(user)
    cats = req.allowed_categories
    if req.is_public and not cats:
        cats = ["*"]
    updated = 0
    tokens: dict[int, dict[str, str]] = {}
    for aid in req.ids:
        ok, new_tokens = db.set_account_public(
            user["id"], aid, req.is_public, allowed_categories=cats
        )
        if ok:
            updated += 1
            if new_tokens:
                tokens[aid] = new_tokens
    cats_label = ",".join(cats) if cats else ("cleared" if not req.is_public else "auto-group")
    db.log_audit(
        "set_account_public", user_id=user["id"], username=user["username"],
        ip=_client_ip(request), user_agent=request.headers.get("user-agent", ""),
        target=",".join(map(str, req.ids[:20])) + ("..." if len(req.ids) > 20 else ""),
        detail=(
            f"is_public={int(req.is_public)},updated={updated},"
            f"requested={len(req.ids)},cats={cats_label},"
            f"new_token_accounts={len(tokens)}"
        ),
    )
    return {
        "updated": updated,
        "requested": len(req.ids),
        "is_public": req.is_public,
        "tokens": tokens,
    }


@app.post("/api/accounts/{account_id}/rotate-token")
def rotate_access_token(
    account_id: int, request: Request, user: dict = CurrentUser
) -> dict:
    """旋转单个账号的接码邮箱凭证（仅站长）。

    成功返回 ``{"id": ..., "email": ..., "access_tokens": {"cursor": "C..."}}``。
    凭证以明文返回，站长复制后可重新分发；DB 中存的是 SecretBox 加密版本。
    审计日志只记录 id + email，**绝不**记录 token 原文（避免 audit 表泄露
    + grep 历史日志即可拿到所有有效凭证的可怕场景）。
    """
    _require_code_owner(user)
    # 先 get 一下拿邮箱，确认账号存在且属于站长（顺带防越权 404 - rotate 一旦
    # 成功就 bump 了 rev，这里多一次 SELECT 换"不存在时立即 404 而不是返回 None"
    # 的清晰错误体验）
    acc = db.get_account(user["id"], account_id)
    if not acc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")
    new_tokens = db.rotate_access_token(user["id"], account_id)
    if not new_tokens:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")
    db.log_audit(
        "rotate_access_token", user_id=user["id"], username=user["username"],
        ip=_client_ip(request), user_agent=request.headers.get("user-agent", ""),
        target=str(account_id),
        detail=f"email={acc.email}",
    )
    primary_token = (
        new_tokens.get("cursor")
        or new_tokens.get("openai")
        or next(iter(new_tokens.values()), "")
    )
    return {
        "id": account_id,
        "email": acc.email,
        "access_tokens": new_tokens,
        "access_token": primary_token,
    }


class RotateTokensBulkRequest(BaseModel):
    """批量旋转邮箱凭证。

    - ``ids`` 为空 + ``only_public=True``：旋转该用户名下**所有**已加入接码
      白名单的账号（"一键失效所有分发出去的旧链接"——重大安全事件应急用）
    - ``ids`` 非空：仅旋转指定的、且属于当前用户的账号；不存在 / 越权的 id
      静默忽略
    - ``only_public=False`` 且 ``ids`` 为空时**禁止**（避免误操作把所有账号
      包括从未加入接码的也生成 token；走 422 拒绝）
    """
    ids: Optional[List[int]] = Field(default=None, max_length=5000)
    only_public: bool = True


@app.post("/api/accounts/rotate-tokens-bulk")
def rotate_access_tokens_bulk(
    req: RotateTokensBulkRequest, request: Request, user: dict = CurrentUser
) -> dict:
    """批量旋转接码邮箱凭证（仅站长）。

    返回 ``{"tokens": {id: {category: "新凭证明文", ...}}, "count": N}``。
    单次响应即装下所有新凭证，前端展示一个"邮箱----新凭证"列表让站长复制全部。

    安全：响应 token 仅在本次 HTTP 响应里出现一次；不写 audit detail，
    仅记录 count + ids 的前缀，保证审计表泄露不会暴露任何 token。
    """
    _require_code_owner(user)
    if not req.ids and not req.only_public:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "批量旋转必须指定 ids，或勾选 only_public=true 才允许全量",
        )
    tokens = db.rotate_access_tokens_bulk(
        user["id"], account_ids=req.ids, only_public=req.only_public,
    )
    ids_label = ""
    if req.ids:
        ids_label = ",".join(map(str, req.ids[:20])) + (
            "..." if len(req.ids) > 20 else ""
        )
    db.log_audit(
        "rotate_access_tokens_bulk", user_id=user["id"], username=user["username"],
        ip=_client_ip(request), user_agent=request.headers.get("user-agent", ""),
        target=ids_label,
        detail=f"only_public={int(req.only_public)},count={len(tokens)},"
               f"requested={len(req.ids) if req.ids else 'all'}",
    )
    return {"tokens": tokens, "count": len(tokens)}


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
    is_owner = user["username"] == CODE_OWNER_USERNAME
    return account_to_dict(
        get_account_or_404(user["id"], account_id),
        include_access_token=is_owner,
    )


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


@app.put("/api/accounts/{account_id}/credentials")
def update_account_credentials(
    account_id: int,
    req: AccountCredentialsUpdate,
    request: Request,
    user: dict = CurrentUser,
) -> dict:
    if not db.update_account_credentials(
        user["id"],
        account_id,
        req.password,
        client_id=req.client_id,
        refresh_token=req.refresh_token,
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")
    try:
        _email_list_cache_invalidate(account_id)
    except NameError:
        pass
    db.log_audit(
        "update_account_credentials",
        user_id=user["id"],
        username=user["username"],
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        target=str(account_id),
        detail=(
            f"password_len={len(req.password or '')},"
            f"oauth={int(bool(req.client_id and req.refresh_token))}"
        ),
    )
    return {"ok": True}


@app.put("/api/accounts/{account_id}/access-tokens")
def update_account_access_tokens(
    account_id: int,
    req: AccountAccessTokensUpdate,
    request: Request,
    user: dict = CurrentUser,
) -> dict:
    _require_code_owner(user)
    ok, msg = db.update_account_access_tokens(
        user["id"], account_id, req.access_tokens
    )
    if not ok:
        status_code = (
            status.HTTP_404_NOT_FOUND
            if msg == "Account not found"
            else status.HTTP_400_BAD_REQUEST
        )
        raise HTTPException(status_code, msg)
    cats = ",".join(sorted(req.access_tokens.keys()))[:80]
    db.log_audit(
        "update_account_access_tokens",
        user_id=user["id"],
        username=user["username"],
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        target=str(account_id),
        detail=f"categories={cats}",
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


# 邮件列表"短期记忆"缓存：(user_id, account_id, folder, with_body, limit) →
# (expires_at, emails, msg)。
#
# 解决的问题：用户在邮件弹窗里连点"刷新"，或者写了 setInterval 类脚本反复
# 刷，每次都打到 Microsoft Graph，会被 *per-mailbox*（每邮箱）滚动窗口限速，
# 表象就是"刷几次后所有账号都接收不到"。
#
# 设计取舍：
# - TTL 5 秒：吸收"用户连点的几次连发"，但不影响"间隔 5 秒以上的真刷"
#   命中新邮件——拿到最新邮件的延迟最多 5s
# - 仅缓存成功结果：上游错误不进缓存，避免一次失败把整个 5s 窗口都钉死成
#   "加载失败"
# - 缓存对**用户**隔离：cache key 含 user_id，避免跨用户访问别人邮箱的数据
# - 进程级、不持久化：重启即清；多 worker 部署不共享，只在 worker 内有效
# - 自带容量上限 1024：防止账号 / 文件夹组合无限增长撑爆内存；超过就 LRU 淘汰
_EMAIL_LIST_CACHE_TTL = float(os.getenv("EMAIL_LIST_CACHE_TTL_SEC", "5"))
_EMAIL_LIST_CACHE_MAXSIZE = 1024
_email_list_cache: "OrderedDict[tuple, tuple[float, list, str]]" = OrderedDict()
_email_list_cache_lock = threading.Lock()


def _email_list_cache_get(key: tuple) -> Optional[tuple[list, str]]:
    now = time.time()
    with _email_list_cache_lock:
        entry = _email_list_cache.get(key)
        if entry is None:
            return None
        expires_at, emails, msg = entry
        if expires_at <= now:
            _email_list_cache.pop(key, None)
            return None
        # LRU 触发：刚命中的项移到末尾
        _email_list_cache.move_to_end(key)
        return emails, msg


def _email_list_cache_put(key: tuple, emails: list, msg: str) -> None:
    if _EMAIL_LIST_CACHE_TTL <= 0:
        return
    expires_at = time.time() + _EMAIL_LIST_CACHE_TTL
    with _email_list_cache_lock:
        _email_list_cache[key] = (expires_at, emails, msg)
        _email_list_cache.move_to_end(key)
        # 超容时丢掉最老一条；OrderedDict.popitem(last=False) 是 O(1)
        while len(_email_list_cache) > _EMAIL_LIST_CACHE_MAXSIZE:
            _email_list_cache.popitem(last=False)


def _email_list_cache_invalidate(account_id: int) -> None:
    """删除 / 标记已读 / 发件等"会让列表过时"的操作后调用，让下次刷新看到最新状态。"""
    with _email_list_cache_lock:
        dead = [k for k in _email_list_cache if k[1] == account_id]
        for k in dead:
            _email_list_cache.pop(k, None)


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

    错误透传：上游（Graph / Outlook REST / IMAP）失败时旧版只返回
    ``{emails: [], message: "API 错误: 429 ..."}``，前端拿到空数组渲染成
    "暂无数据"，让用户误以为是我们自家限流过严。现在改成上游软失败时把
    HTTP 状态码改成 502，让前端 catch 分支显示明确"加载失败"+ 上游错误，
    避免误导。

    短期缓存（``EMAIL_LIST_CACHE_TTL_SEC`` 秒，默认 5）：用户连点刷新或浏览器
    层节流被绕过时，把"高频刷新"压成"上游单次调用"，避免命中 Microsoft Graph
    *per-mailbox* 滚动窗口限速。改邮件 / 删邮件 / 发邮件后会主动失效缓存。
    """
    acc = get_account_or_404(user["id"], account_id)

    cache_key = (user["id"], account_id, folder, bool(with_body), int(limit))
    cached = _email_list_cache_get(cache_key)
    if cached is not None:
        emails_cached, msg_cached = cached
        return {
            "emails": [dict(e) for e in emails_cached],
            "message": msg_cached,
            "cached": True,
        }

    client = create_client(user["id"], acc)
    try:
        # with_body 直接透传到 GraphClient.fetch_emails，让 Graph 服务端就不返回 body
        # 比"先拉再丢"省了 ~MB 级的传输 + Graph 服务端处理
        emails, msg = client.fetch_emails(folder=folder, limit=limit, with_body=with_body)
    finally:
        client.disconnect()

    # 上游软失败判定：emails 为空 + msg 描述了真实错误（"API 错误"/"网络错误"
    # /"OAuth2 错误" 之类）。仅"获取成功"或"取得 0 条"两种成功语义放行；
    # 其余视为上游异常，返回 502 让前端走 email_load_fail 分支。
    # IMAP 路径下空收件箱时 msg 可能是 "获取成功"，命中放行白名单；用户首次打开
    # 真的没邮件也不会被误判成错误。
    if not emails and msg and not _is_email_list_ok(msg):
        retry_after = _maybe_extract_retry_after(msg)
        headers = {"Retry-After": str(retry_after)} if retry_after else None
        # 429 直接透传给前端（保留语义），其它（503 / OAuth / 网络）走 502
        # —— 502 是 Bad Gateway，准确表达"我们这边在帮你 proxy 上游、但上游
        # 没能给我们正确响应"的语义。
        upstream_status = (
            status.HTTP_429_TOO_MANY_REQUESTS
            if "429" in msg
            else status.HTTP_502_BAD_GATEWAY
        )
        # 防御纵深：底层 GraphClient 已经做了一层 _summarize_upstream_error，把
        # HTML / 长 body 净化成简短文案；这里再做一次 100 字符截断 + HTML
        # 标签字符兜底剥离，确保即便底层将来再回退到原始 ``resp.text``，前端
        # 也不会展示 ``<!DOCTYPE html>`` 这类原文。
        safe_msg = _safe_upstream_msg(msg)
        raise HTTPException(upstream_status, safe_msg, headers=headers)

    for e in emails:
        if e.get("date"):
            e["date"] = e["date"].isoformat()
        if not with_body:
            # IMAP 路径仍可能返回完整 body（无视参数），做一道清理保证带宽节省
            full_body = e.get("body") or ""
            if not e.get("preview"):
                e["preview"] = full_body[:200]
            e["body"] = ""

    # 仅缓存成功结果（emails 非空 或 msg 是合法的"获取成功 / Token 有效"）。
    # 失败路径在上面已经 raise，根本走不到这里；保险起见仍 if 一下。
    _email_list_cache_put(cache_key, [dict(e) for e in emails], msg or "")
    return {"emails": emails, "message": msg}


# fetch_emails 在"无邮件但请求成功"时也会返回 ([], "获取成功")，这两个串
# 是合法成功语义；其它非空 msg 都视为软失败。
_EMAIL_LIST_OK_MSGS = frozenset({"获取成功", "Token 有效"})


def _is_email_list_ok(msg: str) -> bool:
    return (msg or "").strip() in _EMAIL_LIST_OK_MSGS


def _maybe_extract_retry_after(msg: str) -> Optional[int]:
    """从上游错误 msg 里粗略提取 Retry-After 秒数。

    目前只识别 "429" 关键字 → 给一个保守默认 5s（让前端节流再叠加一次后端
    建议，避免用户连续撞墙）。Graph 层已经先尝试过 Retry-After 自动重试，
    所以这里能接到的 429 是连续重试后仍然失败的硬限流。
    """
    if not msg:
        return None
    if "429" in msg:
        return 5
    return None


# 简单的"上游错误净化"——把可能漏过来的 HTML 标签字符删除、长度截到 200。
# 与 GraphClient._summarize_upstream_error 是两层防御：底层负责把 HTML 转
# 短文案；这里负责"如果底层因为新逻辑/旧 IMAP/边界情况漏出来一段 ``<...>``，
# 也不让它出现在前端 detail 字段里"。
_HTML_TAG_RE = re.compile(r"<[^>]{0,200}>")


def _safe_upstream_msg(msg: str, max_len: int = 200) -> str:
    if not msg:
        return ""
    cleaned = _HTML_TAG_RE.sub(" ", msg)
    cleaned = cleaned.replace("<", " ").replace(">", " ")
    # 折叠空白
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:max_len]


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
    """单账号检测：连通性 + 是否含 AWS 验证邮件。

    与 ``_check_one_sync`` 同源——单次 ``fetch_emails(inbox, 30)`` 即可同时
    判定 token/IMAP 是否可用、并扫一遍 subject 关键字，避免历史"先 ``$top=1``
    再 ``$top=30``"两次往返。
    """
    acc = get_account_or_404(user["id"], account_id)
    client = create_client(user["id"], acc)
    try:
        status_str, has_aws, msg = client.quick_check_with_aws(limit=30)
        db.update_account_status(user["id"], account_id, status_str)
        if status_str == "正常":
            try:
                db.update_aws_code_status(user["id"], account_id, has_aws)
            except Exception:
                logger.exception("update_aws_code_status 异常 acc=%s", account_id)
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
    if ok:
        # 标记已读会改 emails 列表里的 is_read 字段——失效缓存让下次刷新拿到正确状态
        _email_list_cache_invalidate(account_id)
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
    if ok:
        _email_list_cache_invalidate(account_id)
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
    """检测单个账号（IO 同步）— 在线程池中运行。

    历史实现每个账号发 **2 次**上游请求（``check_status`` ``$top=1`` +
    ``check_aws_verification_emails`` ``$top=30``）。1000 个账号的批量检测
    瞬间就是 2000 次 Graph/IMAP 调用，对 OAuth 账号尤其容易把 ``token`` 端点
    或单邮箱配额撞穿。``EmailClient.quick_check_with_aws`` 把两次合并成一次
    ``fetch_emails(inbox, 30)``：连通性判定取自能否拿到列表、AWS 检测共用
    同一份 emails 数据，单账号请求量减半。
    """
    acc = db.get_account(owner_id, aid)
    if not acc:
        return {"email": "?", "status": "异常", "has_aws": False, "found": False}
    client = create_client(owner_id, acc)
    has_aws = False
    status_str = "异常"
    try:
        try:
            status_str, has_aws, _ = client.quick_check_with_aws(limit=30)
        except Exception:
            logger.exception("quick_check_with_aws 异常 acc=%s", aid)
        try:
            db.update_account_status(owner_id, aid, status_str)
        except Exception:
            logger.exception("update_account_status 异常 acc=%s", aid)
        if status_str == "正常":
            try:
                db.update_aws_code_status(owner_id, aid, has_aws)
            except Exception:
                logger.exception("update_aws_code_status 异常 acc=%s", aid)
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
def get_dashboard(
    request: Request, response: Response, user: dict = CurrentUser
) -> dict:
    """仪表盘概览：总数 / 分组分布 / 状态分布。

    旧实现走 ``get_all_accounts`` 全表加载 + Fernet 解密 + Python 侧
    dict 计数；本接口只用聚合数字，password / refresh_token 完全不需要。
    改走 ``get_dashboard_stats`` 的纯 SQL ``GROUP BY`` 后：
    - N=1000 账号：~50ms（含 Fernet）→ ~2ms（仅 SQL 聚合）
    - 减少 N 次 Fernet 解密的内存暴露面

    带 ETag 协商：dashboard 数据完全由 accounts 表派生，与 ``account_rev``
    强一致——加上 ETag 让 ``loadAccounts`` 之后的 fire-and-forget
    ``loadCounts`` 在数据未变时直接 304，省一次完整聚合查询。
    """
    rev = db.get_account_rev(user["id"])
    raw = f"dash|{rev}"
    etag = f'W/"{hashlib.blake2s(raw.encode("utf-8"), digest_size=8).hexdigest()}"'
    cache_control = "private, must-revalidate"
    if_none_match = request.headers.get("if-none-match", "")
    if if_none_match and etag in {tag.strip() for tag in if_none_match.split(",")}:
        return Response(
            status_code=status.HTTP_304_NOT_MODIFIED,
            headers={"ETag": etag, "Cache-Control": cache_control},
        )
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = cache_control
    return db.get_dashboard_stats(user["id"])


# ── Settings ────────────────────────────────────────────────────


@app.get("/api/settings")
def get_settings(user: dict = CurrentUser) -> dict:
    uid = user["id"]
    return {
        "theme": db.get_setting(uid, "theme", "light"),
        "language": db.get_setting(uid, "language", "zh"),
        "font_size": db.get_setting(uid, "font_size", "13"),
        CODE_RECEIVER_REQUIRE_TOKEN_KEY: db.get_setting(
            uid, CODE_RECEIVER_REQUIRE_TOKEN_KEY, "1",
        ),
    }


@app.put("/api/settings")
def update_settings(req: SettingUpdate, user: dict = CurrentUser) -> dict:
    if req.key not in ALLOWED_SETTING_KEYS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"非法的 setting: {req.key}")
    if req.key == CODE_RECEIVER_REQUIRE_TOKEN_KEY:
        _require_code_owner(user)
        if req.value not in {"0", "1"}:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "code_receiver_require_token 只能是 0 或 1",
            )
    db.set_setting(user["id"], req.key, req.value)
    return {"ok": True}


# ── Helper（邮箱助手 / xiaoxuan 专属） ──────────────────────────
#
# 历史上这里有一组「手动授权 OAuth2」接口（/api/oauth2/auth-url 与
# /api/oauth2/exchange），需要用户自己粘贴 Microsoft 重定向 URL。
# 该流程现在已彻底被「邮箱助手 Helper」替代 —— 用户在本地装一个 Helper
# .exe，由 Helper 自动打开浏览器、自动登录、自动获取 refresh_token 后
# 回传给服务器落库。
#
# 路由实现在 ``core/helper_routes.py``，本文件只负责挂载并注入数据库 +
# 站长用户名。注入而非 import 是为了避免 ``helper_routes`` 反向依赖
# ``web_app`` 形成循环。
configure_helper_routes(db, CODE_OWNER_USERNAME)
app.include_router(helper_router)


# ── 入口 ────────────────────────────────────────────────────────


def main() -> None:
    import uvicorn

    host = os.getenv("EMAIL_WEB_HOST", "127.0.0.1")
    port = int(os.getenv("EMAIL_WEB_PORT", "8000"))
    ssl_keyfile = os.getenv("EMAIL_WEB_SSL_KEY", "").strip() or None
    ssl_certfile = os.getenv("EMAIL_WEB_SSL_CERT", "").strip() or None
    scheme = "https" if ssl_keyfile and ssl_certfile else "http"

    # 多 worker 检测：HelperRegistry 是进程内单例（_sessions / _pending /
    # _log_subscribers 全部内存），多 worker 会让 helper register 落在
    # worker A，但 dispatch 调用可能命中 worker B 拿不到 session。
    # 邮箱助手功能在多 worker 下**不可用**；这里在启动时强警告而不是
    # silently 接受，避免运维误配。
    workers_env = os.getenv("EMAIL_WEB_WORKERS", "").strip()
    workers = int(workers_env) if workers_env.isdigit() else 1

    print("=" * 50)
    print(f"  邮箱管家 Web v3.1 (多用户 + 审计 + 邮箱助手)")
    print(f"  访问: {scheme}://{host}:{port}")
    print(f"  注册: {'已禁用' if DISABLE_REGISTER else '开放（首次访问可注册账号）'}")
    print(f"  反代: {'信任 X-Forwarded-* 头' if TRUST_PROXY else '不信任反代头（公网直连推荐）'}")
    if scheme == "https":
        print(f"  TLS:  启用 (cert={ssl_certfile})")
    elif host not in {"127.0.0.1", "localhost", "::1"}:
        print(f"  [WARN] HTTP 明文传输；公网/内网建议设置 EMAIL_WEB_SSL_KEY/CERT 或经由反代")
    if workers > 1:
        print("=" * 50, file=sys.stderr)
        print(
            f"  [WARN] EMAIL_WEB_WORKERS={workers} 多 worker 模式：",
            file=sys.stderr,
        )
        print(
            "         「📬 邮箱助手 Helper」功能**不可用**（HelperRegistry 是进程内单例）。",
            file=sys.stderr,
        )
        print(
            "         如需 helper，请设置 EMAIL_WEB_WORKERS=1 或不设置该环境变量。",
            file=sys.stderr,
        )
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

    # 注意：``uvicorn.run(app=<对象>, workers=N)`` workers 不会生效（uvicorn
    # 要求多 worker 时必须传 import path 字符串）。这里没传 workers，
    # 永远是单 worker；要多 worker 请通过 ``uvicorn web_app:app --workers N``
    # 命令行启动 —— **但那会破坏邮箱助手功能**（见 main() 开头警告）。
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
