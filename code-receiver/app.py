# -*- coding: utf-8 -*-
"""Code Receiver — FastAPI 主入口（端口默认 8001）。

设计要点：
- 与 ../email/ 共用 SQLite + .master.key；通过 sys.path 注入 ../email/ 后 import core/database
- 全程匿名访问，仅做 IP/邮箱限流 + 凭据失败锁定
- 凭据生命周期：仅在请求函数局部变量内存活，响应返回前主动清除
- 不在任何日志里打印密码 / refresh_token / 邮件原文（只记日志中的哈希与分类）

环境变量：
    CRX_HOST                  默认 127.0.0.1
    CRX_PORT                  默认 8001
    CRX_LOG_LEVEL             默认 INFO
    CODE_OWNER_USERNAME       (必填) 接码业务的站长用户名（仅这个用户的 is_public 邮箱可被前台查询）
    EMAIL_DATA_DIR            数据目录，与管理端共享；默认指向 ../data
    CRX_TRUST_PROXY           "1" 表示信任 X-Forwarded-For（反代后必须开）
    CRX_RATE_IP_PER_MIN       默认 30
    CRX_RATE_IP_PER_HOUR      默认 300
    CRX_RATE_EMAIL_PER_HOUR   默认 60
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator


HERE = os.path.dirname(os.path.abspath(__file__))
# 仓库布局：repo_root/code-receiver/app.py + repo_root/(core/database/web_app.py 等)
# code-receiver 是 email 项目的子目录，向上一级即可拿到管理端代码与共享 data 目录
EMAIL_PROJECT_DIR = os.path.normpath(os.path.join(HERE, ".."))

# 默认共享同一份 data/.master.key + emails.db
os.environ.setdefault("EMAIL_DATA_DIR", os.path.join(EMAIL_PROJECT_DIR, "data"))

# 把 ../email/ 加入 sys.path，让 core / database 可以 import
if EMAIL_PROJECT_DIR not in sys.path:
    sys.path.insert(0, EMAIL_PROJECT_DIR)
# 同级目录也加入（让 extractors 包能被 import）
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import requests  # noqa: E402

from core.email_client import EmailClient  # noqa: E402
from core.models import Account  # noqa: E402
from database.db_manager import QUERY_LOG_RETENTION_DAYS  # noqa: E402

from db_proxy import CodeReceiverDB  # noqa: E402
from extractors import get_extractors  # noqa: E402
from extractors.base import first_match  # noqa: E402
from input_parser import (  # noqa: E402
    InputParseError,
    ParsedCredential,
    parse_user_input,
)
from ip_limiter import RateLimiter  # noqa: E402


# ── 日志 ─────────────────────────────────────────────────────────

logging.basicConfig(
    level=os.getenv("CRX_LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("code_receiver")


# ── 应用 ────────────────────────────────────────────────────────

OWNER_USERNAME = os.getenv("CODE_OWNER_USERNAME", "xiaoxuan").strip()
TRUST_PROXY = os.getenv("CRX_TRUST_PROXY", "").strip() in {"1", "true", "yes"}

# ── Cloudflare Turnstile（可选）──────────────────────────────────
# 默认未配置时跳过校验（向后兼容）；启用后所有 /api/lookup 请求必须带
# 合法 token，配合 IP/邮箱限流形成"代理池也跑不动"的纵深防御。
# 申请 sitekey / secret：https://dash.cloudflare.com/?to=/:account/turnstile
TURNSTILE_SITEKEY = os.getenv("CRX_TURNSTILE_SITEKEY", "").strip()
TURNSTILE_SECRET = os.getenv("CRX_TURNSTILE_SECRET", "").strip()
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
TURNSTILE_ENABLED = bool(TURNSTILE_SITEKEY and TURNSTILE_SECRET)

# 注：byo（用户自带 IMAP/OAuth 凭据）路径已下线 — 前台只接受"邮箱地址"，
# 且必须由站长在管理后台显式加入接码白名单（accounts.is_public=1）才能查码。
# 因此 SSRF 防护（detect_server 域名白名单）不再需要：所有走到这里的邮箱
# 都来自管理端站长自行导入的账号，连接目标完全可控。

# master.key 必须由管理端先生成；前台启动时强制检查存在
def _ensure_master_key_exists() -> None:
    data_dir = os.environ.get("EMAIL_DATA_DIR") or os.path.join(EMAIL_PROJECT_DIR, "data")
    key_path = os.path.join(data_dir, ".master.key")
    if not os.path.exists(key_path):
        raise RuntimeError(
            f"未找到 master.key: {key_path}\n"
            f"前台进程不可独立生成主密钥，否则会与管理端解密不一致。\n"
            f"请先启动 ../email/ 管理端完成首次初始化，再启动 code-receiver。"
        )


_ensure_master_key_exists()


# ── 周期清理 code_query_log（防表无限增长）─────────────────────
# FastAPI 推荐用 lifespan 替代废弃的 on_event；启动后挂一个后台 task，
# 每天清一次超过 QUERY_LOG_RETENTION_DAYS 的旧日志。
_CLEANUP_INTERVAL_SEC = 24 * 3600


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    cleanup_task = asyncio.create_task(_cleanup_loop())
    try:
        yield
    finally:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except (asyncio.CancelledError, Exception):
            pass


async def _cleanup_loop() -> None:
    """后台周期任务：删除 retention 期外的查询日志，避免限流 COUNT 越查越慢。"""
    while True:
        try:
            await asyncio.sleep(_CLEANUP_INTERVAL_SEC)
        except asyncio.CancelledError:
            return
        try:
            # 阻塞 IO 放线程池，避免堵塞事件循环
            deleted = await asyncio.to_thread(
                _db.cleanup_old_query_log, QUERY_LOG_RETENTION_DAYS
            )
            if deleted:
                logger.info(
                    "code_query_log cleanup: deleted=%s retention_days=%s",
                    deleted, QUERY_LOG_RETENTION_DAYS,
                )
        except Exception:
            logger.exception("code_query_log cleanup 异常（已吞掉，下轮再试）")


app = FastAPI(
    title="Code Receiver", version="0.1.0",
    docs_url=None, redoc_url=None,
    lifespan=_lifespan,
)

# CORS：默认拒绝所有跨域。前台静态页与 /api 同源部署，跨域请求一律不需要。
# 显式声明可避免被嵌入 / 跨站脚本利用 fetch 读响应体。
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    allow_credentials=False,
    max_age=600,
)


@app.exception_handler(RequestValidationError)
async def _safe_validation_handler(request: Request, exc: RequestValidationError):
    """覆盖 FastAPI 默认 422 处理器：默认会把请求 body 原样塞进响应 detail，
    导致用户输入的凭据（password / refresh_token）随错误响应回显出去。
    这里只回包含字段名 + 错误原因的最小化 detail。
    """
    safe_errors = []
    for err in exc.errors():
        # err 形如 {'type': '...', 'loc': (...), 'msg': '...', 'input': '...原始值...'}
        # 我们只保留 loc + msg，input 字段是凭据来源，必须丢弃
        # msg 也截断到 200 字符，避免 pydantic 某些校验把原值嵌入错误消息泄漏
        msg_raw = str(err.get("msg") or "invalid")[:200]
        safe_errors.append({"loc": list(err.get("loc", [])), "msg": msg_raw})
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "请求参数校验失败", "errors": safe_errors},
    )


STATIC_DIR = os.path.join(HERE, "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ── 依赖：DB & 限流 ──────────────────────────────────────────────

_db = CodeReceiverDB(owner_username=OWNER_USERNAME)
_limiter = RateLimiter(
    _db,
    ip_per_min=int(os.getenv("CRX_RATE_IP_PER_MIN", "30")),
    ip_per_hour=int(os.getenv("CRX_RATE_IP_PER_HOUR", "300")),
    email_per_hour=int(os.getenv("CRX_RATE_EMAIL_PER_HOUR", "60")),
)


def _client_ip(request: Request) -> str:
    """从 HTTP 请求中解析客户端真实 IP。

    仅当 ``TRUST_PROXY=1`` 时才信任反代头，避免恶意客户端通过自带头伪造 IP 绕过限流。
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
    return request.client.host if request.client else "0.0.0.0"


# ── 安全响应头中间件 ────────────────────────────────────────────


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    # CSP 把 Cloudflare Turnstile 加白：未启用时也无副作用（只是策略层允许加载），
    # 启用时挑战脚本与挑战 iframe 必须能从 challenges.cloudflare.com 加载。
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' https://challenges.cloudflare.com; "
        "frame-src https://challenges.cloudflare.com; "
        "connect-src 'self' https://challenges.cloudflare.com; "
        "frame-ancestors 'none'",
    )
    response.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
    )
    return response


# ── 模型 ────────────────────────────────────────────────────────

# 与前端 chip（cursor / chatgpt）严格对齐：扩展到 anthropic / google 等需要
# 同时改前端，否则就是"前台做了空白名单也没人能触发"。保留小集合更安全。
ALLOWED_CATEGORIES = frozenset({"cursor", "openai"})


class LookupRequest(BaseModel):
    # 邮箱地址 RFC 5321 上限 254 字符，留 256 容错；本接口只接受邮箱地址，
    # 不再支持 ``email----password`` / OAuth2 等扩展格式（byo 路径已下线）。
    input: str = Field(min_length=3, max_length=256)
    category: str = Field(min_length=1, max_length=32)
    # Cloudflare Turnstile 人机校验 token；仅在 TURNSTILE_ENABLED=True 时强制要求。
    # 长度上限放宽到 4096 — 实测 cf-turnstile-response 大致 200~600 字符，预留余量。
    cf_token: Optional[str] = Field(default=None, max_length=4096)

    @field_validator("input")
    @classmethod
    def _email_only(cls, v: str) -> str:
        """前台只接受裸邮箱：含 ``----`` 一律 422 拒绝（在 pydantic 阶段就拦下）。

        这是第一道防线；``lookup`` 路由里 ``parse_user_input`` 之后还会再做
        一次 ``cred.needs_lookup`` 守卫，保证即使前端绕过 / 解析逻辑变化，
        byo 路径也永远到不了 IMAP 调用层。
        """
        s = (v or "").strip()
        if not s:
            raise ValueError("输入不能为空")
        if "----" in s:
            raise ValueError("仅支持邮箱地址，不支持密码 / OAuth 等扩展格式")
        return s

    @field_validator("category")
    @classmethod
    def _valid_category(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in ALLOWED_CATEGORIES:
            raise ValueError(f"category must be one of {sorted(ALLOWED_CATEGORIES)}")
        return v


# ── 工具：根据凭据装配 EmailClient ─────────────────────────────


def _build_client(account_imap: Account) -> EmailClient:
    """从公开账号构造一个 EmailClient。

    byo（用户自带凭据）路径已下线，所有走到这里的连接信息都来自管理端
    站长加入接码白名单的 ``accounts.is_public=1`` 行，凭据来源完全可控。
    """
    return EmailClient(
        email_addr=account_imap.email,
        password=account_imap.password or "",
        imap_server=account_imap.imap_server,
        imap_port=account_imap.imap_port or 993,
        client_id=account_imap.client_id,
        refresh_token=account_imap.refresh_token,
    )


# 用于把"认证失败"和"服务/网络异常"区分开 — 仅前者才计入限流的失败锁定。
# 这些子串覆盖 IMAP / SMTP / Microsoft Graph / OAuth 常见 auth 失败信号。
_AUTH_ERROR_NEEDLES = (
    "logondenied",
    "auth failed",
    "authenticate failed",
    "authentication failed",
    "authentication unsuccessful",
    "authenticationfailed",   # IMAP 标准错误码 [AUTHENTICATIONFAILED] 紧凑形式
    "invalid credentials",
    "login failed",
    "incorrect username",
    "incorrect password",
    "wrong password",
    "bad credentials",        # GitHub / 部分 IMAP 服务器
    "invalid_grant",
    "invalid_client",
    "invalid_request",        # MS 部分 OAuth 错误
    "unauthorized_client",
    "401 unauthorized",       # 精确匹配避免子串误抓 "1401 errors" 之类
    "http 401",
    "(401)",
    "403 forbidden",
    "user not found",         # 部分 IMAP 服务器
    "mailbox not enabled",    # MS 邮箱未开启 IMAP
    "imap is disabled",
    # ── Azure AD STS 错误码（refresh_token 失效 / 撤销 / 用户不存在）──
    "aadsts50034",            # 用户不存在
    "aadsts50173",            # token 已撤销
    "aadsts70008",            # refresh_token 已过期
    "aadsts700003",           # device 已撤销
    "aadsts700082",           # refresh_token 因不活动撤销
)


def _is_auth_failure(text: str) -> bool:
    if not text:
        return False
    low = text.lower()
    return any(needle in low for needle in _AUTH_ERROR_NEEDLES)


# ── IMAP 收件箱结果短期缓存 ────────────────────────────────────
# 同一邮箱在数十秒内反复查询时，与其每次都重新建立 IMAP / Graph 连接 +
# 拉 20 封邮件（每次 1-3 秒），不如把上一次的 (mails, msg) 缓存 30 秒。
# - 命中：单次响应从 ~2s 降到 ~50ms，明显改善"等不及反复点查询"体验
# - 失效：30s 后过期，必拉新；若用户拿到验证码后还想继续刷新，等 30s
# - 隔离：以 (email_lower, owner_id, account_id) 为 key，不会跨账号串
# - 容量限制：最多 200 个 key，超过自动驱逐最老的（小服务足矣）
import threading  # noqa: E402

_INBOX_CACHE_TTL_SEC = 30.0
_INBOX_CACHE_MAX = 200
_inbox_cache: dict[str, tuple[float, list[dict], str]] = {}
_inbox_cache_lock = threading.Lock()


def _inbox_cache_key(account_email: str, account_id: int) -> str:
    return f"{(account_email or '').strip().lower()}:{account_id}"


def _inbox_cache_get(key: str) -> Optional[tuple[list[dict], str]]:
    now = time.monotonic()
    with _inbox_cache_lock:
        entry = _inbox_cache.get(key)
        if not entry:
            return None
        expires_at, mails, msg = entry
        if expires_at <= now:
            _inbox_cache.pop(key, None)
            return None
    return mails, msg


def _inbox_cache_set(key: str, mails: list[dict], msg: str) -> None:
    expires_at = time.monotonic() + _INBOX_CACHE_TTL_SEC
    with _inbox_cache_lock:
        if len(_inbox_cache) >= _INBOX_CACHE_MAX:
            # 简单 FIFO 驱逐（按 key 字典插入序），避免无界增长
            try:
                oldest_key = next(iter(_inbox_cache))
                _inbox_cache.pop(oldest_key, None)
            except StopIteration:
                pass
        _inbox_cache[key] = (expires_at, mails, msg)


def _sort_mails_newest_first(mails: list[dict]) -> list[dict]:
    """按 ``date`` 字段降序排序；缺失或无法解析时排到最后，保持原相对顺序。

    EmailClient.fetch_emails 不同后端返回顺序未定，必须显式排序，
    否则 first_match 可能取到老验证码。

    支持的 date 类型：
    - ``datetime`` 对象（GraphClient / IMAPClient 已解析过的）
    - ISO 8601 字符串（"2024-01-01T00:00:00Z" / "+00:00"）
    - RFC 2822 字符串（"Mon, 01 Jan 2024 00:00:00 +0000" — 部分 IMAP 后端透传时常见）
    """
    from datetime import datetime as _dt
    from email.utils import parsedate_to_datetime as _rfc2822

    def _key(mail: dict):
        d = mail.get("date")
        if d is None or d == "":
            return (1, 0.0)
        try:
            if isinstance(d, _dt):
                return (0, -d.timestamp())
            s = str(d)
            try:
                return (0, -_dt.fromisoformat(s.replace("Z", "+00:00")).timestamp())
            except (ValueError, TypeError):
                # ISO 解析失败时再试 RFC 2822（IMAP 后端常见格式）
                try:
                    parsed = _rfc2822(s)
                    if parsed is not None:
                        return (0, -parsed.timestamp())
                except (ValueError, TypeError, IndexError):
                    pass
                return (1, 0.0)
        except (OverflowError, OSError, AttributeError):
            return (1, 0.0)

    return sorted(mails, key=_key)


# ── 路由 ────────────────────────────────────────────────────────


@app.get("/")
def root():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse({"name": "code-receiver", "ok": True})


@app.get("/healthz")
def healthz():
    """健康检查：绕过缓存做真实 DB 探测 + extractor 注册表非空。

    返回 503 时，docker / k8s / 反代会感知到不健康从而触发重启或摘流量。

    注意：响应里**绝不**返回 ``CODE_OWNER_USERNAME``——即便是只读探针，
    /healthz 是公网未鉴权端点，泄露站长用户名会让攻击者拥有针对管理端
    ``/login`` 的精确字典爆破目标。
    """
    db_ok, db_err = _db.healthcheck()
    rules_ok = bool(get_extractors("cursor")) and bool(get_extractors("openai"))
    if not db_ok or not rules_ok:
        if db_err:
            logger.warning("healthz: DB 探测失败 err=%s", db_err)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"ok": False, "db": db_ok, "rules": rules_ok},
        )
    return {"ok": True, "db": True, "rules": True}


# 429 响应统一文案：不暴露具体限流维度（IP/min vs IP/hour vs email）和阈值，
# 避免攻击者反推内部策略；reason 仅记入日志侧。
_RATE_LIMITED_PUBLIC_MSG = "请求过于频繁，请稍后重试"


def _verify_turnstile(token: Optional[str], remote_ip: str) -> tuple[bool, str]:
    """Cloudflare Turnstile 校验。未启用时直接放行。

    返回 (ok, error_kind)。ok=False 时附带可写入 query_log 的 error_kind。
    超时 / 上游异常时**保守拒绝**，避免攻击者通过让 Cloudflare 不可达来绕过校验。
    """
    if not TURNSTILE_ENABLED:
        return True, ""
    if not token:
        return False, "turnstile_missing"
    try:
        resp = requests.post(
            TURNSTILE_VERIFY_URL,
            data={
                "secret": TURNSTILE_SECRET,
                "response": token,
                "remoteip": remote_ip or "",
            },
            timeout=8,
            # 显式禁用重定向：Cloudflare siteverify 不会重定向；禁用是为了
            # 防上游被攻破或 DNS 投毒时把 secret 随重定向请求转发到第三方主机。
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        logger.warning("turnstile siteverify 异常 — 拒绝放行：%s", exc)
        return False, "turnstile_upstream"
    if resp.status_code != 200:
        logger.warning("turnstile siteverify 非 200：%s", resp.status_code)
        return False, "turnstile_upstream"
    try:
        body = resp.json()
    except ValueError:
        logger.warning("turnstile siteverify 响应非 JSON")
        return False, "turnstile_upstream"
    if body.get("success") is True:
        return True, ""
    codes = ",".join(str(c) for c in body.get("error-codes", [])[:3])
    logger.info("turnstile 校验失败 codes=%s", codes)
    return False, "turnstile_failed"


_APP_VERSION = (os.getenv("APP_VERSION", "") or "dev").strip()[:32]


@app.get("/api/config")
def public_config() -> dict:
    """供前端拉取启动期配置：Turnstile sitekey、版本号等公开字段。

    **绝不**返回 secret、owner、限流阈值等可被反推内部策略的字段。
    """
    return {
        "turnstile": {
            "enabled": TURNSTILE_ENABLED,
            "sitekey": TURNSTILE_SITEKEY if TURNSTILE_ENABLED else "",
        },
        "version": _APP_VERSION,
    }


@app.post("/api/lookup")
def lookup(req: LookupRequest, request: Request) -> JSONResponse:
    """核心：解析输入 → 查白名单公开账号 → 拉邮件 → 提码 → 返回。

    流程（全程**只走白名单路径**，byo 已下线）：
    1. ``parse_user_input`` 解析 — 必须 ``needs_lookup=True``（即纯邮箱）
    2. ``_limiter.begin`` 一次完成 IP + email 双维度判定 + in-flight 登记
    3. ``lookup_public_account`` 找站长名下、``is_public=1`` 且分类匹配的账号
    4. IMAP/Graph 拉收件箱前 20 封
    5. 按时间倒序排序后由分类 extractors 取首个 code/link
    6. ``finally`` 同时执行：落库 + 释放 in-flight + wipe 凭据
    """
    started = time.time()
    ip = _client_ip(request)
    ua = (request.headers.get("user-agent", "") or "")[:200]
    cred: Optional[ParsedCredential] = None
    account: Optional[Account] = None
    matched_rule_id: Optional[int] = None
    error_kind: Optional[str] = None
    success = False
    source = "public"
    email_for_log = ""
    inflight_started = False  # 限流 in-flight 是否已登记，决定 finally 是否 end

    try:
        # 1) 解析输入（解析失败仍按 IP 维度计入限流，避免畸形请求蹭算力）。
        try:
            cred = parse_user_input(req.input)
        except InputParseError as exc:
            error_kind = "parse"
            # 解析失败时也启动 in-flight，让连续畸形请求被 IP/min 拦下
            pre_decision = _limiter.begin(ip=ip, email="")
            if pre_decision.allowed:
                inflight_started = True
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"输入格式错误: {exc}")
        email_for_log = cred.email

        # 1.5) 防御纵深：byo 路径已下线，凡是带密码 / OAuth 凭据的输入一律拒绝。
        # ``LookupRequest`` 的 pydantic field_validator 已在 422 阶段拦下含
        # ``----`` 的输入；这里再做一次后端语义守卫，保证即使解析逻辑被未来
        # 修改 / 上游校验绕过，byo 也永远到不了 IMAP 层。
        if not cred.needs_lookup:
            error_kind = "byo_disabled"
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "仅支持邮箱地址，请确认输入"
            )

        # 1.7) Turnstile 人机校验（可选）：放在限流之前，校验失败也走 finally
        # 落库，配合 IP 限流让单 IP 失败成本翻倍。未启用时立即返回 True 不耗时。
        ok_turnstile, turnstile_err = _verify_turnstile(req.cf_token, ip)
        if not ok_turnstile:
            error_kind = turnstile_err
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "人机校验失败，请刷新页面后重试"
            )

        # 2) 限流（IP + email 双维度，begin 通过即占用 in-flight 配额）
        # 关键：DB 落库在 finally，期间靠 in-flight 内存计数补足，否则 N 个并发
        # 请求会读到同样的旧 DB count 并全部通过——经典 race 漏洞。
        decision = _limiter.begin(ip=ip, email=cred.email)
        if not decision.allowed:
            error_kind = "rate_limited"
            logger.info(
                "rate_limited reason=%s retry_after=%s cat=%s",
                decision.reason, decision.retry_after, req.category,
            )
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": _RATE_LIMITED_PUBLIC_MSG,
                    "retry_after": int(decision.retry_after or 1),
                },
                headers={"Retry-After": str(max(1, int(decision.retry_after or 1)))},
            )
        inflight_started = True

        # 3) 查接码白名单 — 必须存在 & is_public=1 & 分类匹配
        account = _db.lookup_public_account(cred.email, req.category)
        if not account:
            # 站长侧日志：把"为什么没命中"细化打到 logger，方便 docker logs 排错。
            # 用户响应里仍然只暴露统一的 not_authorized，避免攻击者盲注探测白名单。
            try:
                diag = _db.diagnose_lookup_failure(cred.email, req.category)
                # email_domain 不会泄露具体邮箱；reason 是站长配置维度
                domain = cred.email.split("@", 1)[-1] if "@" in cred.email else ""
                logger.info(
                    "lookup not_authorized: cat=%s domain=%s reason=%s allowed=%s",
                    req.category, domain[:48],
                    diag.get("reason"), str(diag.get("allowed_categories"))[:64],
                )
                # 用细化的 error_kind 落库，便于站长在管理端用 SQL 统计排错
                reason = (diag.get("reason") or "unknown").strip()
                if reason in {"no_owner_user", "no_account", "not_public", "category_mismatch"}:
                    error_kind = f"not_authorized_{reason}"
                else:
                    error_kind = "not_authorized"
            except Exception:
                logger.exception("not_authorized 诊断失败（已吞掉）")
                error_kind = "not_authorized"
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "该邮箱未加入接码白名单或不属于此分类",
            )

        # 4) 拉邮件（IMAP 已强制 socket timeout，避免恶意服务器吊死 worker）
        # 4a) 优先查 30s 进程内缓存：用户连续刷新同一邮箱时不必每次都重连 IMAP
        cache_key = _inbox_cache_key(account.email, account.id or 0)
        cached = _inbox_cache_get(cache_key)
        if cached is not None:
            mails, msg = cached
            logger.info(
                "inbox cache HIT cat=%s acc=%d (saved one IMAP/Graph round-trip)",
                req.category, account.id or 0,
            )
        else:
            client = _build_client(account)
            try:
                mails, msg = client.fetch_emails(folder="inbox", limit=20, with_body=True)
                # 拉取成功才写缓存；异常时直接 raise，不污染缓存
                _inbox_cache_set(cache_key, mails, msg)
            except Exception as exc:
                err_text = f"{type(exc).__name__}: {exc}"
                is_auth = _is_auth_failure(err_text)
                logger.warning(
                    "拉取邮件失败 cat=%s auth_fail=%s err_kind=%s",
                    req.category, is_auth, type(exc).__name__,
                )
                error_kind = "auth_failed" if is_auth else "fetch_exception"
                if is_auth:
                    raise HTTPException(
                        status.HTTP_401_UNAUTHORIZED, "邮箱凭据无效或已过期"
                    )
                raise HTTPException(
                    status.HTTP_502_BAD_GATEWAY, "邮件服务器暂时不可用，请稍后重试"
                )
            finally:
                client.disconnect()
                # wipe EmailClient 内部的密码 / refresh_token 副本（IMAPClient 也持有一份）。
                # 与 finally 块里 wipe account.password 配合，让明文凭据在响应返回前被清。
                try:
                    client.password = ""
                    client.refresh_token = None
                    if getattr(client, "_imap", None) is not None:
                        client._imap.password = ""
                except (AttributeError, TypeError):
                    pass

        if not mails:
            error_kind = "no_mails"
            return JSONResponse(
                status_code=200,
                content={"found": False, "reason": "暂无邮件", "raw_message": msg},
            )

        # 4.5) 关键：按 date 降序，确保 first_match 拿到的是最新邮件
        mails = _sort_mails_newest_first(mails)

        # 5) 提取
        def _rules_loader(c: str):
            return _db.list_rules(c)

        extractors = get_extractors(req.category, db_rules_loader=_rules_loader)
        if not extractors:
            error_kind = "no_extractor"
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR, "未找到该分类的提取规则"
            )

        result = first_match(extractors, mails)
        if not result:
            error_kind = "no_match"
            return JSONResponse(
                status_code=200,
                content={"found": False, "reason": "未匹配到该分类的邮件"},
            )

        matched_rule_id = result.matched_rule_id
        success = True

        # 6) 命中公开账号 → 自增 query_count（用于站长统计 & 反滥用基线）
        try:
            _db.incr_query_count(account.id)
        except Exception:
            logger.exception("query_count 自增失败 acc_id=%s", account.id)

        return JSONResponse(
            content={
                "found": True,
                "category": req.category,
                "source": source,
                "code": result.code,
                "link": result.link,
                "sender": result.sender,
                "subject": result.subject,
                "received_at": result.received_at,
                "preview": result.body_preview,
            }
        )

    except HTTPException:
        raise
    except Exception:
        logger.exception("lookup 未预期异常 cat=%s", req.category)
        error_kind = error_kind or "unexpected"
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "服务异常")
    finally:
        latency = int((time.time() - started) * 1000)
        try:
            _db.add_query_log(
                ip=ip,
                email=email_for_log,
                category=req.category,
                success=success,
                source=source,
                matched_rule_id=matched_rule_id,
                error_kind=error_kind,
                latency_ms=latency,
                user_agent=ua,
            )
        except Exception:
            logger.exception("写 code_query_log 失败")
        # 释放 in-flight 计数（与 begin 配对）。注意：日志先落库、再 end，
        # 这样后续请求的限流判定一定能数到这一笔（DB 计数 + 0 inflight）。
        if inflight_started:
            try:
                _limiter.end(ip=ip, email=email_for_log)
            except Exception:
                logger.exception("limiter.end 异常（已吞掉）")
        # 主动 wipe 公开账号的解密敏感字段。即便此函数返回后 account 对象
        # 进入 GC，密码 / refresh_token 仍会在内存里活到下次 GC；显式置空
        # 缩短暴露窗口（纵深防御，主密钥同机失守时减少攻击面）。
        if account is not None:
            try:
                account.password = ""
                account.refresh_token = None
            except (AttributeError, TypeError):
                pass
        # cred 是 ParsedCredential — byo 已下线，password / refresh_token 字段
        # 永远是空（needs_lookup=True 时这些字段都不会被填充），不需要再 _wipe。


# ── 启动 ────────────────────────────────────────────────────────


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("CRX_HOST", "127.0.0.1")
    port = int(os.getenv("CRX_PORT", "8001"))
    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        reload=False,
        access_log=False,
    )
