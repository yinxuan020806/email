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
    CRX_RATE_IP_PER_MIN       默认 5
    CRX_RATE_IP_PER_HOUR      默认 30
    CRX_RATE_EMAIL_PER_HOUR   默认 10
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
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

from core.email_client import EmailClient  # noqa: E402
from core.models import Account  # noqa: E402
from core.server_config import detect_server  # noqa: E402

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

# 是否允许 byo（用户自带凭据）路径连接到未在 server_config 白名单的邮箱域名。
# 默认 False — 只允许 outlook/gmail/qq/163/126/sina/yahoo 等已知服务商，
# 防止攻击者把前台当作 IMAP SSRF 跳板去连接内网 / 任意主机。
ALLOW_UNKNOWN_DOMAINS = os.getenv("CRX_ALLOW_UNKNOWN_DOMAINS", "").strip() in {"1", "true", "yes"}

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

app = FastAPI(title="Code Receiver", version="0.1.0", docs_url=None, redoc_url=None)


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
    ip_per_min=int(os.getenv("CRX_RATE_IP_PER_MIN", "5")),
    ip_per_hour=int(os.getenv("CRX_RATE_IP_PER_HOUR", "30")),
    email_per_hour=int(os.getenv("CRX_RATE_EMAIL_PER_HOUR", "10")),
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
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
    )
    response.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
    )
    return response


# ── 模型 ────────────────────────────────────────────────────────

ALLOWED_CATEGORIES = {"cursor", "openai"}


class LookupRequest(BaseModel):
    # 4000 字节足够覆盖 email + password + client_id + refresh_token (单个 MS RT 长度
    # 1500-2000 字节，加分隔符和 UUID 后整个串可达 2300+，2000 限制会切断)
    input: str = Field(min_length=3, max_length=4000)
    category: str = Field(min_length=1, max_length=32)

    @field_validator("category")
    @classmethod
    def _valid_category(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in ALLOWED_CATEGORIES:
            raise ValueError(f"category must be one of {sorted(ALLOWED_CATEGORIES)}")
        return v


# ── 工具：根据凭据装配 EmailClient ─────────────────────────────


def _build_client(cred: ParsedCredential, account_imap: Optional[Account] = None) -> EmailClient:
    """从 ParsedCredential（或公开账号）构造一个 EmailClient。"""
    if account_imap is not None:
        return EmailClient(
            email_addr=account_imap.email,
            password=account_imap.password or "",
            imap_server=account_imap.imap_server,
            imap_port=account_imap.imap_port or 993,
            client_id=account_imap.client_id,
            refresh_token=account_imap.refresh_token,
        )
    return EmailClient(
        email_addr=cred.email,
        password=cred.password or "",
        client_id=cred.client_id,
        refresh_token=cred.refresh_token,
    )


def _wipe(cred: ParsedCredential) -> None:
    """请求结束时尽力擦除凭据字符串引用（CPython 不保证立即 GC，仅尽力而为）。"""
    cred.password = ""
    cred.refresh_token = None
    cred.client_id = None


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
    """
    db_ok, db_err = _db.healthcheck()
    rules_ok = bool(get_extractors("cursor")) and bool(get_extractors("openai"))
    if not db_ok or not rules_ok:
        if db_err:
            logger.warning("healthz: DB 探测失败 err=%s", db_err)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"ok": False, "db": db_ok, "db_err": db_err, "rules": rules_ok},
        )
    return {"ok": True, "owner": OWNER_USERNAME, "db": True, "rules": True}


@app.post("/api/lookup")
def lookup(req: LookupRequest, request: Request) -> JSONResponse:
    """核心：解析输入 → 查 DB / 直接 IMAP → 提码 → 返回。"""
    started = time.time()
    ip = _client_ip(request)
    ua = (request.headers.get("user-agent", "") or "")[:200]
    cred: Optional[ParsedCredential] = None
    matched_rule_id: Optional[int] = None
    error_kind: Optional[str] = None
    success = False
    source = "public"
    email_for_log = ""

    try:
        # 0) 预检：仅 IP 维度（防止用畸形输入绕过限流计数 / 蹭算力）。
        # finally 块会写 query_log，所以连续畸形请求超过 IP/min 阈值后会被拒；
        # 若不预检，第一次解析失败前 limiter 还未执行，攻击者每次都能消耗 IO。
        pre_decision = _limiter.check(ip=ip, email="")
        if not pre_decision.allowed:
            error_kind = "rate_limited"
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"error": pre_decision.reason, "retry_after": pre_decision.retry_after},
                headers={"Retry-After": str(max(1, pre_decision.retry_after))},
            )

        # 1) 解析输入
        try:
            cred = parse_user_input(req.input)
        except InputParseError as exc:
            error_kind = "parse"
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"输入格式错误: {exc}")
        email_for_log = cred.email
        source = "public" if cred.needs_lookup else "byo"

        # 2) 限流（带 email 维度的二次检查 — 防止"同邮箱被密集打码"）
        decision = _limiter.check(ip=ip, email=cred.email)
        if not decision.allowed:
            error_kind = "rate_limited"
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"error": decision.reason, "retry_after": decision.retry_after},
                headers={"Retry-After": str(max(1, decision.retry_after))},
            )

        # 3) 拿到一个可用的凭据 / Account
        account: Optional[Account] = None
        if cred.needs_lookup:
            account = _db.lookup_public_account(cred.email, req.category)
            if not account:
                error_kind = "not_authorized"
                raise HTTPException(
                    status.HTTP_404_NOT_FOUND,
                    "该邮箱未公开 / 不存在 / 未授权此分类",
                )
        else:
            # byo：用户自带凭据
            if not cred.password and not (cred.client_id and cred.refresh_token):
                error_kind = "missing_secret"
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "缺少邮箱密码 / OAuth 凭据")
            # SSRF 防护：限制 byo 路径只能连已知邮箱服务商，避免被诱导连接内网
            if not ALLOW_UNKNOWN_DOMAINS and detect_server(cred.email) is None:
                error_kind = "domain_not_allowed"
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "暂不支持该邮箱服务商；如需自定义 IMAP，请联系管理员配置公开账号",
                )

        # 4) 拉邮件
        client = _build_client(cred, account_imap=account)
        try:
            mails, msg = client.fetch_emails(folder="inbox", limit=20, with_body=True)
        except Exception as exc:
            err_text = f"{type(exc).__name__}: {exc}"
            is_auth = _is_auth_failure(err_text)
            logger.warning(
                "拉取邮件失败 cat=%s auth_fail=%s err_kind=%s",
                req.category, is_auth, type(exc).__name__,
            )
            error_kind = "auth_failed" if is_auth else "fetch_exception"
            # 仅认证失败计入限流，避免因服务/网络抖动误锁用户
            if is_auth:
                _limiter.record_failure(ip)
                raise HTTPException(
                    status.HTTP_401_UNAUTHORIZED, "邮箱凭据无效或已过期"
                )
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY, "邮件服务器暂时不可用，请稍后重试"
            )
        finally:
            client.disconnect()

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
        _limiter.record_success(ip)

        # 6) 命中公开账号则自增 query_count
        if account is not None:
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
        if cred is not None:
            _wipe(cred)


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
