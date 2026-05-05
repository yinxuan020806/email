# -*- coding: utf-8 -*-
"""受限 DB 访问层 — 给前台进程一道安全栅栏。

设计目标：
- **绝对禁止**写入 users / accounts (除 query_count) / sessions / settings / extractor_rules / audit_log
- 仅允许：
    * SELECT 公开账号（accounts.is_public=1 且属于配置中的接码站长用户名）
    * UPDATE accounts.query_count（自增 1，限定单条）
    * INSERT code_query_log
    * SELECT extractor_rules WHERE enabled=1
    * SELECT COUNT(*) code_query_log（限流读）

约束方法：把 DatabaseManager 包一层，仅暴露白名单方法；其余调用一律 AttributeError。
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import List, Optional

from core.models import Account
from database.db_manager import DatabaseManager


logger = logging.getLogger(__name__)

# 提取规则缓存 TTL（秒）。规则属低频更新，缓存 30 秒能显著降 DB 压力。
_RULES_CACHE_TTL = 30.0


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def hash_ip(ip: str) -> str:
    """对 IP 做 SHA-256 摘要后存 DB，避免泄露原文。"""
    return _sha256_hex((ip or "").strip().lower())


def hash_email(email: str) -> str:
    return _sha256_hex((email or "").strip().lower())


class CodeReceiverDB:
    """前台进程持有的受限 DB 访问对象。"""

    def __init__(self, owner_username: str, db: Optional[DatabaseManager] = None) -> None:
        self.owner_username = (owner_username or "").strip()
        if not self.owner_username:
            raise RuntimeError(
                "code-receiver 必须配置 CODE_OWNER_USERNAME（接码业务的站长用户名）"
            )
        self._db = db or DatabaseManager()
        # rules 缓存：{category: (expires_at_monotonic, rows_list)}
        self._rules_cache: dict[str, tuple[float, list[dict]]] = {}
        self._rules_lock = threading.Lock()

    # ── 读：公开账号查询 ─────────────────────────────────────────

    def lookup_public_account(self, email: str, category: str) -> Optional[Account]:
        """前台输入邮箱（无密码）时调用：取站长名下、公开、允许此分类的账号。"""
        if not email or not category:
            return None
        return self._db.get_public_account_for_lookup(
            self.owner_username, email, category
        )

    # ── 读：提取规则 ─────────────────────────────────────────────

    def list_rules(self, category: str) -> List[dict]:
        cat = (category or "").lower()
        now = time.monotonic()
        with self._rules_lock:
            cached = self._rules_cache.get(cat)
            if cached and cached[0] > now:
                return cached[1]
        rows = self._db.list_extractor_rules(category=cat, enabled_only=True)
        with self._rules_lock:
            self._rules_cache[cat] = (now + _RULES_CACHE_TTL, rows)
        return rows

    def invalidate_rules_cache(self) -> None:
        """管理端在 UI 上写完规则后可远程触发；目前未暴露 endpoint，仅供测试。"""
        with self._rules_lock:
            self._rules_cache.clear()

    # ── 健康检查 ────────────────────────────────────────────────

    def healthcheck(self) -> tuple[bool, str]:
        """绕过缓存，对 DB 做一次真实只读探测。返回 (ok, error_kind)。"""
        ok, err, names = self._db.health_ping()
        if not ok:
            return False, err
        missing = {"accounts", "code_query_log", "extractor_rules"} - names
        if missing:
            return False, f"missing_tables:{','.join(sorted(missing))}"
        return True, ""

    # ── 写：query_count 自增 + 查询日志 ──────────────────────────

    def incr_query_count(self, account_id: int) -> bool:
        return self._db.incr_account_query_count(account_id)

    def add_query_log(
        self,
        ip: str,
        email: str,
        category: str,
        success: bool,
        source: str,
        matched_rule_id: Optional[int] = None,
        error_kind: Optional[str] = None,
        latency_ms: Optional[int] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        domain = (email.split("@", 1)[-1] if email and "@" in email else "")[:64]
        self._db.add_code_query_log(
            ip_hash=hash_ip(ip),
            email_hash=hash_email(email),
            email_domain=domain,
            category=category,
            success=success,
            source=source,
            matched_rule_id=matched_rule_id,
            error_kind=error_kind,
            latency_ms=latency_ms,
            user_agent=user_agent,
        )

    # ── 读：限流计数 ─────────────────────────────────────────────

    def count_queries_in_window(
        self,
        window_seconds: int,
        ip: Optional[str] = None,
        email: Optional[str] = None,
    ) -> int:
        since = (datetime.now() - timedelta(seconds=window_seconds)).isoformat(
            sep=" ", timespec="seconds"
        )
        return self._db.count_code_queries_since(
            since_ts_iso=since,
            ip_hash=hash_ip(ip) if ip else None,
            email_hash=hash_email(email) if email else None,
        )
