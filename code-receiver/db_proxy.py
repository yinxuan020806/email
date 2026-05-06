# -*- coding: utf-8 -*-
"""受限 DB 访问层 — 给前台进程一道安全栅栏。

设计目标：
- **绝对禁止**写入 users / accounts (除 query_count) / sessions / settings / extractor_rules / audit_log
- 仅允许：
    * SELECT 公开账号（accounts.is_public=1 且属于配置中的接码站长用户名）
    * UPDATE accounts.query_count（自增 1，限定单条）
    * INSERT code_query_log
    * SELECT extractor_rules WHERE enabled=1
    * SELECT COUNT(*) code_query_log（限流读 / 失败计数读）
    * DELETE code_query_log（仅按"超出保留期"清理，不能定向删除）

约束方法：把 DatabaseManager 包一层，仅暴露白名单方法；其余调用一律 AttributeError。
"""

from __future__ import annotations

import hmac
import logging
import os
import secrets
import stat
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from core.models import Account
from database.db_manager import DatabaseManager, get_data_dir


logger = logging.getLogger(__name__)

# 提取规则缓存 TTL（秒）。规则属低频更新，缓存 30 秒能显著降 DB 压力。
_RULES_CACHE_TTL = 30.0

# Pepper：HMAC 的服务端密钥，与 master.key 同目录（``data/.code_log_pepper``）。
# 不存在时启动自动生成。引入 pepper 是为了让 ``code_query_log`` 里的 ip_hash /
# email_hash 即使整库泄露也无法在外部"反推 IP 字典"——攻击者必须同时拿到 pepper
# 才能枚举 IPv4 (2^32) / 邮箱字典并匹配哈希。
_PEPPER_FILENAME = ".code_log_pepper"
_pepper_lock = threading.Lock()
_pepper_cache: Optional[bytes] = None


def _load_pepper() -> bytes:
    """读取或生成 pepper；不存在时自动写一份新的 32 字节随机值。

    设计取舍：
    - pepper 一旦丢失会让"基于 hash 的限流统计"失去匹配能力（旧日志全部失效），
      但**不会破坏**业务可用性（限流计数在重启后从零开始累加，最坏退化）。
    - 与 ``.master.key`` 不同：master.key 丢失会让 accounts 加密字段无法解密
      → 毁灭性；pepper 丢失只是限流"失忆一段时间"，可接受。
    """
    global _pepper_cache
    if _pepper_cache is not None:
        return _pepper_cache
    with _pepper_lock:
        if _pepper_cache is not None:
            return _pepper_cache
        path = Path(get_data_dir()) / _PEPPER_FILENAME
        if path.exists():
            data = path.read_bytes().strip()
            if len(data) >= 16:
                _pepper_cache = data
                return data
            logger.warning(
                "%s 长度异常（<16B），将重新生成。旧限流计数将失效。", path,
            )
        data = secrets.token_bytes(32)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        logger.info("已生成 code-receiver pepper: %s", path)
        _pepper_cache = data
        return data


def _hmac_hex(value: str) -> str:
    msg = (value or "").strip().lower().encode("utf-8", errors="ignore")
    return hmac.new(_load_pepper(), msg, "sha256").hexdigest()


def hash_ip(ip: str) -> str:
    """对 IP 做 HMAC-SHA256(pepper) 后存 DB，避免泄露原文且抵御字典反推。"""
    return _hmac_hex(ip)


def hash_email(email: str) -> str:
    return _hmac_hex(email)


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

    def diagnose_lookup_failure(self, email: str, category: str) -> dict:
        """``lookup_public_account`` 返回 None 时调用，告诉站长**到底是哪一步**没满足。

        仅用于服务器侧日志诊断 — 不会把结果回包给前台访问者，避免：
        - 泄露"该邮箱是否属于站长"（盲注探测站长名下的邮箱）
        - 泄露"邮箱是否处于 is_public=1 状态"（探测白名单组成）

        返回 dict 形式 { reason: str, allowed_categories: str|None }
        - ``no_owner_user``：站长用户名 ``owner_username`` 不存在（部署/配置问题）
        - ``no_account``：站长名下没有这个邮箱（用户拼写错 / 还没导入）
        - ``not_public``：邮箱在站长名下但 ``is_public=0``（管理端忘了点"加入接码"）
        - ``category_mismatch``：is_public=1 但 ``allowed_categories`` / ``group_name``
          都不允许此分类（账号在 GitHub 分组里却查 cursor 之类）
        - ``unknown``：诊断异常或并发改动
        """
        if not email or not category:
            return {"reason": "no_account", "allowed_categories": None}
        try:
            with self._db._connect() as conn:  # noqa: SLF001
                cur = conn.execute(
                    "SELECT id FROM users WHERE username = ?",
                    (self.owner_username,),
                )
                user_row = cur.fetchone()
                if not user_row:
                    return {"reason": "no_owner_user", "allowed_categories": None}
                owner_id = int(user_row[0])
                cur = conn.execute(
                    "SELECT is_public, COALESCE(allowed_categories, ''), "
                    "       COALESCE(group_name, '') "
                    "FROM accounts "
                    "WHERE owner_id = ? AND LOWER(email) = LOWER(?) LIMIT 1",
                    (owner_id, email.strip()),
                )
                row = cur.fetchone()
            if not row:
                return {"reason": "no_account", "allowed_categories": None}
            is_public, allowed_cats, group_name = row
            if not is_public:
                return {
                    "reason": "not_public",
                    "allowed_categories": allowed_cats or None,
                }
            return {
                "reason": "category_mismatch",
                "allowed_categories": allowed_cats or f"(empty,group={group_name!r})",
            }
        except Exception:
            logger.exception("diagnose_lookup_failure 异常")
            return {"reason": "unknown", "allowed_categories": None}

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
        exclude_error_kinds: Optional[list[str]] = None,
    ) -> int:
        """限流计数：可选排除"前置失败"类 error_kind，避免用户输错邮箱
        / 触发人机校验等情况把自己 IP 配额耗尽。"""
        since = (datetime.now() - timedelta(seconds=window_seconds)).isoformat(
            sep=" ", timespec="seconds"
        )
        return self._db.count_code_queries_since(
            since_ts_iso=since,
            ip_hash=hash_ip(ip) if ip else None,
            email_hash=hash_email(email) if email else None,
            exclude_error_kinds=exclude_error_kinds,
        )

    def count_auth_failures(self, ip: str, window_seconds: int) -> int:
        """限流：最近 ``window_seconds`` 内某 IP 的"凭据失败"次数。

        与 ``count_queries_in_window`` 区别：仅统计 ``error_kind='auth_failed'``
        的行，用于失败锁定判定（FailureLocker）。
        """
        if not ip:
            return 0
        since = (datetime.now() - timedelta(seconds=window_seconds)).isoformat(
            sep=" ", timespec="seconds"
        )
        return self._db.count_code_queries_since(
            since_ts_iso=since,
            ip_hash=hash_ip(ip),
            error_kind="auth_failed",
        )

    # ── 维护：清理过期日志 ───────────────────────────────────────

    def cleanup_old_query_log(self, retention_days: Optional[int] = None) -> int:
        """删除 ``retention_days`` 天前的 ``code_query_log`` 行（仅日志，
        不涉及 accounts / users）。无权限做定向删除。"""
        if retention_days is None:
            return self._db.cleanup_old_code_query_log()
        return self._db.cleanup_old_code_query_log(retention_days=retention_days)
