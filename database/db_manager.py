# -*- coding: utf-8 -*-
"""
数据库管理模块 - SQLite 本地存储（多用户版）。

要点：
- 通过 PRAGMA user_version 做版本化 schema 迁移
- 启用 WAL，提升并发读性能
- password 与 refresh_token 通过 SecretBox 透明加密
- 多用户隔离：accounts / groups / settings 均按 owner_id 隔离
- 内置 users 与 sessions 两张表，支持账密注册与会话管理
"""

from __future__ import annotations

import logging
import os
import secrets
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator, List, Optional

from core.models import Account
from core.security import SecretBox
from core.server_config import get_imap_smtp


logger = logging.getLogger(__name__)


# 允许写入的 settings key 白名单
ALLOWED_SETTING_KEYS = {"theme", "language", "font_size"}

# 允许排序的字段白名单
SORTABLE_COLUMNS = {
    "id",
    "email",
    "group_name",
    "status",
    "account_type",
    "has_aws_code",
    "created_at",
    "last_check",
}

SCHEMA_VERSION = 5

# 审计日志保留天数（超过自动清理）
AUDIT_RETENTION_DAYS = 90

# 接码业务允许的分类标签白名单（写入 extractor_rules.category 时校验）
ALLOWED_CODE_CATEGORIES = {"cursor", "openai", "anthropic", "google", "github", "generic"}

# 接码查询日志保留天数
QUERY_LOG_RETENTION_DAYS = 30

# 当 accounts.allowed_categories 为空时，根据 accounts.group_name 自动推断
# 哪些分类可以查询（substring，大小写不敏感）。键是分类名，值是该分类
# 命中时需要在 group_name 中出现的关键字列表（任一即可）。
#
# 例：管理端把账号放进 group_name='cursor+gpt' 时，
#     既会被 'cursor' 命中（含 "cursor"），也会被 'openai' 命中（含 "gpt"）。
#
# 站长仍可通过显式 allowed_categories 精细覆盖，或用 '*' 表示允许所有分类。
GROUP_KEYWORDS_BY_CATEGORY: dict[str, tuple[str, ...]] = {
    "cursor": ("cursor",),
    "openai": ("gpt", "openai", "chatgpt"),
    "anthropic": ("anthropic", "claude"),
    "google": ("google", "gmail-only"),
    "github": ("github",),
}


def get_app_dir() -> str:
    """获取程序所在目录，兼容打包后的 exe。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_data_dir() -> Path:
    """数据目录优先级：

    1. 环境变量 EMAIL_DATA_DIR （容器/云部署）
    2. 程序所在目录下的 data/ （开发/单机使用）
    """
    env = os.getenv("EMAIL_DATA_DIR", "").strip()
    if env:
        return Path(env).expanduser()
    return Path(get_app_dir()) / "data"


class DatabaseManager:
    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(get_data_dir() / "emails.db")
        self.db_path = db_path

        db_dir = Path(db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        # 主密钥与数据库放在同一目录
        SecretBox.instance(key_path=db_dir / ".master.key")

        self._init_database()

    # ── 连接管理 ──────────────────────────────────────────────────

    def get_connection(self) -> sqlite3.Connection:
        """取得一次性连接（调用方负责关闭）。"""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """上下文管理器：自动 commit / rollback / close。"""
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── 初始化与迁移 ──────────────────────────────────────────────

    def _init_database(self) -> None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode = WAL")
            cur.execute("PRAGMA synchronous = NORMAL")

            current_version = cur.execute("PRAGMA user_version").fetchone()[0]

            # v3 及更早是不兼容 schema（无 owner_id），需要 RENAME 备份后重建；
            # v4→v5 仅新增列与表，可以在线增量，不动旧数据。
            BREAKING_THRESHOLD = 4
            if current_version != 0 and current_version < BREAKING_THRESHOLD:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                logger.warning(
                    "检测到旧数据库 (v%d)，升级到 v%d。旧表将重命名为 backup_v%d_%s_*，"
                    "如果升级后无问题可手动 DROP 这些备份表。",
                    current_version,
                    SCHEMA_VERSION,
                    current_version,
                    ts,
                )
                for tbl in ("accounts", "groups", "settings"):
                    exists = cur.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                        (tbl,),
                    ).fetchone()
                    if not exists:
                        continue
                    backup_name = f"backup_v{current_version}_{ts}_{tbl}"
                    try:
                        cur.execute(
                            f"ALTER TABLE {tbl} RENAME TO {backup_name}"
                        )
                        logger.warning("已备份: %s -> %s", tbl, backup_name)
                    except sqlite3.OperationalError as exc:
                        logger.exception("备份 %s 失败，回退到 DROP: %s", tbl, exc)
                        cur.execute(f"DROP TABLE IF EXISTS {tbl}")

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)"
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    email TEXT NOT NULL,
                    password TEXT NOT NULL,
                    group_name TEXT DEFAULT '默认分组',
                    status TEXT DEFAULT '未检测',
                    account_type TEXT DEFAULT '普通',
                    imap_server TEXT,
                    imap_port INTEGER DEFAULT 993,
                    smtp_server TEXT,
                    smtp_port INTEGER DEFAULT 465,
                    client_id TEXT,
                    refresh_token TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_check TIMESTAMP,
                    has_aws_code INTEGER DEFAULT 0,
                    remark TEXT,
                    is_public INTEGER DEFAULT 0,
                    allowed_categories TEXT DEFAULT '',
                    query_count INTEGER DEFAULT 0,
                    UNIQUE (owner_id, email)
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_accounts_owner ON accounts(owner_id)"
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (owner_id, name)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    key TEXT NOT NULL,
                    value TEXT,
                    PRIMARY KEY (owner_id, key)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER,
                    username TEXT,
                    action TEXT NOT NULL,
                    target TEXT,
                    ip TEXT,
                    user_agent TEXT,
                    success INTEGER DEFAULT 1,
                    detail TEXT
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)")

            # v4 → v5 增量：在线给已有 accounts 表补列（幂等）
            existing_cols = {
                row[1] for row in cur.execute("PRAGMA table_info(accounts)").fetchall()
            }
            for col_def in (
                ("is_public", "INTEGER DEFAULT 0"),
                ("allowed_categories", "TEXT DEFAULT ''"),
                ("query_count", "INTEGER DEFAULT 0"),
            ):
                col_name, col_type = col_def
                if col_name not in existing_cols:
                    try:
                        cur.execute(
                            f"ALTER TABLE accounts ADD COLUMN {col_name} {col_type}"
                        )
                        logger.info("accounts 表已增列: %s", col_name)
                    except sqlite3.OperationalError as exc:
                        logger.exception("ALTER TABLE 加列 %s 失败: %s", col_name, exc)

            # 接码业务：可由管理员热改的提取规则（按 category 分组）
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS extractor_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    sender_pattern TEXT DEFAULT '',
                    subject_pattern TEXT DEFAULT '',
                    code_regex TEXT DEFAULT '',
                    link_regex TEXT DEFAULT '',
                    priority INTEGER DEFAULT 0,
                    enabled INTEGER DEFAULT 1,
                    remark TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_extractor_rules_category "
                "ON extractor_rules(category, enabled, priority DESC)"
            )

            # 接码业务：前台每次查询都写一条，匿名（不记凭据原文）
            # ip_hash / email_hash 使用应用层 SHA-256，DB 里看到的是哈希，泄露也不暴露原值
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS code_query_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_hash TEXT NOT NULL,
                    email_hash TEXT NOT NULL,
                    email_domain TEXT,
                    category TEXT NOT NULL,
                    source TEXT DEFAULT 'public',
                    success INTEGER DEFAULT 0,
                    matched_rule_id INTEGER,
                    error_kind TEXT,
                    latency_ms INTEGER,
                    user_agent TEXT
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_code_query_ts ON code_query_log(ts)")
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_code_query_ip ON code_query_log(ip_hash, ts)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_code_query_email "
                "ON code_query_log(email_hash, ts)"
            )

            cur.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # ── User & Session ────────────────────────────────────────────

    def create_user(self, username: str, password_hash: str) -> Optional[int]:
        """注册新用户，返回 user_id；若用户名已存在返回 None。"""
        username = (username or "").strip()
        if not username or not password_hash:
            return None
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash),
                )
                user_id = cur.lastrowid
                # 自动创建默认分组
                conn.execute(
                    "INSERT OR IGNORE INTO groups (owner_id, name) VALUES (?, '默认分组')",
                    (user_id,),
                )
            return user_id
        except sqlite3.IntegrityError:
            return None

    def get_user_by_username(self, username: str) -> Optional[dict]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                ((username or "").strip(),),
            )
            row = cur.fetchone()
        if not row:
            return None
        return {"id": row[0], "username": row[1], "password_hash": row[2]}

    def get_user_by_id(self, user_id: int) -> Optional[dict]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT id, username, password_hash FROM users WHERE id = ?",
                (user_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        return {"id": row[0], "username": row[1], "password_hash": row[2]}

    def update_user_password(self, user_id: int, new_password_hash: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_password_hash, user_id),
            )
            return cur.rowcount > 0

    def create_session(self, user_id: int, ttl_seconds: int = 7 * 24 * 3600) -> str:
        """创建会话并返回 token。"""
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.now() + timedelta(seconds=ttl_seconds)).isoformat(
            sep=" ", timespec="seconds"
        )
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
                (token, user_id, expires_at),
            )
        return token

    def get_session_user(self, token: str) -> Optional[dict]:
        """查询 token 对应的用户；过期或不存在返回 None。"""
        if not token:
            return None
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT u.id, u.username
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token = ? AND s.expires_at > ?
                """,
                (token, datetime.now().isoformat(sep=" ", timespec="seconds")),
            )
            row = cur.fetchone()
        if not row:
            return None
        return {"id": row[0], "username": row[1]}

    def delete_session(self, token: str) -> bool:
        if not token:
            return False
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            return cur.rowcount > 0

    def cleanup_expired_sessions(self) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM sessions WHERE expires_at <= ?",
                (datetime.now().isoformat(sep=" ", timespec="seconds"),),
            )
            return cur.rowcount

    def user_count(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("SELECT COUNT(*) FROM users")
            return cur.fetchone()[0]

    # ── Audit Log ─────────────────────────────────────────────────

    def log_audit(
        self,
        action: str,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        target: Optional[str] = None,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
        detail: Optional[str] = None,
    ) -> None:
        """写入审计日志。失败仅记 logger，不抛异常打断主流程。"""
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO audit_log
                        (user_id, username, action, target, ip, user_agent, success, detail)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        username,
                        action,
                        target,
                        ip,
                        (user_agent or "")[:200],
                        1 if success else 0,
                        (detail or "")[:500],
                    ),
                )
        except sqlite3.Error:
            logger.exception("写入审计日志失败 action=%s", action)

    def list_audit(
        self,
        limit: int = 100,
        offset: int = 0,
        user_id: Optional[int] = None,
        action: Optional[str] = None,
    ) -> List[dict]:
        sql = "SELECT id, ts, user_id, username, action, target, ip, success, detail FROM audit_log WHERE 1=1"
        params: list = []
        if user_id is not None:
            sql += " AND user_id = ?"
            params.append(user_id)
        if action:
            sql += " AND action = ?"
            params.append(action)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([max(1, min(limit, 500)), max(0, offset)])
        with self._connect() as conn:
            cur = conn.execute(sql, params)
            rows = cur.fetchall()
        return [
            {
                "id": r[0],
                "ts": str(r[1]),
                "user_id": r[2],
                "username": r[3],
                "action": r[4],
                "target": r[5],
                "ip": r[6],
                "success": bool(r[7]),
                "detail": r[8],
            }
            for r in rows
        ]

    def cleanup_old_audit(self, retention_days: int = AUDIT_RETENTION_DAYS) -> int:
        cutoff = (datetime.now() - timedelta(days=retention_days)).isoformat(
            sep=" ", timespec="seconds"
        )
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,))
            return cur.rowcount

    # ── Account CRUD ──────────────────────────────────────────────

    def add_account(
        self,
        owner_id: int,
        email: str,
        password: str,
        group: str = "默认分组",
        imap_server: Optional[str] = None,
        imap_port: int = 993,
        client_id: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> tuple[bool, str]:
        box = SecretBox.instance()
        if not imap_server:
            imap_server, smtp_server = get_imap_smtp(email)
        else:
            smtp_server = imap_server.replace("imap", "smtp")

        account_type = "OAuth2" if client_id and refresh_token else "普通"
        group = (group or "默认分组").strip() or "默认分组"

        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO groups (owner_id, name) VALUES (?, ?)",
                    (owner_id, group),
                )
                conn.execute(
                    """
                    INSERT INTO accounts (
                        owner_id, email, password, group_name, imap_server, imap_port,
                        smtp_server, client_id, refresh_token, account_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        owner_id,
                        email,
                        box.encrypt(password) or "",
                        group,
                        imap_server,
                        imap_port,
                        smtp_server,
                        client_id,
                        box.encrypt(refresh_token),
                        account_type,
                    ),
                )
            return True, "添加成功"
        except sqlite3.IntegrityError:
            return False, "邮箱已存在"

    _ACCOUNT_COLUMN_NAMES = (
        "id", "email", "password", "group_name", "status", "account_type",
        "imap_server", "imap_port", "smtp_server", "smtp_port",
        "client_id", "refresh_token", "created_at", "last_check",
        "has_aws_code", "remark",
    )

    def _select_account_columns(self, alias: str = "") -> str:
        """与 Account.from_row 字段顺序保持一致（不含 owner_id）。

        ``alias`` 为表别名，在 JOIN 场景必须传入避免列名歧义。
        """
        prefix = f"{alias}." if alias else ""
        return ", ".join(f"{prefix}{c}" for c in self._ACCOUNT_COLUMN_NAMES)

    def get_account(self, owner_id: int, account_id: int) -> Optional[Account]:
        cols = self._select_account_columns()
        with self._connect() as conn:
            cur = conn.execute(
                f"SELECT {cols} FROM accounts WHERE id = ? AND owner_id = ?",
                (account_id, owner_id),
            )
            row = cur.fetchone()
        return self._row_to_account(row) if row else None

    def get_all_accounts(self, owner_id: int) -> List[Account]:
        cols = self._select_account_columns()
        with self._connect() as conn:
            cur = conn.execute(
                f"SELECT {cols} FROM accounts WHERE owner_id = ? ORDER BY id DESC",
                (owner_id,),
            )
            rows = cur.fetchall()
        return [self._row_to_account(r) for r in rows]

    def get_accounts_by_group(self, owner_id: int, group_name: str) -> List[Account]:
        cols = self._select_account_columns()
        with self._connect() as conn:
            cur = conn.execute(
                f"SELECT {cols} FROM accounts WHERE owner_id = ? AND group_name = ? ORDER BY id DESC",
                (owner_id, group_name),
            )
            rows = cur.fetchall()
        return [self._row_to_account(r) for r in rows]

    def get_account_by_email(self, owner_id: int, email: str) -> Optional[Account]:
        cols = self._select_account_columns()
        with self._connect() as conn:
            cur = conn.execute(
                f"SELECT {cols} FROM accounts WHERE owner_id = ? AND email = ?",
                (owner_id, email),
            )
            row = cur.fetchone()
        return self._row_to_account(row) if row else None

    def get_all_accounts_sorted(
        self, owner_id: int, sort_by: str = "id", sort_order: str = "DESC"
    ) -> List[Account]:
        sort_by, order = self._safe_order(sort_by, sort_order)
        cols = self._select_account_columns()
        with self._connect() as conn:
            cur = conn.execute(
                f"SELECT {cols} FROM accounts WHERE owner_id = ? ORDER BY {sort_by} {order}",
                (owner_id,),
            )
            rows = cur.fetchall()
        return [self._row_to_account(r) for r in rows]

    def get_accounts_by_group_sorted(
        self,
        owner_id: int,
        group_name: str,
        sort_by: str = "id",
        sort_order: str = "DESC",
    ) -> List[Account]:
        sort_by, order = self._safe_order(sort_by, sort_order)
        cols = self._select_account_columns()
        with self._connect() as conn:
            cur = conn.execute(
                f"SELECT {cols} FROM accounts WHERE owner_id = ? AND group_name = ? ORDER BY {sort_by} {order}",
                (owner_id, group_name),
            )
            rows = cur.fetchall()
        return [self._row_to_account(r) for r in rows]

    def update_account_oauth(
        self, owner_id: int, account_id: int, client_id: str, refresh_token: str
    ) -> bool:
        box = SecretBox.instance()
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE accounts
                SET client_id = ?, refresh_token = ?, account_type = 'OAuth2'
                WHERE id = ? AND owner_id = ?
                """,
                (client_id, box.encrypt(refresh_token), account_id, owner_id),
            )
            return cur.rowcount > 0

    def update_account_status(
        self, owner_id: int, account_id: int, status: str
    ) -> bool:
        now_iso = datetime.now().isoformat(sep=" ", timespec="seconds")
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE accounts SET status = ?, last_check = ? WHERE id = ? AND owner_id = ?",
                (status, now_iso, account_id, owner_id),
            )
            return cur.rowcount > 0

    def delete_account(self, owner_id: int, account_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM accounts WHERE id = ? AND owner_id = ?",
                (account_id, owner_id),
            )
            return cur.rowcount > 0

    def delete_accounts(self, owner_id: int, account_ids: list[int]) -> int:
        """批量删除（仅限当前用户名下的账号），返回真实删除行数。"""
        if not account_ids:
            return 0
        placeholders = ",".join("?" for _ in account_ids)
        with self._connect() as conn:
            cur = conn.execute(
                f"DELETE FROM accounts WHERE owner_id = ? AND id IN ({placeholders})",
                (owner_id, *account_ids),
            )
            return cur.rowcount

    def update_account_group(
        self, owner_id: int, account_id: int, group_name: str
    ) -> bool:
        group_name = (group_name or "").strip() or "默认分组"
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO groups (owner_id, name) VALUES (?, ?)",
                (owner_id, group_name),
            )
            cur = conn.execute(
                "UPDATE accounts SET group_name = ? WHERE id = ? AND owner_id = ?",
                (group_name, account_id, owner_id),
            )
            return cur.rowcount > 0

    def update_account_remark(
        self, owner_id: int, account_id: int, remark: str
    ) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE accounts SET remark = ? WHERE id = ? AND owner_id = ?",
                (remark, account_id, owner_id),
            )
            return cur.rowcount > 0

    def update_aws_code_status(
        self, owner_id: int, account_id: int, has_code: bool
    ) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE accounts SET has_aws_code = ? WHERE id = ? AND owner_id = ?",
                (1 if has_code else 0, account_id, owner_id),
            )
            return cur.rowcount > 0

    def get_account_count(self, owner_id: int) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT COUNT(*) FROM accounts WHERE owner_id = ?", (owner_id,)
            )
            return cur.fetchone()[0]

    # ── Group CRUD ────────────────────────────────────────────────

    def get_all_groups(self, owner_id: int) -> List[tuple]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT id, name FROM groups WHERE owner_id = ? ORDER BY id",
                (owner_id,),
            )
            return cur.fetchall()

    def add_group(self, owner_id: int, name: str) -> bool:
        name = (name or "").strip()
        if not name:
            return False
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO groups (owner_id, name) VALUES (?, ?)",
                    (owner_id, name),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def group_exists(self, owner_id: int, name: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT 1 FROM groups WHERE owner_id = ? AND name = ?",
                (owner_id, name),
            )
            return cur.fetchone() is not None

    def delete_group(self, owner_id: int, name: str) -> bool:
        if name == "默认分组":
            return False
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM groups WHERE owner_id = ? AND name = ?",
                (owner_id, name),
            )
            if cur.rowcount == 0:
                return False
            conn.execute(
                "UPDATE accounts SET group_name = '默认分组' WHERE owner_id = ? AND group_name = ?",
                (owner_id, name),
            )
            return True

    def rename_group(self, owner_id: int, old_name: str, new_name: str) -> bool:
        if old_name == "默认分组":
            return False
        new_name = (new_name or "").strip()
        if not new_name or new_name == old_name:
            return False
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE groups SET name = ? WHERE owner_id = ? AND name = ?",
                    (new_name, owner_id, old_name),
                )
                if cur.rowcount == 0:
                    return False
                conn.execute(
                    "UPDATE accounts SET group_name = ? WHERE owner_id = ? AND group_name = ?",
                    (new_name, owner_id, old_name),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    # ── Settings ──────────────────────────────────────────────────

    def get_setting(
        self, owner_id: int, key: str, default: Optional[str] = None
    ) -> Optional[str]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT value FROM settings WHERE owner_id = ? AND key = ?",
                (owner_id, key),
            )
            row = cur.fetchone()
        return row[0] if row else default

    def set_setting(self, owner_id: int, key: str, value: str) -> bool:
        if key not in ALLOWED_SETTING_KEYS:
            logger.warning("拒绝写入未在白名单的 setting key: %s", key)
            return False
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (owner_id, key, value) VALUES (?, ?, ?)",
                (owner_id, key, value),
            )
        return True

    # ── 接码业务（Code Receiver 前台共享 DB 用）─────────────────────
    #
    # 设计约束：
    # - 这部分方法不能让前台 web 进程拥有 accounts 写权限，因此只暴露
    #   "读公开账号" / "自增 query_count" / "记录日志" / "读规则" 四类。
    # - 管理端 (web_app.py) 才能调用 set_account_public / upsert_extractor_rule。

    def set_account_public(
        self,
        owner_id: int,
        account_id: int,
        is_public: bool,
        allowed_categories: Optional[List[str]] = None,
    ) -> bool:
        """管理端：把某个账号对前台公开 / 取消公开。

        ``allowed_categories`` 留空或 None 表示允许所有分类，否则用逗号
        分隔后入库（写入前会按 ALLOWED_CODE_CATEGORIES 过滤非法值）。
        """
        cats_str = ""
        if allowed_categories:
            valid = [
                c.strip().lower() for c in allowed_categories
                if c and c.strip().lower() in ALLOWED_CODE_CATEGORIES
            ]
            cats_str = ",".join(sorted(set(valid)))
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE accounts SET is_public = ?, allowed_categories = ? "
                "WHERE id = ? AND owner_id = ?",
                (1 if is_public else 0, cats_str, account_id, owner_id),
            )
            return cur.rowcount > 0

    def get_public_account_for_lookup(
        self, owner_username: str, email: str, category: str
    ) -> Optional[Account]:
        """前台：按"接码站长用户名 + 邮箱地址 + 分类"取一个公开账号。

        命中规则（任一为真即命中）：
        1. ``allowed_categories = '*'``                    显式声明允许所有分类
        2. ``allowed_categories LIKE '%<category>%'``      显式包含该分类
        3. ``allowed_categories`` 为空 + ``group_name``    在 GROUP_KEYWORDS_BY_CATEGORY[category]
           里含任一关键字                                   推断出该账号天然属于此分类

        过滤前置条件：
        - 该邮箱必须属于 ``owner_username`` 这一个用户
        - ``is_public = 1``

        命中后返回带解密的 Account；未命中返回 None。
        """
        if not (owner_username and email and category):
            return None

        cat = category.strip().lower()
        keywords = GROUP_KEYWORDS_BY_CATEGORY.get(cat, (cat,))

        cols = self._select_account_columns(alias="a")
        # 用占位符同时支撑显式 allowed_categories LIKE 与 N 个 group_name LIKE
        group_or = " OR ".join("lower(a.group_name) LIKE ?" for _ in keywords)
        sql = f"""
            SELECT {cols}
            FROM accounts a
            JOIN users u ON u.id = a.owner_id
            WHERE u.username = ?
              AND a.email = ?
              AND a.is_public = 1
              AND (
                  a.allowed_categories = '*'
                  OR a.allowed_categories LIKE ?
                  OR (
                      COALESCE(a.allowed_categories, '') = ''
                      AND ({group_or})
                  )
              )
            LIMIT 1
        """
        params: list = [
            (owner_username or "").strip(),
            email.strip(),
            f"%{cat}%",
        ]
        params.extend(f"%{kw.lower()}%" for kw in keywords)
        with self._connect() as conn:
            cur = conn.execute(sql, params)
            row = cur.fetchone()
        return self._row_to_account(row) if row else None

    def incr_account_query_count(self, account_id: int) -> bool:
        """前台命中公开账号后自增 query_count（不校验 owner，控制权在调用方）。"""
        if not account_id:
            return False
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE accounts SET query_count = COALESCE(query_count, 0) + 1 "
                "WHERE id = ?",
                (account_id,),
            )
            return cur.rowcount > 0

    def add_code_query_log(
        self,
        ip_hash: str,
        email_hash: str,
        category: str,
        success: bool,
        source: str = "public",
        email_domain: Optional[str] = None,
        matched_rule_id: Optional[int] = None,
        error_kind: Optional[str] = None,
        latency_ms: Optional[int] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        """前台：写一条接码查询日志。
        失败仅 logger，不抛异常打断主流程。
        ``ip_hash`` / ``email_hash`` 必须由调用方 SHA-256 后传入，DB 里不存原文。
        """
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO code_query_log
                        (ip_hash, email_hash, email_domain, category, source,
                         success, matched_rule_id, error_kind, latency_ms, user_agent)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ip_hash,
                        email_hash,
                        (email_domain or "")[:64],
                        (category or "")[:32],
                        (source or "public")[:16],
                        1 if success else 0,
                        matched_rule_id,
                        (error_kind or "")[:64] or None,
                        latency_ms,
                        (user_agent or "")[:200] or None,
                    ),
                )
        except sqlite3.Error:
            logger.exception("写入 code_query_log 失败")

    def count_code_queries_since(
        self,
        since_ts_iso: str,
        ip_hash: Optional[str] = None,
        email_hash: Optional[str] = None,
    ) -> int:
        """限流读：统计 ``since_ts_iso`` 之后某 ip_hash / email_hash 的查询次数。"""
        sql = "SELECT COUNT(*) FROM code_query_log WHERE ts >= ?"
        params: list = [since_ts_iso]
        if ip_hash:
            sql += " AND ip_hash = ?"
            params.append(ip_hash)
        if email_hash:
            sql += " AND email_hash = ?"
            params.append(email_hash)
        with self._connect() as conn:
            cur = conn.execute(sql, params)
            return cur.fetchone()[0]

    def cleanup_old_code_query_log(
        self, retention_days: int = QUERY_LOG_RETENTION_DAYS
    ) -> int:
        cutoff = (datetime.now() - timedelta(days=retention_days)).isoformat(
            sep=" ", timespec="seconds"
        )
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM code_query_log WHERE ts < ?", (cutoff,))
            return cur.rowcount

    def list_extractor_rules(
        self, category: Optional[str] = None, enabled_only: bool = True
    ) -> List[dict]:
        """读取规则列表，按 priority DESC, id ASC 排序。"""
        sql = "SELECT id, category, sender_pattern, subject_pattern, code_regex, " \
              "link_regex, priority, enabled, remark FROM extractor_rules WHERE 1=1"
        params: list = []
        if category:
            sql += " AND category = ?"
            params.append(category.lower())
        if enabled_only:
            sql += " AND enabled = 1"
        sql += " ORDER BY priority DESC, id ASC"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            {
                "id": r[0],
                "category": r[1],
                "sender_pattern": r[2] or "",
                "subject_pattern": r[3] or "",
                "code_regex": r[4] or "",
                "link_regex": r[5] or "",
                "priority": r[6] or 0,
                "enabled": bool(r[7]),
                "remark": r[8] or "",
            }
            for r in rows
        ]

    def upsert_extractor_rule(
        self,
        category: str,
        sender_pattern: str,
        subject_pattern: str = "",
        code_regex: str = "",
        link_regex: str = "",
        priority: int = 0,
        enabled: bool = True,
        remark: str = "",
        rule_id: Optional[int] = None,
    ) -> int:
        """新增 / 更新一条提取规则，返回规则 id。"""
        cat = (category or "").strip().lower()
        if cat not in ALLOWED_CODE_CATEGORIES:
            raise ValueError(f"category 必须是 {sorted(ALLOWED_CODE_CATEGORIES)} 之一")
        if rule_id:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE extractor_rules SET
                        category = ?, sender_pattern = ?, subject_pattern = ?,
                        code_regex = ?, link_regex = ?, priority = ?, enabled = ?,
                        remark = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (
                        cat, sender_pattern, subject_pattern, code_regex,
                        link_regex, priority, 1 if enabled else 0, remark, rule_id,
                    ),
                )
            return rule_id
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO extractor_rules
                    (category, sender_pattern, subject_pattern, code_regex,
                     link_regex, priority, enabled, remark)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cat, sender_pattern, subject_pattern, code_regex,
                    link_regex, priority, 1 if enabled else 0, remark,
                ),
            )
            return cur.lastrowid

    def delete_extractor_rule(self, rule_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM extractor_rules WHERE id = ?", (rule_id,)
            )
            return cur.rowcount > 0

    def health_ping(self) -> tuple[bool, str, set[str]]:
        """轻量健康检查：返回 (ok, error_kind, present_table_names)。

        ok=True 表示 DB 文件可读、关键表都存在。
        present_table_names 包含此次 PING 命中的接码业务表，便于上层精准告警。
        """
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name IN ('accounts','code_query_log','extractor_rules')"
                )
                names = {row[0] for row in cur.fetchall()}
            return True, "", names
        except sqlite3.Error as exc:
            return False, type(exc).__name__, set()

    # ── 内部辅助 ──────────────────────────────────────────────────

    def _row_to_account(self, row: tuple) -> Account:
        acc = Account.from_row(row)
        box = SecretBox.instance()
        acc.password = box.decrypt(acc.password) or ""
        acc.refresh_token = box.decrypt(acc.refresh_token)
        return acc

    @staticmethod
    def _safe_order(sort_by: str, sort_order: str) -> tuple[str, str]:
        if sort_by not in SORTABLE_COLUMNS:
            sort_by = "id"
        order = "DESC" if str(sort_order).upper() == "DESC" else "ASC"
        return sort_by, order
