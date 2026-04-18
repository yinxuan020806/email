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

SCHEMA_VERSION = 4

# 审计日志保留天数（超过自动清理）
AUDIT_RETENTION_DAYS = 90


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

            # v3 之前是单用户 schema，v3 起加 owner_id；结构差异较大无法在线迁移。
            # 升级前先把旧表 RENAME 成 backup_v{N}_{ts}_xxx，然后重建。
            # 这样万一升级出问题用户至少能从备份表里恢复出原始 password / refresh_token。
            if current_version != 0 and current_version < SCHEMA_VERSION:
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

    def _select_account_columns(self) -> str:
        # 与 Account.from_row 字段顺序保持一致（不含 owner_id）
        return (
            "id, email, password, group_name, status, account_type, "
            "imap_server, imap_port, smtp_server, smtp_port, "
            "client_id, refresh_token, created_at, last_check, "
            "has_aws_code, remark"
        )

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
