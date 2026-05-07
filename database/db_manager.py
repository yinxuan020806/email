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
from core.security import SecretBox, SecretBoxDecryptError
from core.server_config import detect_server, get_imap_smtp


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

SCHEMA_VERSION = 7

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
        """取得一次性连接（调用方负责关闭）。

        每条连接都会应用 ``_PERF_PRAGMAS``（cache_size / mmap_size /
        temp_store / busy_timeout）。这些 PRAGMA 全部是 connection-level
        作用域，必须在每条新连接上都设置，否则只有 init 那一条享受到。
        """
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA foreign_keys = ON")
        self._apply_perf_pragmas(conn)
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

    # ── SQLite 性能 PRAGMA ────────────────────────────────────────
    # 这些 PRAGMA 在每个新连接上都生效（cache_size / mmap_size / temp_store
    # 是 connection-level，busy_timeout 也是 per-connection），写在
    # ``get_connection`` 而不是仅 ``_init_database``，因为本仓库每次操作都新建
    # 连接（``_connect`` 上下文 = connect→use→close）。一次 setup 在 init
    # 阶段只对 init 那条连接生效，后续业务连接拿不到。
    #
    # - cache_size = -64000：64MB page cache（默认仅 2MB，账号库大时索引常常
    #   走全表扫描；64MB 足以把 accounts/code_query_log 索引完整缓存住）。
    #   负数表示按 KB 计算，1 page=4KB 时即 16000 pages
    # - mmap_size  = 256MB ：让 SQLite 直接 mmap 数据库文件做大读零拷贝；
    #   超过 mmap_size 的部分自动 fallback 到普通 IO，安全
    # - temp_store = MEMORY：临时表 / 排序缓冲走内存，避免写 /tmp
    # - busy_timeout = 5000：并发写时等待 5 秒再抛 SQLITE_BUSY，与
    #   ``sqlite3.connect(timeout=10)`` 双层防护（前者是 SQLite 层、后者是
    #   Python 层），WAL + 5s busy timeout 实测能消化绝大多数瞬时锁竞争
    #
    # 不加 ``PRAGMA optimize`` —— 它会在大表上触发 ANALYZE，启动期延迟不可控；
    # 改在 ``cleanup_*`` 后调用一次更合适（未来可加）。
    _PERF_PRAGMAS = (
        "PRAGMA cache_size = -64000",
        "PRAGMA mmap_size = 268435456",
        "PRAGMA temp_store = MEMORY",
        "PRAGMA busy_timeout = 5000",
    )

    def _apply_perf_pragmas(self, conn: sqlite3.Connection) -> None:
        """对单条连接应用性能 PRAGMA。失败仅 logger，不阻断业务。

        某些极端环境（只读 FS、非常老的 SQLite 编译选项）可能不支持
        ``mmap_size``；此时单条 PRAGMA 失败不能让整个 ``get_connection``
        崩掉，否则一条连接异常就让整服务挂掉。
        """
        for sql in self._PERF_PRAGMAS:
            try:
                conn.execute(sql)
            except sqlite3.Error as exc:
                logger.warning("应用 PRAGMA 失败 %s: %s", sql, exc)

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

            # ── v5 → v6 一次性数据迁移：修复部分"假加入接码"账号（保守版） ──
            # 仅修复 group_name 不含分类关键字的账号 — 但漏掉了一种关键场景：
            # 账号 group_name='cursor' 时，前台查 cursor 能命中（group_name 推断），
            # 但查 openai 仍查不到——站长意图是"加入接码=允许所有分类"，但前台只支持
            # 一个分类。v6 没修这种 case；v7 来兜底。
            if current_version < 6:
                fix_sql = """
                    UPDATE accounts SET allowed_categories='*'
                    WHERE is_public = 1
                      AND COALESCE(allowed_categories, '') = ''
                      AND LOWER(COALESCE(group_name, '')) NOT LIKE '%cursor%'
                      AND LOWER(COALESCE(group_name, '')) NOT LIKE '%gpt%'
                      AND LOWER(COALESCE(group_name, '')) NOT LIKE '%openai%'
                      AND LOWER(COALESCE(group_name, '')) NOT LIKE '%chatgpt%'
                      AND LOWER(COALESCE(group_name, '')) NOT LIKE '%anthropic%'
                      AND LOWER(COALESCE(group_name, '')) NOT LIKE '%claude%'
                      AND LOWER(COALESCE(group_name, '')) NOT LIKE '%google%'
                      AND LOWER(COALESCE(group_name, '')) NOT LIKE '%gmail-only%'
                      AND LOWER(COALESCE(group_name, '')) NOT LIKE '%github%'
                """
                fixed = cur.execute(fix_sql).rowcount
                if fixed:
                    logger.warning(
                        "v5→v6 数据迁移：修复 %d 个『完全假加入』账号 "
                        "(allowed_categories: '' → '*')",
                        fixed,
                    )

            # ── v6 → v7 一次性数据迁移：修复"分类受限的假加入"账号 ──
            # 用户报告：管理端 UI 显示『已开放』，但前台查 openai 分类时仍提示
            # 『邮箱未加入接码白名单』，必须重新点一次"加入接码"才能恢复。
            #
            # 根因：账号 is_public=1 但 allowed_categories='' 且 group_name='cursor'
            # → group_name 推断只让 cursor 分类能查到，openai/chatgpt 都被拦下。
            # 但站长在 UI 点"加入接码"按钮的语义是"允许所有分类"（按钮目前默认写 '*'）。
            #
            # v7 无条件把所有 is_public=1 但 allowed_categories='' 的账号设成 '*'：
            # - 已经显式设过 allowed_categories（如 'cursor' / 'cursor,openai'）的账号不动
            # - 让"已开放"⇄"前台所有分类都能查到"语义彻底一致
            if current_version < 7:
                fix_sql_v7 = """
                    UPDATE accounts SET allowed_categories='*'
                    WHERE is_public = 1
                      AND COALESCE(allowed_categories, '') = ''
                """
                fixed_v7 = cur.execute(fix_sql_v7).rowcount
                if fixed_v7:
                    logger.warning(
                        "v6→v7 数据迁移：修复 %d 个『管理端显示已开放但前台查不到』"
                        "的账号 (allowed_categories: '' → '*')。这些账号 group_name "
                        "命中某个分类（如 cursor），但其他分类（如 openai）拿不到——"
                        "v7 让『加入接码』按钮的语义彻底兑现：开放 = 允许所有分类。",
                        fixed_v7,
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

    def delete_user_sessions(
        self, user_id: int, except_token: Optional[str] = None
    ) -> int:
        """删除指定用户的所有会话；用于改密码 / 强制下线场景。

        - ``except_token=None`` 表示**踢光所有会话**（包括当前），
          用于必须强制重新登录的场景（改密 / 主动安全注销）。
        - ``except_token=<token>`` 表示**保留该会话**，踢光其它，
          用于"修改密码后保持当前浏览器在线，其它端下线"的体验。
        - 返回真实删除条数（cur.rowcount）。
        """
        if not user_id:
            return 0
        if except_token:
            with self._connect() as conn:
                cur = conn.execute(
                    "DELETE FROM sessions WHERE user_id = ? AND token != ?",
                    (user_id, except_token),
                )
                return cur.rowcount
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM sessions WHERE user_id = ?", (user_id,),
            )
            return cur.rowcount

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
        # 邮箱地址标准化：去首尾空白 + 全部小写。
        # SMTP/IMAP RFC 5321 要求 local-part 大小写敏感，但实际所有主流邮件服务器
        # 都按大小写不敏感处理；保持小写存储后：
        # - import 同一邮箱的不同大小写形态（USER@x.com / user@X.COM）自动合并
        # - get_account_by_email / get_public_account_for_lookup 也能精确命中
        # - UNIQUE (owner_id, email) 约束实际生效，防"重复账号"
        email = (email or "").strip().lower()
        if not email or "@" not in email:
            return False, "邮箱格式不合法"

        box = SecretBox.instance()
        if not imap_server:
            imap_server, smtp_server = get_imap_smtp(email)
        else:
            # 自定义 imap 主机时，优先用 server_config 按邮箱域查表得到对应
            # SMTP 主机；表里没有再退化为基于 imap 字符串替换。
            #
            # 旧实现 ``imap_server.replace("imap", "smtp")`` 的两类已知问题：
            # 1. 主机名含多个 ``imap`` 子串时会全部替换（如 ``imap-relay.imap.example.com``）
            #    得到不存在的 SMTP 主机；
            # 2. ``outlook.office365.com`` / ``smtp.office365.com`` 这类命名
            #    不对称的服务（IMAP 与 SMTP 主机名前缀不同）会被错误推导。
            profile = detect_server(email)
            if profile and profile.smtp_host:
                smtp_server = profile.smtp_host
            elif imap_server.lower().startswith("imap."):
                smtp_server = "smtp." + imap_server[len("imap."):]
            else:
                smtp_server = imap_server.replace("imap", "smtp", 1)

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

    def get_accounts_by_ids(
        self, owner_id: int, account_ids: list[int]
    ) -> List[Account]:
        """按 ID 列表批量取账号，仅返回当前用户名下的命中项。

        相比 ``get_all_accounts(owner_id)`` 后过滤 ID：
        - 单条 SQL，N=10000 下省去 ~99% 的 Python 侧 dict 构建与解密开销
          （只解密命中的几条而非全表）
        - 用 SQL 自身做 owner_id 隔离，避免把"全表加载到内存里再过滤"的
          O(N) 临时副本暴露给进程
        - 返回顺序按 SQL 默认（id ASC）；调用方若需保留入参顺序应自行 reorder

        ``account_ids`` 为空或全部去重后为空 → 返回 ``[]``。
        SQLite 单语句最大占位符约 999（旧版）/ 32766（新版）；超过会被分片。
        """
        if not account_ids:
            return []
        unique_ids: list[int] = []
        seen: set[int] = set()
        for i in account_ids:
            if isinstance(i, int) and i not in seen:
                seen.add(i)
                unique_ids.append(i)
        if not unique_ids:
            return []

        cols = self._select_account_columns()
        # SQLite 老版本默认 SQLITE_MAX_VARIABLE_NUMBER=999；预留 1 个给 owner_id
        chunk_size = 998
        rows: list[tuple] = []
        with self._connect() as conn:
            for offset in range(0, len(unique_ids), chunk_size):
                chunk = unique_ids[offset:offset + chunk_size]
                placeholders = ",".join("?" for _ in chunk)
                cur = conn.execute(
                    f"SELECT {cols} FROM accounts "
                    f"WHERE owner_id = ? AND id IN ({placeholders})",
                    (owner_id, *chunk),
                )
                rows.extend(cur.fetchall())
        return [self._row_to_account(r) for r in rows]

    def get_account_by_email(self, owner_id: int, email: str) -> Optional[Account]:
        # 与 add_account 标准化策略一致：小写匹配，避免大小写差异导致漏命中
        norm = (email or "").strip().lower()
        if not norm:
            return None
        cols = self._select_account_columns()
        with self._connect() as conn:
            cur = conn.execute(
                f"SELECT {cols} FROM accounts WHERE owner_id = ? AND LOWER(email) = ?",
                (owner_id, norm),
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

    def get_existing_emails(self, owner_id: int) -> set[str]:
        """返回当前用户名下所有已存在账号的 email（小写、去重）。

        与 ``get_all_accounts`` 的本质差异：
        - 不构造 ``Account`` 对象
        - 不解密 ``password`` / ``refresh_token`` 密文
        - 仅 ``SELECT email``，让 SQLite 用覆盖索引（若存在）走单列扫描

        用于 ``import_accounts`` 的去重检查 — 旧实现是把整张表（含 N 个
        Fernet 密文）全解密一次只为读 email 字段，N=10000 时 ~2 万次
        Fernet 操作几乎是 import 接口的全部 CPU 开销。本方法把这一步
        从 O(N · Fernet) 降到 O(N)。
        """
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT LOWER(email) FROM accounts WHERE owner_id = ?",
                (owner_id,),
            )
            return {row[0] for row in cur.fetchall() if row[0]}

    def get_dashboard_stats(self, owner_id: int) -> dict:
        """仪表盘数据：纯 SQL 聚合，不解密任何密文。

        旧实现 ``/api/dashboard`` 走 ``get_all_accounts`` 全表加载 + 解密
        + Python 侧 dict 计数。本方法用两条 ``GROUP BY`` 替代，
        N=1000 账号下从 ~50ms（含 Fernet 开销）降到 ~2ms。

        返回结构与旧版完全一致：
            { "total": int,
              "groups":  {group_name: count, ...},
              "statuses": {status: count, ...} }

        注意：``statuses`` 至少包含 ``正常 / 异常 / 未检测`` 三个键
        （即使 count=0），保持前端渲染逻辑不必判 KeyError。
        """
        groups: dict[str, int] = {}
        statuses: dict[str, int] = {"正常": 0, "异常": 0, "未检测": 0}
        total = 0
        with self._connect() as conn:
            for name, cnt in conn.execute(
                "SELECT group_name, COUNT(*) FROM accounts "
                "WHERE owner_id = ? GROUP BY group_name",
                (owner_id,),
            ).fetchall():
                groups[name or "默认分组"] = int(cnt)
                total += int(cnt)
            for status, cnt in conn.execute(
                "SELECT status, COUNT(*) FROM accounts "
                "WHERE owner_id = ? GROUP BY status",
                (owner_id,),
            ).fetchall():
                statuses[status or "未检测"] = int(cnt)
        return {"total": total, "groups": groups, "statuses": statuses}

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

        ``allowed_categories`` 取值约定：
        - ``None`` / ``[]``：写入空串，前台按 ``group_name`` 自动推断分类
          （历史行为，向后兼容）
        - 含 ``'*'``：写入 ``'*'`` 通配，前台所有分类直接命中
          （与 ``get_public_account_for_lookup`` 的 ``allowed_categories='*'``
          分支配合；这是"加入接码白名单"按钮的默认语义）
        - 其他：按 ``ALLOWED_CODE_CATEGORIES`` 过滤后逗号拼接
        """
        cats_str = ""
        if allowed_categories:
            normalized = [
                c.strip().lower() for c in allowed_categories if c and c.strip()
            ]
            if "*" in normalized:
                cats_str = "*"
            else:
                valid = [c for c in normalized if c in ALLOWED_CODE_CATEGORIES]
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
        # email 用 LOWER() 让查询大小写不敏感；账号导入若大小写混存（如 User@x.com vs user@x.com）
        # 也不会因输入形态不同而漏命中公开账号
        # allowed_categories 用 token 严格匹配（前后包逗号，匹配 ',cursor,'）：
        # 旧版 `LIKE '%cursor%'` 在未来引入 'cursor-disabled' / 'chatgpt-code' 之类
        # 时会被误命中，token 匹配可彻底杜绝。
        sql = f"""
            SELECT {cols}
            FROM accounts a
            JOIN users u ON u.id = a.owner_id
            WHERE u.username = ?
              AND LOWER(a.email) = LOWER(?)
              AND a.is_public = 1
              AND (
                  a.allowed_categories = '*'
                  OR (',' || COALESCE(a.allowed_categories, '') || ',') LIKE ?
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
            f"%,{cat},%",
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
        error_kind: Optional[str] = None,
        exclude_error_kinds: Optional[list[str]] = None,
    ) -> int:
        """限流读：统计 ``since_ts_iso`` 之后某 ip_hash / email_hash / error_kind 的查询次数。

        ``error_kind`` 非空时仅统计该错误类型的行（用于 FailureLocker 的
        ``auth_failed`` 计数）；为空时不限制错误类型（用于普通限流计数）。
        ``exclude_error_kinds`` 非空时**排除**这些错误类型，让"前置失败"
        （如用户输错邮箱、parse 失败、人机校验失败）不占用 IP/email 限流配额，
        仅"实际发起 IMAP 拉取"的请求消耗配额，避免误操作把自己锁 1 小时。
        """
        sql = "SELECT COUNT(*) FROM code_query_log WHERE ts >= ?"
        params: list = [since_ts_iso]
        if ip_hash:
            sql += " AND ip_hash = ?"
            params.append(ip_hash)
        if email_hash:
            sql += " AND email_hash = ?"
            params.append(email_hash)
        if error_kind:
            sql += " AND error_kind = ?"
            params.append(error_kind)
        if exclude_error_kinds:
            cleaned = [k for k in exclude_error_kinds if k]
            if cleaned:
                placeholders = ",".join("?" for _ in cleaned)
                # COALESCE 保证 NULL（success=True 的成功行）不会被排除
                sql += f" AND COALESCE(error_kind, '') NOT IN ({placeholders})"
                params.extend(cleaned)
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
        """把 DB 行转 Account，并解密敏感字段。

        损坏密文容错策略：``SecretBox.decrypt`` 在新合约下会对"带前缀但
        Fernet 校验失败"的密文 ``raise SecretBoxDecryptError``。这里把它
        降级为单条字段失效（写 error 日志 + 字段置空），避免一条损坏数据
        把整张账号列表的查询拽崩。运维仍可通过 ERROR 日志感知到问题。
        """
        acc = Account.from_row(row)
        box = SecretBox.instance()
        try:
            acc.password = box.decrypt(acc.password) or ""
        except SecretBoxDecryptError:
            logger.error(
                "account.password 解密失败 acc.id=%s，本次回退为空字符串；"
                "请尽快定位 master.key 是否被替换或密文是否损坏",
                acc.id,
            )
            acc.password = ""
        try:
            acc.refresh_token = box.decrypt(acc.refresh_token)
        except SecretBoxDecryptError:
            logger.error(
                "account.refresh_token 解密失败 acc.id=%s，本次回退为 None",
                acc.id,
            )
            acc.refresh_token = None
        return acc

    @staticmethod
    def _safe_order(sort_by: str, sort_order: str) -> tuple[str, str]:
        if sort_by not in SORTABLE_COLUMNS:
            sort_by = "id"
        order = "DESC" if str(sort_order).upper() == "DESC" else "ASC"
        return sort_by, order
