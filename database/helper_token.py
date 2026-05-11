"""
Helper Token 持久化
=====================

存放本地 Helper 客户端用来鉴权的一次性 token。和 ``emails.db`` 解耦：
用一个独立的 SQLite 文件 ``helper.db``，避免与账号存储的迁移/加密互相影响。

数据目录与 ``emails.db`` 同目录（``EMAIL_DATA_DIR`` 或 ``./data``）。

表结构::

    helper_tokens(
        token         TEXT PRIMARY KEY,    -- 64 位 hex
        label         TEXT,                -- 用户给该 token 起的名字（可选）
        owner_id      INTEGER NOT NULL,    -- 颁发该 token 的用户 ID（多用户隔离）
        created_at    INTEGER NOT NULL,
        last_used_at  INTEGER NOT NULL,
        revoked       INTEGER NOT NULL DEFAULT 0,
        platform      TEXT,
        version       TEXT
    )

使用方式::

    from database.helper_token import (
        provision_token, validate_token, touch_token, revoke_token,
    )
    token = provision_token(owner_id=42, label="xiaoxuan-laptop")
    info = validate_token(token)        # None 表示无效 / 已撤销 / 已过期
    touch_token(token, platform="win32", version="0.1.0")
    revoke_token(token)
"""
from __future__ import annotations

import logging
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DB_FILE_NAME = "helper.db"

# 默认有效期：7 天未被使用则自动失效。
#
# 0.1.2 以前是 30 天；安全审视后缩到 7 天 —— 邮箱助手 token 走 ``emailhelper://``
# URL 协议拉起，浏览器历史 / 扩展可能能拿到一次性快照。30 天的窗口给被截获
# 的 token 留了太长重放时间；7 天对正常使用毫无影响（每周连一次都会 touch），
# 但能压缩被滥用窗口。
DEFAULT_TTL_SECONDS = 7 * 24 * 3600

# 单用户允许的最大未撤销 token 数。超过会拒绝 provision_token，防止
# 累积无用 token / 误调用刷接口撑爆 helper.db。
MAX_TOKENS_PER_USER = 32

_SCHEMA = """
CREATE TABLE IF NOT EXISTS helper_tokens (
    token         TEXT PRIMARY KEY,
    label         TEXT,
    owner_id      INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER NOT NULL,
    revoked       INTEGER NOT NULL DEFAULT 0,
    platform      TEXT,
    version       TEXT
);
CREATE INDEX IF NOT EXISTS idx_helper_tokens_revoked
    ON helper_tokens(revoked);
CREATE INDEX IF NOT EXISTS idx_helper_tokens_owner
    ON helper_tokens(owner_id);
"""

_PRAGMAS = (
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA temp_store=MEMORY",
    "PRAGMA busy_timeout=5000",
)

_tls = threading.local()
_init_lock = threading.Lock()
_inited = False
_db_path_override: Optional[str] = None


def _resolve_db_path() -> str:
    """返回 helper.db 的绝对路径。测试可通过 ``set_db_path`` 覆写。"""
    if _db_path_override:
        return _db_path_override
    # 复用 db_manager.get_data_dir() 的目录选择策略
    from database.db_manager import get_data_dir  # 延迟导入避免循环
    return str(Path(get_data_dir()) / _DB_FILE_NAME)


def set_db_path(path: Optional[str]) -> None:
    """测试专用：临时把 helper.db 指到别的位置；传 None 恢复默认。"""
    global _db_path_override, _inited
    _db_path_override = path
    _inited = False
    _tls.__dict__.pop("conn", None)


def _connect() -> sqlite3.Connection:
    """每线程独立连接（按需创建），首次启动时建表。"""
    global _inited
    conn = getattr(_tls, "conn", None)
    if conn is None:
        path = _resolve_db_path()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        conn = sqlite3.connect(
            path,
            check_same_thread=False,
            timeout=10.0,
            isolation_level=None,  # autocommit
        )
        for pragma in _PRAGMAS:
            try:
                conn.execute(pragma)
            except sqlite3.Error as exc:
                logger.warning("helper.db PRAGMA 失败 %s: %s", pragma, exc)
        _tls.conn = conn

    if not _inited:
        with _init_lock:
            if not _inited:
                conn.executescript(_SCHEMA)
                _inited = True
    return conn


# ── Public API ─────────────────────────────────────────────────


def provision_token(owner_id: int, label: Optional[str] = None) -> str:
    """生成新 token 并落盘，返回 hex 字符串。

    owner_id 必填，用于多用户隔离：列出 / 撤销 token 时会按 owner_id 过滤。

    防御：单用户未撤销 token 数 >= ``MAX_TOKENS_PER_USER`` 时抛 ValueError，
    避免误循环或恶意调用刷接口撑爆 helper.db。
    """
    if not owner_id or owner_id < 1:
        raise ValueError("owner_id 必须为正整数")
    conn = _connect()
    # 查未撤销 token 数
    cur = conn.execute(
        "SELECT COUNT(*) FROM helper_tokens "
        "WHERE owner_id = ? AND revoked = 0",
        (int(owner_id),),
    )
    n = cur.fetchone()[0] or 0
    if n >= MAX_TOKENS_PER_USER:
        raise ValueError(
            f"当前未撤销 token 数 {n} 已达上限 {MAX_TOKENS_PER_USER}，"
            "请先在「邮箱助手 → 已颁发 Token」清理旧 token"
        )
    token = secrets.token_hex(32)  # 64 位 hex
    now = int(time.time())
    conn.execute(
        "INSERT INTO helper_tokens(token, label, owner_id, created_at, last_used_at, revoked) "
        "VALUES (?, ?, ?, ?, ?, 0)",
        (token, (label or "").strip() or None, int(owner_id), now, now),
    )
    return token


def validate_token(
    token: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> Optional[dict]:
    """校验 token；返回 dict 或 None。

    返回的 dict 至少含：token / label / owner_id / created_at / last_used_at / revoked /
    platform / version。
    """
    if not token or len(token) < 16:
        return None
    conn = _connect()
    cur = conn.execute(
        "SELECT token, label, owner_id, created_at, last_used_at, revoked, "
        "platform, version FROM helper_tokens WHERE token = ?",
        (token,),
    )
    row = cur.fetchone()
    if not row:
        return None
    info = dict(zip(
        ("token", "label", "owner_id", "created_at", "last_used_at",
         "revoked", "platform", "version"),
        row,
    ))
    if info["revoked"]:
        return None
    if ttl_seconds > 0:
        if int(time.time()) - int(info["last_used_at"]) >= ttl_seconds:
            return None
    return info


def touch_token(
    token: str,
    platform: Optional[str] = None,
    version: Optional[str] = None,
) -> None:
    """Helper 注册 / 心跳时调用，刷新 last_used_at + 元信息。"""
    if not token:
        return
    conn = _connect()
    conn.execute(
        "UPDATE helper_tokens SET last_used_at = ?, "
        "platform = COALESCE(?, platform), version = COALESCE(?, version) "
        "WHERE token = ?",
        (int(time.time()), platform, version, token),
    )


def revoke_token(token: str, owner_id: Optional[int] = None) -> bool:
    """撤销 token。

    若提供 owner_id，则强制 owner_id 匹配（防止跨用户撤销）；返回是否真撤销。
    """
    if not token:
        return False
    conn = _connect()
    if owner_id is not None:
        cur = conn.execute(
            "UPDATE helper_tokens SET revoked = 1 "
            "WHERE token = ? AND revoked = 0 AND owner_id = ?",
            (token, int(owner_id)),
        )
    else:
        cur = conn.execute(
            "UPDATE helper_tokens SET revoked = 1 "
            "WHERE token = ? AND revoked = 0",
            (token,),
        )
    return (cur.rowcount or 0) > 0


def revoke_all(owner_id: Optional[int] = None) -> int:
    """撤销 owner_id 名下所有未撤销 token；owner_id=None 表示全库（仅测试用）。"""
    conn = _connect()
    if owner_id is not None:
        cur = conn.execute(
            "UPDATE helper_tokens SET revoked = 1 "
            "WHERE revoked = 0 AND owner_id = ?",
            (int(owner_id),),
        )
    else:
        cur = conn.execute(
            "UPDATE helper_tokens SET revoked = 1 WHERE revoked = 0"
        )
    return cur.rowcount or 0


def list_tokens(
    owner_id: Optional[int] = None,
    include_revoked: bool = False,
) -> list[dict]:
    """列出 token（管理界面用）。owner_id 过滤；None=全部（仅测试）。"""
    conn = _connect()
    where = []
    params: list = []
    if owner_id is not None:
        where.append("owner_id = ?")
        params.append(int(owner_id))
    if not include_revoked:
        where.append("revoked = 0")
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    cur = conn.execute(
        "SELECT token, label, owner_id, created_at, last_used_at, "
        "revoked, platform, version FROM helper_tokens"
        + where_sql + " ORDER BY created_at DESC",
        params,
    )
    out: list[dict] = []
    for row in cur:
        out.append(dict(zip(
            ("token", "label", "owner_id", "created_at", "last_used_at",
             "revoked", "platform", "version"),
            row,
        )))
    return out


def purge_expired(ttl_seconds: int = DEFAULT_TTL_SECONDS) -> int:
    """物理删除超过 ttl 的已撤销 / 长期未用 token，返回删除数。"""
    conn = _connect()
    cutoff = int(time.time()) - max(0, ttl_seconds)
    cur = conn.execute(
        "DELETE FROM helper_tokens "
        "WHERE revoked = 1 OR last_used_at < ?",
        (cutoff,),
    )
    return cur.rowcount or 0


__all__ = (
    "DEFAULT_TTL_SECONDS",
    "set_db_path",
    "provision_token",
    "validate_token",
    "touch_token",
    "revoke_token",
    "revoke_all",
    "list_tokens",
    "purge_expired",
)
