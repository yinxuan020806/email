# -*- coding: utf-8 -*-
"""Schema 升级时旧表必须被备份，而不是直接 DROP。"""

from __future__ import annotations

import sqlite3
import sys

import pytest


def _reset_singletons():
    from core import security
    security.SecretBox._instance = None  # noqa: SLF001
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager")):
            sys.modules.pop(m, None)


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    _reset_singletons()
    yield tmp_path / "emails.db"
    _reset_singletons()


def test_v2_to_current_backs_up_old_tables(db_path, monkeypatch):
    """模拟 v2 旧库，升级后应该出现 backup_v2_xxx_accounts 表，且包含原数据。"""
    # 1. 手工建一个 "v2" 风格的库（没有 owner_id 的 accounts 表）
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA user_version = 2")
    conn.execute(
        """
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
        """
    )
    conn.execute("INSERT INTO accounts (email, password) VALUES (?, ?)",
                 ("legacy@x.com", "old-plain"))
    conn.execute("CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT UNIQUE)")
    conn.execute("INSERT INTO groups (name) VALUES ('OldGroup')")
    conn.commit()
    conn.close()

    # 2. 触发升级
    from database.db_manager import DatabaseManager, SCHEMA_VERSION
    DatabaseManager(db_path=str(db_path))

    # 3. 验证：新 accounts 表存在且为空（owner_id 重建）
    conn = sqlite3.connect(str(db_path))
    new_count = conn.execute(
        "SELECT COUNT(*) FROM accounts"
    ).fetchone()[0]
    assert new_count == 0  # 新表是干净的

    # 4. 验证：备份表存在并保留旧数据
    backup_tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'backup_v2_%_accounts'"
    ).fetchall()
    assert len(backup_tables) == 1, f"应有 1 个 backup_v2_*_accounts 备份表，实际: {backup_tables}"

    backup_name = backup_tables[0][0]
    rows = conn.execute(f"SELECT email, password FROM {backup_name}").fetchall()
    assert ("legacy@x.com", "old-plain") in rows

    # groups 也应被备份
    backup_groups = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'backup_v2_%_groups'"
    ).fetchall()
    assert len(backup_groups) == 1

    # 5. 升级后 user_version 应为 SCHEMA_VERSION
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    conn.close()


def test_fresh_install_no_backup_tables(db_path):
    """全新安装不应有任何 backup_ 表。"""
    from database.db_manager import DatabaseManager
    DatabaseManager(db_path=str(db_path))
    conn = sqlite3.connect(str(db_path))
    backups = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'backup_%'"
    ).fetchall()
    conn.close()
    assert backups == []


def test_audit_log_table_exists(db_path):
    """SCHEMA_VERSION=4 引入 audit_log 表，确认创建成功。"""
    from database.db_manager import DatabaseManager
    DatabaseManager(db_path=str(db_path))
    conn = sqlite3.connect(str(db_path))
    cols = conn.execute("PRAGMA table_info(audit_log)").fetchall()
    conn.close()
    col_names = {c[1] for c in cols}
    assert {"id", "ts", "user_id", "username", "action",
            "target", "ip", "user_agent", "success", "detail"} <= col_names


def test_v7_migration_fixes_fake_public_accounts(db_path, monkeypatch):
    """v6→v7 迁移：把 is_public=1 但 allowed_categories='' 的账号统一改成 '*'。

    回归用：用户实测场景——管理端 UI 显示『已开放』但前台查 openai 拿不到，
    必须重新点一次"加入接码"才能恢复。原因是账号 group_name='cursor'，旧逻辑
    依赖 group_name 推断分类（cursor 命中、openai 漏匹）。v7 让"已开放"
    在所有分类都有效。
    """
    # 1. 先用 v6 schema 建库，插一条"假加入"账号
    monkeypatch.setenv("EMAIL_DATA_DIR", str(db_path.parent))
    _reset_singletons()
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA user_version = 6")
    conn.execute(
        """CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"""
    )
    conn.execute("INSERT INTO users (username, password_hash) VALUES ('xiaoxuan', 'h')")
    conn.execute(
        """CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            group_name TEXT DEFAULT '默认分组',
            status TEXT DEFAULT '未检测',
            account_type TEXT DEFAULT '普通',
            imap_server TEXT, imap_port INTEGER DEFAULT 993,
            smtp_server TEXT, smtp_port INTEGER DEFAULT 465,
            client_id TEXT, refresh_token TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_check TIMESTAMP, has_aws_code INTEGER DEFAULT 0,
            remark TEXT, is_public INTEGER DEFAULT 0,
            allowed_categories TEXT DEFAULT '', query_count INTEGER DEFAULT 0,
            UNIQUE (owner_id, email))"""
    )
    # 三种账号，验证 v7 迁移行为
    conn.execute(
        "INSERT INTO accounts (owner_id, email, password, group_name, is_public, allowed_categories) "
        "VALUES (1, 'a@x.com', 'p', 'cursor', 1, '')"        # 假加入：分组限 cursor
    )
    conn.execute(
        "INSERT INTO accounts (owner_id, email, password, group_name, is_public, allowed_categories) "
        "VALUES (1, 'b@x.com', 'p', '默认', 1, '')"           # 完全假加入（v6 已修过）
    )
    conn.execute(
        "INSERT INTO accounts (owner_id, email, password, group_name, is_public, allowed_categories) "
        "VALUES (1, 'c@x.com', 'p', 'cursor', 1, 'cursor')"  # 显式只允许 cursor，不应被改
    )
    conn.execute(
        "INSERT INTO accounts (owner_id, email, password, group_name, is_public, allowed_categories) "
        "VALUES (1, 'd@x.com', 'p', 'cursor', 0, '')"        # 未开放，不该动
    )
    conn.commit()
    conn.close()

    # 2. 触发 v6 → v7 升级
    from database.db_manager import DatabaseManager, SCHEMA_VERSION
    assert SCHEMA_VERSION >= 7
    DatabaseManager(db_path=str(db_path))

    # 3. 验证迁移结果
    conn = sqlite3.connect(str(db_path))
    rows = dict(conn.execute(
        "SELECT email, allowed_categories FROM accounts ORDER BY email"
    ).fetchall())
    conn.close()
    _reset_singletons()

    assert rows["a@x.com"] == "*", "假加入(分组 cursor)账号应被 v7 修复为 '*'"
    assert rows["b@x.com"] == "*", "完全假加入账号应被 v7 修复为 '*'"
    assert rows["c@x.com"] == "cursor", "显式 'cursor' 配置不应被覆盖"
    assert rows["d@x.com"] == "", "is_public=0 的账号不该被动"
