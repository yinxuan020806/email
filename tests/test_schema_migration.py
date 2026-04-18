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
