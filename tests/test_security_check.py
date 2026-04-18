# -*- coding: utf-8 -*-
"""启动时安全检查。"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from core.security_check import check_data_dir


def test_returns_empty_on_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert check_data_dir(tmp_path) == []


def test_nonexistent_dir_no_warn(tmp_path):
    if sys.platform.startswith("win"):
        pytest.skip("POSIX only")
    nope = tmp_path / "nope"
    assert check_data_dir(nope) == []


def test_secure_dir_no_warn(tmp_path):
    if sys.platform.startswith("win"):
        pytest.skip("POSIX only")
    os.chmod(tmp_path, 0o700)
    warns = check_data_dir(tmp_path)
    assert all("数据目录" not in w for w in warns)


def test_world_readable_dir_warns(tmp_path):
    if sys.platform.startswith("win"):
        pytest.skip("POSIX only")
    os.chmod(tmp_path, 0o755)
    warns = check_data_dir(tmp_path)
    assert any("数据目录权限过宽" in w for w in warns)


def test_master_key_world_readable_warns(tmp_path):
    if sys.platform.startswith("win"):
        pytest.skip("POSIX only")
    key = tmp_path / ".master.key"
    key.write_bytes(b"x" * 32)
    os.chmod(tmp_path, 0o700)
    os.chmod(key, 0o644)
    warns = check_data_dir(tmp_path)
    assert any("主密钥权限过宽" in w for w in warns)


def test_master_key_db_same_dir_warns(tmp_path):
    if sys.platform.startswith("win"):
        pytest.skip("POSIX only")
    (tmp_path / ".master.key").write_bytes(b"x" * 32)
    (tmp_path / "emails.db").write_bytes(b"\x00" * 8)
    os.chmod(tmp_path, 0o700)
    os.chmod(tmp_path / ".master.key", 0o600)
    os.chmod(tmp_path / "emails.db", 0o600)
    warns = check_data_dir(tmp_path)
    assert any("主密钥与数据库位于同一目录" in w for w in warns)
