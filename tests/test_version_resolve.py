# -*- coding: utf-8 -*-
"""``core.version.resolve_app_version`` 回归测试。

钉死版本号解析的优先级合约：
    APP_VERSION 环境变量 > git rev-parse --short=8 HEAD > "dev"

前端拿 "dev" 时不加 "v" 前缀（防止显示成 "vdev"），其他值才加 v。
本测试在 server 侧钉住 helper 行为；前端逻辑由人工 / E2E 验证。
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest


# ── 优先级 1：环境变量 ─────────────────────────────────────────────


def test_env_var_wins_over_git(monkeypatch):
    """APP_VERSION 环境变量存在时，直接使用，绝不调用 git。"""
    from core.version import resolve_app_version
    monkeypatch.setenv("APP_VERSION", "custom-tag-9.9.9")

    # 即使 cwd 在 git 仓库下，也不应去 subprocess 调 git
    with patch("core.version.subprocess.run") as spy:
        v = resolve_app_version(repo_root=Path.cwd())

    assert v == "custom-tag-9.9.9"
    assert not spy.called, "环境变量已设置时不应再 fork git 子进程"


def test_env_var_truncated_to_max_len(monkeypatch):
    """超长 APP_VERSION 截到 32 字符（防止前端 layout 被无限长字符串撑爆）。"""
    from core.version import resolve_app_version
    monkeypatch.setenv("APP_VERSION", "x" * 100)
    v = resolve_app_version()
    assert len(v) == 32
    assert v == "x" * 32


def test_env_var_blank_falls_through(monkeypatch):
    """APP_VERSION 设为空 / 仅空白时视为未设置，继续走 git → dev fallback 链。"""
    from core.version import resolve_app_version
    monkeypatch.setenv("APP_VERSION", "   ")  # 仅空白
    # 在非 git 目录下应得 dev
    v = resolve_app_version(repo_root="/nonexistent_path_xyz")
    assert v == "dev"


# ── 优先级 2：git rev-parse ───────────────────────────────────────


def test_git_short_sha_when_no_env(monkeypatch):
    """无环境变量但在 git 仓库下：返回 8 位 hex SHA。"""
    from core.version import resolve_app_version
    monkeypatch.delenv("APP_VERSION", raising=False)
    repo_root = Path(__file__).resolve().parents[1]  # 项目根
    v = resolve_app_version(repo_root=repo_root)
    # 本仓库正常情况下应有 git history
    assert v != "dev", "本仓库内应能拿到 git SHA，拿到 'dev' 说明 git 命令失败"
    assert len(v) == 8
    assert all(c in "0123456789abcdef" for c in v), f"SHA 应是 8 位 hex，实际: {v!r}"


def test_git_failure_falls_back_to_dev(monkeypatch):
    """git 命令失败（非 0 退出）→ fallback 到 'dev'。"""
    from core.version import resolve_app_version
    monkeypatch.delenv("APP_VERSION", raising=False)

    class _FakeCompleted:
        returncode = 128  # git 常见的"不是仓库"错误码
        stdout = "fatal: not a git repository\n"

    with patch("core.version.subprocess.run", return_value=_FakeCompleted()):
        v = resolve_app_version(repo_root=Path.cwd())
    assert v == "dev"


def test_git_binary_missing_falls_back_to_dev(monkeypatch):
    """系统没装 git 时 (shutil.which 返回 None) → 不抛异常，直接 fallback。"""
    from core.version import resolve_app_version
    monkeypatch.delenv("APP_VERSION", raising=False)

    with patch("core.version.shutil.which", return_value=None):
        v = resolve_app_version(repo_root=Path.cwd())
    assert v == "dev"


def test_git_subprocess_oserror_falls_back(monkeypatch):
    """subprocess 自身抛 OSError（PATH 错乱、权限问题）→ 不阻断启动。"""
    from core.version import resolve_app_version
    monkeypatch.delenv("APP_VERSION", raising=False)

    def _raise(*args, **kwargs):
        raise OSError("simulated subprocess explosion")

    with patch("core.version.shutil.which", return_value="/usr/bin/git"), \
         patch("core.version.subprocess.run", side_effect=_raise):
        v = resolve_app_version(repo_root=Path.cwd())
    assert v == "dev"


def test_git_garbled_output_falls_back(monkeypatch):
    """git 输出非合法 hex（被环境扰动 / 编码问题）→ 当作失败处理。"""
    from core.version import resolve_app_version
    monkeypatch.delenv("APP_VERSION", raising=False)

    class _FakeCompleted:
        returncode = 0
        stdout = "ZZZ-NOT-HEX\n"

    with patch("core.version.subprocess.run", return_value=_FakeCompleted()):
        v = resolve_app_version(repo_root=Path.cwd())
    assert v == "dev"


def test_git_too_long_output_falls_back(monkeypatch):
    """git 输出超过 8 字符（异常版本的 git 不支持 --short）→ fallback。"""
    from core.version import resolve_app_version
    monkeypatch.delenv("APP_VERSION", raising=False)

    class _FakeCompleted:
        returncode = 0
        stdout = "abcdef0123456789\n"  # 16 字符 long SHA

    with patch("core.version.subprocess.run", return_value=_FakeCompleted()):
        v = resolve_app_version(repo_root=Path.cwd())
    assert v == "dev"


# ── 优先级 3：fallback ────────────────────────────────────────────


def test_fallback_dev_when_all_fail(monkeypatch):
    """环境变量 + git 都拿不到 → 必须返回 'dev'（不能 None / 不能空串）。"""
    from core.version import resolve_app_version
    monkeypatch.delenv("APP_VERSION", raising=False)

    with patch("core.version.shutil.which", return_value=None):
        v = resolve_app_version(repo_root="/nonexistent/path")
    assert v == "dev"


# ── 启动期不抛异常（任何场景）──────────────────────────────────────


def test_resolver_never_raises_on_repo_root_str(monkeypatch):
    """传入 str / Path 都应工作，不抛 TypeError。"""
    from core.version import resolve_app_version
    monkeypatch.delenv("APP_VERSION", raising=False)
    # str 路径
    v1 = resolve_app_version(repo_root=str(Path(__file__).resolve().parents[1]))
    # Path 路径
    v2 = resolve_app_version(repo_root=Path(__file__).resolve().parents[1])
    assert v1 == v2  # 两次结果一致


def test_resolver_handles_none_repo_root(monkeypatch):
    """repo_root=None 走当前 cwd（不传也不抛）。"""
    from core.version import resolve_app_version
    monkeypatch.delenv("APP_VERSION", raising=False)
    v = resolve_app_version(repo_root=None)
    # 至少返回非空字符串
    assert isinstance(v, str) and v


# ── 集成：管理端 / 接码前台都要用上新 helper ───────────────────────


def test_web_app_uses_resolver_at_module_load():
    """``web_app._APP_VERSION`` 必须由 resolver 解析，不再硬编码 'dev'。"""
    import web_app
    # 在本仓库内跑测试，应得 git SHA 或者 fixture 注入的环境变量值
    # 关键不变量：不能是空串
    assert web_app._APP_VERSION  # noqa: SLF001
    assert isinstance(web_app._APP_VERSION, str)  # noqa: SLF001


def test_health_endpoint_returns_resolved_version(client):
    """``/api/health`` 暴露的 ``version`` 字段 == resolver 当前结果。"""
    import web_app
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert "version" in body
    assert body["version"] == web_app._APP_VERSION  # noqa: SLF001
