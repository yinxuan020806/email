# -*- coding: utf-8 -*-
"""``core.version.resolve_app_version`` 回归测试。

钉死版本号解析的优先级合约：
    APP_VERSION 环境变量 > core.version.__version__ 常量 > "dev"

发版流程：直接 bump ``core/version.py`` 顶部的 ``__version__``，无需 deploy 脚本。
前端拿 "dev" 时不加 "v" 前缀（防止显示成 "vdev"），其他值才加 v。
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


# ── 优先级 1：环境变量覆盖 ─────────────────────────────────────────


def test_env_var_wins_over_package_version(monkeypatch):
    """APP_VERSION 环境变量存在时，覆盖 ``__version__`` 常量。

    用于运维期临时覆盖（hotfix 标记 / canary 等）；正常发版应直接 bump 常量。
    """
    from core.version import resolve_app_version
    monkeypatch.setenv("APP_VERSION", "hotfix-2026-05-07")
    assert resolve_app_version() == "hotfix-2026-05-07"


def test_env_var_truncated_to_max_len(monkeypatch):
    """超长 APP_VERSION 截到 32 字符（防止前端 layout 被无限长字符串撑爆）。"""
    from core.version import resolve_app_version
    monkeypatch.setenv("APP_VERSION", "x" * 100)
    v = resolve_app_version()
    assert len(v) == 32
    assert v == "x" * 32


def test_env_var_blank_falls_through_to_package_version(monkeypatch):
    """APP_VERSION 设为空 / 仅空白时视为未设置，回到 ``__version__`` 常量。

    此场景对应 docker-compose 的 ``${APP_VERSION:-}`` 空 fallback：当
    宿主机 .env 没有 APP_VERSION 时，docker compose 会把空串透传给容器，
    我们必须正确识别并走代码常量，而不是错把空串当成显式值。
    """
    from core.version import __version__, resolve_app_version
    monkeypatch.setenv("APP_VERSION", "   ")  # 仅空白
    v = resolve_app_version()
    assert v == __version__


# ── 优先级 2：__version__ 常量是默认值 ────────────────────────────


def test_package_version_is_used_when_no_env_var(monkeypatch):
    """无环境变量时，直接使用 ``__version__`` 常量。

    这是默认场景：发版直接改常量、tag、push，前端右下角立刻看到新版本号。
    """
    from core.version import __version__, resolve_app_version
    monkeypatch.delenv("APP_VERSION", raising=False)
    assert resolve_app_version() == __version__


def test_package_version_format_is_semver_like():
    """``__version__`` 应是语义化形态（点分整数），便于前端展示成 v1.2.3。"""
    import re
    from core.version import __version__
    assert __version__, "__version__ 不能为空字符串"
    # 允许 1.2 / 1.2.3 / 1.2.3-rc.1 / 1.2.3+build.5 等常见形态
    assert re.match(r"^\d+(\.\d+)+([\-+][\w.\-]*)?$", __version__), (
        f"__version__={__version__!r} 不是语义化版本号；"
        f"建议形如 '1.0.1' / '1.2.3-rc.1'"
    )


# ── 优先级 3：极端 fallback ────────────────────────────────────────


def test_dev_fallback_only_when_constant_blank(monkeypatch):
    """理论上 ``__version__`` 常量永远非空；只有人为把它清空后才会走 dev。

    用来钉死"无论怎么折腾，永远不会返回空串"这一不变量。
    """
    from core import version as _version_mod
    monkeypatch.delenv("APP_VERSION", raising=False)
    monkeypatch.setattr(_version_mod, "__version__", "")
    v = _version_mod.resolve_app_version()
    assert v == "dev"


# ── 启动期不抛异常（任何场景）──────────────────────────────────────


def test_resolver_never_raises(monkeypatch):
    """任意环境下 resolver 都不能抛异常。"""
    from core.version import resolve_app_version
    # 无环境变量
    monkeypatch.delenv("APP_VERSION", raising=False)
    assert isinstance(resolve_app_version(), str)
    # 有环境变量
    monkeypatch.setenv("APP_VERSION", "test")
    assert isinstance(resolve_app_version(), str)


def test_legacy_repo_root_param_is_silently_ignored():
    """历史签名兼容：旧调用方传了 ``repo_root`` 参数也不报错。"""
    from core.version import resolve_app_version
    # 这些都应该正常工作，不抛 TypeError
    resolve_app_version(repo_root=None)
    resolve_app_version(repo_root="/any/path")
    from pathlib import Path
    resolve_app_version(repo_root=Path.cwd())


# ── 集成：管理端 / 接码前台都要用上 helper ─────────────────────────


def test_web_app_uses_resolver_at_module_load():
    """``web_app._APP_VERSION`` 必须由 resolver 解析，等于 ``__version__`` 常量
    （在测试环境无 APP_VERSION 时）。"""
    import web_app
    from core.version import __version__
    assert web_app._APP_VERSION == __version__  # noqa: SLF001


def test_health_endpoint_returns_resolved_version(client):
    """``/api/health`` 暴露的 ``version`` 字段 == resolver 当前结果。"""
    import web_app
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert "version" in body
    assert body["version"] == web_app._APP_VERSION  # noqa: SLF001


def test_health_endpoint_returns_semver_format(client):
    """``/api/health`` 默认返回语义化版本号（在测试环境）。"""
    import re
    r = client.get("/api/health")
    body = r.json()
    v = body.get("version", "")
    # 测试环境 conftest 不设 APP_VERSION，应走 __version__ 常量
    assert re.match(r"^\d+(\.\d+)+", v), (
        f"/api/health 返回的 version 应为语义化形态，实际: {v!r}"
    )
