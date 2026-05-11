# -*- coding: utf-8 -*-
"""
共享 fixture：每个测试使用临时数据目录，避免污染真实 data/。

多用户改造后：
- ``tmp_db``  暴露 (db, owner_id)，自动注入一个测试用户。
- ``client``  TestClient + 已登录测试用户，cookie 自动维护在 client 上。
- ``client2`` 第二个 TestClient，使用同一数据库但不同账号，便于做隔离测试。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


# ── 已移除的接口标记 ────────────────────────────────────────────
#
# 「手动授权」OAuth2 接口（``/api/oauth2/auth-url`` / ``/api/oauth2/exchange``
# / ``_pending_oauth_*`` 内部状态）在「邮箱助手 Helper」上线时被整体替换为
# helper 派发流程。下面这组测试针对的接口已经不存在了，但暂时保留测试文件
# 作为历史回归覆盖；用 ``OAUTH_REMOVED_SKIP`` 标记统一跳过。
#
# 后续 Stage 2 移植完 outlook_service.py 后可以彻底删除这些测试。
OAUTH_REMOVED_SKIP = pytest.mark.skip(
    reason="/api/oauth2/* 接口已被「邮箱助手 Helper」替代；此回归测试已过期",
)

# 让测试能 import 到项目根模块
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _reset_globals() -> None:
    """重置 SecretBox 单例与 web_app 缓存模块，避免测试间污染。"""
    from core import security
    security.SecretBox._instance = None  # noqa: SLF001
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager")):
            sys.modules.pop(m, None)


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """提供干净的 DatabaseManager，并自动注入一个测试用户。

    返回 (db, owner_id)。
    """
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    _reset_globals()

    from core.auth import hash_password
    from database.db_manager import DatabaseManager

    db = DatabaseManager()
    owner_id = db.create_user("tester", hash_password("pwd-tester"))
    assert owner_id is not None
    yield db, owner_id

    _reset_globals()


@pytest.fixture
def client(tmp_path, monkeypatch):
    """FastAPI TestClient，已自动注册并登录一个测试用户。"""
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    _reset_globals()

    from fastapi.testclient import TestClient
    import web_app  # noqa: WPS433

    with TestClient(web_app.app) as c:
        r = c.post(
            "/api/auth/register",
            json={"username": "alice", "password": "pwd-alice"},
        )
        assert r.status_code == 200, r.text
        yield c

    _reset_globals()


@pytest.fixture
def client2(tmp_path, monkeypatch):
    """两个 TestClient 共享同一数据库，分别登录两个不同用户。

    返回 (client_alice, client_bob)。两个 client 拥有独立 cookie jar。
    """
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    _reset_globals()

    from fastapi.testclient import TestClient
    import web_app  # noqa: WPS433

    with TestClient(web_app.app) as a, TestClient(web_app.app) as b:
        ra = a.post("/api/auth/register", json={"username": "alice", "password": "pwd-alice"})
        rb = b.post("/api/auth/register", json={"username": "bob", "password": "pwd-bob1"})
        assert ra.status_code == 200, ra.text
        assert rb.status_code == 200, rb.text
        yield a, b

    _reset_globals()
