# -*- coding: utf-8 -*-
"""
``core.helper_routes`` HTTP 端点单测：

- xiaoxuan 鉴权：非 xiaoxuan 用户 / 未登录 一律 403/401
- provision-token / status / tokens / revoke 基本流程
- stale_account_id 响应（mailbox/* 当 account_id 不存在时）
- dispatch action 白名单
- 批量 SSE 流（progress×N + done）
- /cancel-task 校验 owner 隔离
- audit_log 是否写入

测试策略：使用 TestClient 模拟 cookie，模拟 helper 注册后用后台线程响应 task。
"""
from __future__ import annotations

import json
import threading
import time
from typing import Iterator

import pytest

from database import helper_token as tk


@pytest.fixture
def helper_client(tmp_path, monkeypatch):
    """两个 TestClient：xiaoxuan (站长) + alice (普通用户)，共享同一 DB。"""
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    # 重置缓存
    import sys
    from core import security
    security.SecretBox._instance = None
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager",
                          "core.helper_registry", "core.helper_routes",
                          "database.helper_token")):
            sys.modules.pop(m, None)

    from fastapi.testclient import TestClient
    import web_app  # noqa: WPS433

    with TestClient(web_app.app) as xx, TestClient(web_app.app) as al:
        r1 = xx.post(
            "/api/auth/register",
            json={"username": "xiaoxuan", "password": "Pwd-Xiaoxuan-123"},
        )
        r2 = al.post(
            "/api/auth/register",
            json={"username": "alice", "password": "Pwd-Alice-123"},
        )
        assert r1.status_code == 200, r1.text
        assert r2.status_code == 200, r2.text
        yield xx, al

    # cleanup
    security.SecretBox._instance = None
    for m in list(sys.modules.keys()):
        if m.startswith(("web_app", "database.db_manager",
                          "core.helper_registry", "core.helper_routes",
                          "database.helper_token")):
            sys.modules.pop(m, None)


def _fake_helper(
    server_url_base: str,
    token: str,
    test_client,
    action_handlers: dict,
) -> tuple[threading.Event, threading.Thread, str]:
    """启动后台 fake helper：register → 循环 poll-task → 回 task-result。

    返回 (stop_event, thread, helper_id)。
    """
    # register
    r = test_client.post("/api/helper/register", json={
        "token": token, "version": "0.2.0", "platform": "win32",
    })
    assert r.status_code == 200, r.text
    helper_id = r.json()["helper_id"]

    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                r = test_client.get(
                    "/api/helper/poll-task",
                    params={"helper_id": helper_id, "timeout": 0.5},
                )
                data = r.json()
                for t in data.get("tasks", []):
                    if t.get("type") != "task":
                        continue
                    handler = action_handlers.get(t.get("action"))
                    result = (
                        handler(t) if handler
                        else {"success": False, "error": "no handler"}
                    )
                    result["task_id"] = t["task_id"]
                    test_client.post(
                        "/api/helper/task-result",
                        json=result,
                        headers={"X-Helper-Id": helper_id},
                    )
            except Exception:  # noqa: BLE001
                if stop.is_set():
                    return
                time.sleep(0.1)

    th = threading.Thread(target=loop, daemon=True)
    th.start()
    return stop, th, helper_id


# ── 鉴权 ────────────────────────────────────────────────────────


def test_helper_endpoints_require_owner(helper_client):
    """非 xiaoxuan 用户访问 helper 端点应得 403。"""
    _, alice = helper_client
    r = alice.get("/api/helper/status")
    assert r.status_code == 403
    r = alice.post("/api/helper/provision-token", json={"label": "evil"})
    assert r.status_code == 403


def test_helper_endpoints_require_login(helper_client):
    """未登录访问应得 401。"""
    from fastapi.testclient import TestClient
    import web_app
    with TestClient(web_app.app) as anonym:
        r = anonym.get("/api/helper/status")
        assert r.status_code == 401


# ── provision-token / list / revoke ─────────────────────────────


def test_provision_token_returns_full_token_once(helper_client):
    xx, _ = helper_client
    r = xx.post("/api/helper/provision-token", json={"label": "laptop"})
    assert r.status_code == 200
    data = r.json()
    assert data["success"]
    assert len(data["token"]) == 64  # 64 hex
    assert data["label"] == "laptop"
    assert data["ttl_seconds"] > 0


def test_list_tokens_redacted(helper_client):
    xx, _ = helper_client
    xx.post("/api/helper/provision-token", json={"label": "lt"})
    r = xx.get("/api/helper/tokens")
    assert r.status_code == 200
    items = r.json()["tokens"]
    assert len(items) == 1
    # token 应被脱敏（含 ...）
    assert "..." in items[0]["token"]


def test_provision_token_respects_max_limit(helper_client):
    """单用户超过 MAX_TOKENS_PER_USER 应被拒绝。

    不用 monkeypatch — TestClient 在 fixture 启动时已经把 helper_token
    模块 import 进 web_app 命名空间，函数体引用 MAX_TOKENS_PER_USER 时走
    模块级 LOAD_GLOBAL，但 helper.db 在 fixture 启动后才连，
    实际撑满 32 个最稳。
    """
    from database.helper_token import MAX_TOKENS_PER_USER
    xx, _ = helper_client
    for i in range(MAX_TOKENS_PER_USER):
        r = xx.post("/api/helper/provision-token", json={"label": f"t{i}"})
        assert r.json()["success"], f"#{i} should succeed: {r.text}"
    # 第 MAX+1 个应被拒
    r = xx.post("/api/helper/provision-token", json={"label": "t-overflow"})
    assert r.json()["success"] is False, r.json()
    assert "上限" in r.json()["error"]


def test_revoke_token_by_self(helper_client):
    xx, _ = helper_client
    r = xx.post("/api/helper/provision-token", json={"label": "for-revoke"})
    token = r.json()["token"]
    r = xx.post("/api/helper/revoke", json={"token": token})
    assert r.json()["success"]
    assert r.json()["revoked"] == 1


def test_revoke_all_for_owner(helper_client):
    xx, _ = helper_client
    for i in range(3):
        xx.post("/api/helper/provision-token", json={"label": f"t{i}"})
    r = xx.post("/api/helper/revoke", json={"all": True})
    assert r.json()["success"]
    assert r.json()["revoked"] == 3


# ── status 含 version_ok / min_helper_version ──────────────────


def test_status_offline(helper_client):
    xx, _ = helper_client
    r = xx.get("/api/helper/status")
    data = r.json()
    assert data["online"] is False
    assert data["min_helper_version"] == "0.2.0"


def test_status_online_with_version_ok(helper_client):
    xx, _ = helper_client
    token = xx.post("/api/helper/provision-token", json={"label": "x"}).json()["token"]
    stop, th, hid = _fake_helper("", token, xx, {})
    try:
        time.sleep(0.5)
        r = xx.get("/api/helper/status").json()
        assert r["online"] is True
        assert r["version_ok"] is True
        assert r["version"] == "0.2.0"
    finally:
        stop.set(); th.join(timeout=2)


# ── dispatch action 白名单 ──────────────────────────────────────


def test_dispatch_action_allowlist(helper_client):
    xx, _ = helper_client
    r = xx.post("/api/helper/dispatch", json={
        "action": "evil_or_misspelled",
        "params": {}, "timeout": 5,
    })
    data = r.json()
    assert data["success"] is False
    assert "不允许" in data["error"]


def test_dispatch_params_too_many(helper_client):
    xx, _ = helper_client
    r = xx.post("/api/helper/dispatch", json={
        "action": "ping",
        "params": {f"k{i}": "v" for i in range(40)},
        "timeout": 5,
    })
    data = r.json()
    assert data["success"] is False
    assert "字段过多" in data["error"]


def test_dispatch_ping_via_fake_helper(helper_client):
    xx, _ = helper_client
    token = xx.post("/api/helper/provision-token", json={"label": "x"}).json()["token"]
    stop, th, hid = _fake_helper(
        "", token, xx,
        {"ping": lambda t: {"success": True, "data": {"pong": 42}}},
    )
    try:
        r = xx.post("/api/helper/dispatch", json={
            "action": "ping", "params": {}, "timeout": 5,
        })
        data = r.json()
        assert data["success"] is True
        assert data["data"]["pong"] == 42
    finally:
        stop.set(); th.join(timeout=2)


# ── stale_account_id ────────────────────────────────────────────


def test_mailbox_open_stale_account_id(helper_client):
    xx, _ = helper_client
    r = xx.post("/api/helper/mailbox/open", json={
        "account_id": 99999, "timeout": 10,
    })
    data = r.json()
    assert data["success"] is False
    assert data["code"] == "stale_account_id"
    assert data["stale_account_id"] == 99999


def test_mailbox_get_token_stale_account_id(helper_client):
    xx, _ = helper_client
    r = xx.post("/api/helper/mailbox/get-token", json={
        "account_id": 99999, "timeout": 10,
    })
    assert r.json()["code"] == "stale_account_id"


# ── 批量 SSE 流 ─────────────────────────────────────────────────


def test_batch_mailbox_sse_progress_and_done(helper_client):
    xx, _ = helper_client
    # 导入 2 个账号
    xx.post("/api/accounts/import", json={
        "text": "a@x.com----p1\nb@x.com----p2",
        "group": "default", "skip_duplicate": True,
    })
    accs = xx.get("/api/accounts").json()
    ids = [a["id"] for a in accs]

    # 起 fake helper：stub 直接失败（验证派发链路即可）
    token = xx.post("/api/helper/provision-token", json={"label": "b"}).json()["token"]
    stop, th, hid = _fake_helper(
        "", token, xx,
        {"open_mailbox": lambda t: {"success": False, "error": "stub"}},
    )
    try:
        # 流式调用
        with xx.stream(
            "POST", "/api/helper/batch/mailbox",
            json={"action": "open_mailbox", "account_ids": ids, "timeout": 10},
        ) as r:
            events = []
            for line in r.iter_lines():
                if line.startswith("data: "):
                    events.append(json.loads(line[6:]))
        progress = [e for e in events if e.get("type") == "progress"]
        done = [e for e in events if e.get("type") == "done"]
        assert len(progress) == 2
        assert len(done) == 1
        assert done[0]["fail"] == 2
        assert done[0]["success"] == 0
    finally:
        stop.set(); th.join(timeout=2)


def test_batch_mailbox_bind_recovery_passes_alias_params(helper_client):
    """batch SSE 链路：bind_recovery_email 把 alias_suffix / alias_email 透传给 helper。

    Phase 1B 把单条绑辅助 / 改密 / 取 Token 改走 batch SSE 绕 Cloudflare 100s。
    确保 BatchMailboxRequest 新增的 alias_suffix / alias_email 字段确实落到
    dispatch 的 params 里（而不是被丢弃）。
    """
    xx, _ = helper_client
    # 导入 1 个账号
    xx.post("/api/accounts/import", json={
        "text": "bind-test@x.com----pwd-xxx",
        "group": "default", "skip_duplicate": True,
    })
    aid = xx.get("/api/accounts").json()[0]["id"]

    captured = {}

    def stub(task):
        # action_handlers 拿到 task 后会把 params 透出来；这里直接捕获后失败收尾
        captured["params"] = task.get("params") or {}
        return {"success": False, "error": "stub-captured"}

    token = xx.post("/api/helper/provision-token", json={"label": "b"}).json()["token"]
    stop, th, _hid = _fake_helper(
        "", token, xx,
        {"bind_recovery_email": stub},
    )
    try:
        with xx.stream(
            "POST", "/api/helper/batch/mailbox",
            json={
                "action": "bind_recovery_email",
                "account_ids": [aid],
                "timeout": 10,
                "alias_suffix": "mydomain.com",
                "alias_email": "user@mydomain.com",
            },
        ) as r:
            list(r.iter_lines())  # drain SSE
    finally:
        stop.set(); th.join(timeout=2)
    p = captured.get("params", {})
    assert p.get("alias_suffix") == "mydomain.com", f"captured: {p}"
    assert p.get("alias_email") == "user@mydomain.com"


def test_batch_mailbox_change_password_requires_new_password(helper_client):
    """批量改密缺 ``new_password`` 时单条直接判失败，不浪费 dispatch。

    v0.1.9 起为「单条改密走 SSE 绕 Cloudflare 100s」加了 change_email_password
    到 batch 白名单（前端 UI 仅允许 ``account_ids=[id]`` 单条形式触发，
    不开放真正的批量改密入口）。
    """
    xx, _ = helper_client
    # 导入 1 个账号
    xx.post("/api/accounts/import", json={
        "text": "missing-newpwd@x.com----old-pwd",
        "group": "default", "skip_duplicate": True,
    })
    aid = xx.get("/api/accounts").json()[0]["id"]
    with xx.stream("POST", "/api/helper/batch/mailbox",
                    json={"action": "change_email_password",
                          "account_ids": [aid], "timeout": 10}) as r:
        events = []
        for line in r.iter_lines():
            if line.startswith("data: "):
                events.append(json.loads(line[6:]))
    # 期望 2 条事件：progress(失败:缺 new_password) + done(fail=1)
    progress = [e for e in events if e.get("type") == "progress"]
    done = [e for e in events if e.get("type") == "done"]
    assert len(progress) == 1
    assert progress[0]["success"] is False
    assert "new_password" in progress[0].get("error", "")
    assert len(done) == 1
    assert done[0]["fail"] == 1


# ── cancel-task ─────────────────────────────────────────────────


def test_cancel_task_nonexistent(helper_client):
    xx, _ = helper_client
    r = xx.post("/api/helper/cancel-task", json={"task_id": "t_nope"})
    assert r.json()["success"] is False


# ── audit_log 写入 ──────────────────────────────────────────────


def test_audit_log_records_helper_actions(helper_client):
    xx, _ = helper_client
    xx.post("/api/helper/provision-token", json={"label": "audit-test"})
    # mailbox/open with stale account
    xx.post("/api/helper/mailbox/open", json={"account_id": 99999})

    r = xx.get("/api/audit?limit=20")
    audits = r.json()["items"]
    actions = [a["action"] for a in audits]
    assert "helper_provision_token" in actions
    assert "helper_mailbox_open" in actions
