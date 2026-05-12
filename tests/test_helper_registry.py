# -*- coding: utf-8 -*-
"""
``core.helper_registry`` 单测覆盖：

- HelperSession alive 判定 / outbox send / drain
- HelperRegistry register / unregister / get / get_online / status
- version 解析 + MIN_HELPER_VERSION 守门
- dispatch 完整链路（含派发前/超时/取消/完成的 SSE 广播）
- 并发上限保护
- cancel_task 跨 owner 隔离 + outbox drain
- broadcast_log + subscribe_logs / unsubscribe_logs 桶限制
"""
from __future__ import annotations

import queue
import threading
import time

import pytest

from core import helper_registry as reg
from database import helper_token as tk


@pytest.fixture
def fresh_db(tmp_path):
    db_path = tmp_path / "helper.db"
    tk.set_db_path(str(db_path))
    yield
    tk.set_db_path(None)


@pytest.fixture
def fresh_registry(fresh_db):
    """每个用例独立 registry 实例 + 干净 helper.db。"""
    r = reg.HelperRegistry()
    yield r
    # 清理订阅桶（模块级单例，避免跨测试污染）
    reg._log_subscribers.clear()


# ── version 解析 ────────────────────────────────────────────────


def test_parse_version_normal():
    assert reg._parse_version("0.1.2") == (0, 1, 2)
    assert reg._parse_version("v0.1.10") == (0, 1, 10)
    assert reg._parse_version("0.1.0-dev") == (0, 1, 0)
    assert reg._parse_version("1.2") == (1, 2, 0)


def test_parse_version_fallback():
    assert reg._parse_version("") == (0, 0, 0)
    assert reg._parse_version(None) == (0, 0, 0)  # type: ignore[arg-type]
    assert reg._parse_version("abc") == (0, 0, 0)
    assert reg._parse_version("0.x.5") == (0, 0, 5)


def test_version_ok():
    assert reg._version_ok("0.1.0", "0.1.0")
    assert reg._version_ok("0.1.10", "0.1.0")
    assert reg._version_ok("1.0.0", "0.1.0")
    assert not reg._version_ok("0.0.5", "0.1.0")
    assert not reg._version_ok("", "0.1.0")


# ── HelperSession ───────────────────────────────────────────────


def test_session_alive_and_dead():
    s = reg.HelperSession("h_1", "tk", 42, "0.1.0", "win32")
    assert s.alive
    s.mark_dead()
    assert not s.alive


def test_session_alive_after_timeout(monkeypatch):
    s = reg.HelperSession("h_1", "tk", 42, "0.1.0", "win32")
    monkeypatch.setattr(
        time, "time", lambda: s.last_seen + reg.HEARTBEAT_DEAD_AFTER + 1,
    )
    assert not s.alive


def test_session_outbox_send_drain():
    s = reg.HelperSession("h_1", "tk", 42, "0.1.0", "win32")
    assert s.send({"type": "task", "task_id": "t1", "action": "ping"})
    tasks = s.drain(timeout=0.1)
    assert len(tasks) == 1
    assert tasks[0]["task_id"] == "t1"


def test_session_send_returns_false_when_dead():
    s = reg.HelperSession("h_1", "tk", 42, "0.1.0", "win32")
    s.mark_dead()
    assert s.send({"type": "task", "task_id": "x"}) is False


# ── register / unregister ───────────────────────────────────────


def test_register_with_valid_token(fresh_registry):
    token = tk.provision_token(owner_id=42, label="laptop")
    sess, err = fresh_registry.register(token, "0.2.0", "win32")
    assert err is None
    assert sess is not None
    assert sess.owner_id == 42
    assert sess.version == "0.2.0"


def test_register_with_invalid_token(fresh_registry):
    sess, err = fresh_registry.register("not-a-real-token-xxxx", "0.1.0", "win32")
    assert sess is None
    assert err is not None


def test_register_revoked_token(fresh_registry):
    token = tk.provision_token(owner_id=1)
    tk.revoke_token(token, owner_id=1)
    sess, err = fresh_registry.register(token, "0.1.0", "win32")
    assert sess is None
    assert err is not None


def test_register_replaces_same_token(fresh_registry):
    """同 token 重连 → 旧 session 被踢，新 session 接管。"""
    token = tk.provision_token(owner_id=1)
    sess1, _ = fresh_registry.register(token, "0.1.0", "win32")
    sess2, _ = fresh_registry.register(token, "0.1.0", "win32")
    assert sess1.helper_id != sess2.helper_id
    # 旧 session 应被踢
    assert fresh_registry.get(sess1.helper_id) is None
    # 新 session 可查
    assert fresh_registry.get(sess2.helper_id) is not None


def test_get_online_per_owner(fresh_registry):
    tk_a = tk.provision_token(owner_id=1)
    tk_b = tk.provision_token(owner_id=2)
    sess_a, _ = fresh_registry.register(tk_a, "0.1.0", "win32")
    sess_b, _ = fresh_registry.register(tk_b, "0.1.0", "win32")

    # owner 1 只看到自己的
    online_1 = fresh_registry.get_online(owner_id=1)
    assert online_1.helper_id == sess_a.helper_id
    online_2 = fresh_registry.get_online(owner_id=2)
    assert online_2.helper_id == sess_b.helper_id

    # owner 99 没有
    assert fresh_registry.get_online(owner_id=99) is None


def test_status_per_owner(fresh_registry):
    token = tk.provision_token(owner_id=1)
    fresh_registry.register(token, "0.1.0", "win32")

    info = fresh_registry.status(owner_id=1)
    assert info["online"] is True
    # owner 2 没有 helper
    info2 = fresh_registry.status(owner_id=2)
    assert info2 == {"online": False}


# ── dispatch 完整链路 ─────────────────────────────────────────


def _fake_helper_loop(reg_instance, sess, action_handlers):
    """后台模拟 helper：取 task 后用 action_handlers 计算结果，回传 submit_result。"""
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            tasks = sess.drain(timeout=0.2)
            for t in tasks:
                if t.get("type") != "task":
                    continue
                handler = action_handlers.get(t.get("action"))
                result = handler(t) if handler else {
                    "success": False,
                    "error": f"unknown action: {t.get('action')}",
                }
                result.setdefault("task_id", t["task_id"])
                reg_instance.submit_result(sess.helper_id, result)

    th = threading.Thread(target=loop, daemon=True)
    th.start()
    return stop, th


def test_dispatch_success_returns_helper_result(fresh_registry):
    token = tk.provision_token(owner_id=1)
    sess, _ = fresh_registry.register(token, "0.2.0", "win32")

    stop, th = _fake_helper_loop(
        fresh_registry, sess,
        {"echo": lambda t: {"success": True, "data": {"echoed": t["params"]}}},
    )
    try:
        result = fresh_registry.dispatch(
            "echo", {"x": 1}, timeout=5, owner_id=1,
        )
        assert result["success"]
        assert result["data"]["echoed"] == {"x": 1}
        assert result["task_id"].startswith("t_")
    finally:
        stop.set(); th.join(timeout=2)


def test_dispatch_offline_returns_offline_flag(fresh_registry):
    result = fresh_registry.dispatch(
        "open_mailbox", {}, timeout=5, owner_id=1,
    )
    assert result["success"] is False
    assert result["offline"] is True


def test_dispatch_version_guard_blocks_old_helper(fresh_registry):
    """老 helper（version < MIN_HELPER_VERSION）调用业务 action 应被守门。"""
    token = tk.provision_token(owner_id=1)
    fresh_registry.register(token, "0.0.5", "win32")  # 故意低于 MIN

    result = fresh_registry.dispatch(
        "open_mailbox", {"email": "x"}, timeout=5, owner_id=1,
    )
    assert result["success"] is False
    assert result["needs_helper_upgrade"] is True
    assert result["current_version"] == "0.0.5"


def test_dispatch_version_guard_exempts_connectivity(fresh_registry):
    """echo/ping/version 这些连通性测试应该豁免版本守门（让 launch 后立即可测）。"""
    token = tk.provision_token(owner_id=1)
    sess, _ = fresh_registry.register(token, "0.0.5", "win32")

    stop, th = _fake_helper_loop(
        fresh_registry, sess,
        {"ping": lambda t: {"success": True, "data": {"pong": 123}}},
    )
    try:
        result = fresh_registry.dispatch("ping", {}, timeout=5, owner_id=1)
        assert result["success"] is True
        assert not result.get("needs_helper_upgrade")
    finally:
        stop.set(); th.join(timeout=2)


def test_dispatch_timeout(fresh_registry):
    """helper 不响应 task-result 时 dispatch 应超时返回。"""
    token = tk.provision_token(owner_id=1)
    sess, _ = fresh_registry.register(token, "0.2.0", "win32")
    # 不启 fake helper，task 派出去后没人响应

    result = fresh_registry.dispatch(
        "ping", {}, timeout=1, owner_id=1,  # 1s timeout
    )
    assert result["success"] is False
    assert "超时" in result["error"]


def test_dispatch_concurrent_limit(fresh_registry):
    """同 owner 同时 N 个业务任务派发 → 第 N+1 个被并发上限挡下。"""
    token = tk.provision_token(owner_id=1)
    sess, _ = fresh_registry.register(token, "0.2.0", "win32")

    # 把 _pending 手动填满（不真跑 fake helper，让 task 一直 pending）
    barrier = threading.Event()
    results = []

    def slow_dispatch():
        # 用 ping 不会被业务版本守门拦
        results.append(
            fresh_registry.dispatch("open_mailbox",
                                    {"email": "x", "email_password": "p"},
                                    timeout=2, owner_id=1)
        )

    # 派 MAX+1 个并发
    threads = [
        threading.Thread(target=slow_dispatch, daemon=True)
        for _ in range(reg.MAX_CONCURRENT_TASKS_PER_OWNER + 1)
    ]
    for t in threads:
        t.start()
    # 等一会儿让前 N 个进 _pending，第 N+1 个被并发上限拦
    time.sleep(0.3)

    # 检查 _pending：应该至多 MAX 个
    with fresh_registry._lock:
        in_flight = sum(
            1 for (_, oid) in fresh_registry._pending.values() if oid == 1
        )
    assert in_flight <= reg.MAX_CONCURRENT_TASKS_PER_OWNER

    # 等所有线程结束（前 N 个超时返回，最后一个 too_many_concurrent 立返）
    for t in threads:
        t.join(timeout=5)

    too_many = [r for r in results if r.get("too_many_concurrent")]
    assert len(too_many) >= 1, f"应该至少 1 个被并发限制，实际 {results}"


# ── cancel_task ─────────────────────────────────────────────────


def test_cancel_task_returns_false_for_unknown(fresh_registry):
    assert fresh_registry.cancel_task(1, "nonexistent") is False


def test_cancel_task_blocks_cross_owner(fresh_registry):
    """owner B 不能取消 owner A 的 task。"""
    token_a = tk.provision_token(owner_id=1)
    sess_a, _ = fresh_registry.register(token_a, "0.2.0", "win32")

    # 手动塞一个 pending task
    q: queue.Queue = queue.Queue(maxsize=1)
    fresh_registry._pending["t_test"] = (q, 1)  # owner=1

    # owner B 尝试取消
    assert fresh_registry.cancel_task(owner_id=2, task_id="t_test") is False
    # owner 自己取消
    assert fresh_registry.cancel_task(owner_id=1, task_id="t_test") is True
    item = q.get_nowait()
    assert item["_cancelled"] is True


def test_cancel_task_drains_outbox(fresh_registry):
    """cancel 时应该从 helper outbox 中清掉还没发的 task。"""
    token = tk.provision_token(owner_id=1)
    sess, _ = fresh_registry.register(token, "0.2.0", "win32")

    # 塞 2 个 task 进 outbox（helper 还没 poll）
    sess.send({"type": "task", "task_id": "t_a", "action": "ping"})
    sess.send({"type": "task", "task_id": "t_b", "action": "ping"})
    # 同步 _pending 记录（模拟 dispatch 派单时填入的）
    q_a: queue.Queue = queue.Queue(maxsize=1)
    q_b: queue.Queue = queue.Queue(maxsize=1)
    fresh_registry._pending["t_a"] = (q_a, 1)
    fresh_registry._pending["t_b"] = (q_b, 1)

    # 取消 t_a
    assert fresh_registry.cancel_task(owner_id=1, task_id="t_a") is True

    # outbox 里应只剩 t_b
    remaining = sess.drain(timeout=0.1, max_batch=10)
    task_ids = [m.get("task_id") for m in remaining]
    assert "t_a" not in task_ids
    assert "t_b" in task_ids

    # cancel_task 应该往 q_a 塞了 _cancelled 消息
    cancelled_msg = q_a.get_nowait()
    assert cancelled_msg["_cancelled"] is True
    assert cancelled_msg["_cancelled_in_outbox"] is True


# ── 日志广播 ────────────────────────────────────────────────────


def test_subscribe_unsubscribe(fresh_registry):
    q = reg.subscribe_logs(owner_id=42)
    assert q in reg._log_subscribers[42]
    reg.unsubscribe_logs(42, q)
    assert 42 not in reg._log_subscribers


def test_broadcast_log_reaches_subscribers(fresh_registry):
    q = reg.subscribe_logs(owner_id=42)
    fresh_registry.broadcast_log(42, "hello", "info")
    msg = q.get_nowait()
    assert msg["message"] == "hello"
    assert msg["level"] == "info"


def test_broadcast_log_isolated_per_owner(fresh_registry):
    q1 = reg.subscribe_logs(owner_id=1)
    q2 = reg.subscribe_logs(owner_id=2)
    fresh_registry.broadcast_log(1, "for-1", "info")

    msg = q1.get_nowait()
    assert msg["message"] == "for-1"
    # owner 2 的桶不应收到 owner 1 的消息
    with pytest.raises(queue.Empty):
        q2.get_nowait()


def test_subscribe_logs_lru_eviction(fresh_registry):
    """超过 _MAX_SUBSCRIBERS_PER_OWNER 时最老的会被踢。"""
    queues = []
    for _ in range(reg._MAX_SUBSCRIBERS_PER_OWNER):
        queues.append(reg.subscribe_logs(owner_id=1))
    assert len(reg._log_subscribers[1]) == reg._MAX_SUBSCRIBERS_PER_OWNER

    # 再加一个 → 最老的（queues[0]）被踢
    new_q = reg.subscribe_logs(owner_id=1)
    assert len(reg._log_subscribers[1]) == reg._MAX_SUBSCRIBERS_PER_OWNER
    assert queues[0] not in reg._log_subscribers[1]
    assert new_q in reg._log_subscribers[1]
    # 被踢的 queue 应该收到 _disconnect 信号
    msg = queues[0].get_nowait()
    assert msg["type"] == "_disconnect"


# ── dispatch 派单广播日志 ────────────────────────────────────────


def test_dispatch_broadcasts_status_logs(fresh_registry):
    """dispatch 应该在派发前/完成时主动 broadcast SSE 日志。"""
    token = tk.provision_token(owner_id=1)
    sess, _ = fresh_registry.register(token, "0.2.0", "win32")
    q = reg.subscribe_logs(owner_id=1)

    stop, th = _fake_helper_loop(
        fresh_registry, sess,
        {"ping": lambda t: {"success": True, "data": {"pong": 1}}},
    )
    try:
        fresh_registry.dispatch("ping", {}, timeout=5, owner_id=1)
    finally:
        stop.set(); th.join(timeout=2)

    messages = []
    while not q.empty():
        messages.append(q.get_nowait().get("message", ""))
    assert any("已派发任务到本地 Helper" in m for m in messages)
    assert any("✅" in m and "ping" in m for m in messages)
