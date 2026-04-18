# -*- coding: utf-8 -*-
"""批量检测/发送的并发行为：mock 同步 IMAP 调用，验证并发流式输出。"""

from __future__ import annotations

import json
import time
from unittest.mock import patch


def _import_n(client, n):
    text = "\n".join(f"acc{i}@gmail.com----pw{i}" for i in range(n))
    client.post("/api/accounts/import", json={
        "text": text, "group": "默认分组", "skip_duplicate": False,
    })
    return [a["id"] for a in client.get("/api/accounts").json()]


def _parse_sse(body: str):
    items = []
    for line in body.splitlines():
        if line.startswith("data: "):
            try:
                items.append(json.loads(line[6:]))
            except json.JSONDecodeError:
                pass
    return items


def test_batch_check_concurrent_completion(client):
    """并发执行：每个调用 sleep 0.5s，4 个总耗时应明显 < 2s（串行需 2s）。"""
    ids = _import_n(client, 4)

    def slow_check(owner_id, aid):
        time.sleep(0.5)
        return {"email": f"acc{aid}", "status": "正常", "has_aws": False, "found": True}

    with patch("web_app._check_one_sync", side_effect=slow_check):
        start = time.time()
        with client.stream("POST", "/api/batch/check",
                           json={"account_ids": ids}) as r:
            assert r.status_code == 200
            body = "".join(chunk for chunk in r.iter_text())
        elapsed = time.time() - start

    items = _parse_sse(body)
    progress = [i for i in items if i["type"] == "progress"]
    done = [i for i in items if i["type"] == "done"]

    assert len(progress) == 4
    assert len(done) == 1
    assert done[0]["success"] == 4
    # 4 路并发 > 串行（耗时大约 0.5-0.7s 而不是 2s+）
    assert elapsed < 1.5, f"并发未生效，耗时 {elapsed:.2f}s 太接近串行"


def test_batch_check_progress_monotonic(client):
    """current 字段必须单调递增，跟传入顺序无关。"""
    ids = _import_n(client, 5)

    def fake_check(owner_id, aid):
        # 反向 sleep 让先开始的后完成
        delay = 0.05 * (10 - (aid % 10))
        time.sleep(delay)
        return {"email": f"a{aid}", "status": "正常", "has_aws": False, "found": True}

    with patch("web_app._check_one_sync", side_effect=fake_check):
        with client.stream("POST", "/api/batch/check",
                           json={"account_ids": ids}) as r:
            body = "".join(chunk for chunk in r.iter_text())

    items = [i for i in _parse_sse(body) if i["type"] == "progress"]
    assert [it["current"] for it in items] == [1, 2, 3, 4, 5]
    # total 字段保持一致
    assert all(it["total"] == 5 for it in items)


def test_batch_send_concurrent(client):
    ids = _import_n(client, 4)

    def slow_send(owner_id, aid, to, subject, body):
        time.sleep(0.4)
        return {"email": f"acc{aid}", "success": True, "message": "ok"}

    with patch("web_app._send_one_sync", side_effect=slow_send):
        start = time.time()
        with client.stream("POST", "/api/batch/send",
                           json={
                               "account_ids": ids,
                               "to": "x@y.com",
                               "subject": "hi",
                               "body": "test",
                           }) as r:
            assert r.status_code == 200
            body = "".join(chunk for chunk in r.iter_text())
        elapsed = time.time() - start

    items = _parse_sse(body)
    done = [i for i in items if i["type"] == "done"]
    assert done[0]["success"] == 4
    # 4 路并发，2 个 worker（默认 SEND_CONCURRENCY=4，但 client fixture 中环境
    # 变量没设，所以是默认 4）—— 4 个任务应该几乎同时完成
    assert elapsed < 1.0, f"批量发送并发未生效，耗时 {elapsed:.2f}s"


def test_batch_check_handles_individual_failure(client):
    """部分账号失败不影响整体流程。"""
    ids = _import_n(client, 3)

    call_count = {"n": 0}

    def maybe_fail(owner_id, aid):
        call_count["n"] += 1
        if call_count["n"] == 2:
            return {"email": "?", "status": "异常", "has_aws": False, "found": True}
        return {"email": f"a{aid}", "status": "正常", "has_aws": False, "found": True}

    with patch("web_app._check_one_sync", side_effect=maybe_fail):
        with client.stream("POST", "/api/batch/check",
                           json={"account_ids": ids}) as r:
            body = "".join(chunk for chunk in r.iter_text())

    items = _parse_sse(body)
    done = [i for i in items if i["type"] == "done"][0]
    assert done["success"] + done["fail"] == 3
    assert done["fail"] >= 1
