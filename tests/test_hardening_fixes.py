# -*- coding: utf-8 -*-
"""本轮硬化修复对应的回归测试（管理端）。

覆盖修复点：
- M4 ``mail_parser.has_attachments`` 处理 None Content-Disposition
- L1 ``EmailClient.fetch_emails`` Graph 路径直接返回（不再有冗余 if）
- M5 ``OAuth2Helper.exchange_code_for_token`` 错误响应非 JSON 时不崩溃
- L2 静态资源 ``index.html`` 缺失时返回 503 而非 500
- L5 batch SSE 响应头包含 ``X-Accel-Buffering: no``
- L6 ``mark_read`` / ``delete_email`` / ``update_account_group`` / ``update_account_remark``
    操作有审计日志
- L8 ``EMAIL_WEB_TRUST_PROXY=False`` 时拒绝信任反代头
- M1 OAuth 自动取邮箱失败时返回 ``needs_email`` 让用户两阶段提交补 email
- L7 ``db.add_account`` 静默失败不再被 OAuth 路径吞掉
- S1 batch SSE 客户端断开时 task 被取消（_cancel_pending 工具函数验证）
"""

from __future__ import annotations

import asyncio
import os
import sys
from email.message import Message
from pathlib import Path
from unittest.mock import patch

import pytest


# ── 单元测试：core/* 直接验证 ─────────────────────────────────────


def test_has_attachments_handles_none_disposition():
    """M4: ``part.get(...)`` 在某些奇怪邮件下返回 None，旧代码 `or ""` 拼写有歧义。
    
    新版用 ``(part.get(...) or "")`` 显式处理 None，确保 None 不会进入 ``in`` 触发 TypeError。
    """
    from core.mail_parser import has_attachments

    class FakePart:
        def __init__(self, disposition):
            self._d = disposition
            self._items = []

        def get(self, key, default=None):
            if key == "Content-Disposition":
                return self._d
            return default

        def walk(self):
            return iter(self._items)

    class FakeMsg:
        def __init__(self, parts):
            self._parts = parts

        def is_multipart(self):
            return True

        def walk(self):
            return iter(self._parts)

    # Content-Disposition 为 None 不应抛 TypeError
    msg_none = FakeMsg([FakePart(None)])
    assert has_attachments(msg_none) is False

    # 正常 attachment 仍应识别
    msg_att = FakeMsg([FakePart("attachment; filename=foo.pdf")])
    assert has_attachments(msg_att) is True

    # inline 不算 attachment
    msg_inline = FakeMsg([FakePart("inline")])
    assert has_attachments(msg_inline) is False


def test_email_client_fetch_emails_returns_graph_directly():
    """L1: Graph 路径不再有 ``if emails: return ...; return ...`` 的冗余分支。
    
    旧代码两个 return 完全一样；新代码直接 return，路径更短也更不易出 bug。
    """
    from core.email_client import EmailClient

    client = EmailClient.__new__(EmailClient)
    client.email_addr = "x@example.com"
    client.password = ""
    client._token_manager = None

    class FakeGraph:
        def __init__(self):
            self.calls = 0

        def fetch_emails(self, folder, limit, with_body):
            self.calls += 1
            return [], "empty-but-ok"

    client._graph = FakeGraph()
    client._imap = None  # 不应被调用

    emails, msg = client.fetch_emails(folder="inbox", limit=5, with_body=False)
    assert emails == []
    assert msg == "empty-but-ok"
    assert client._graph.calls == 1


def test_oauth2_helper_handles_non_json_error_response():
    """M5: Microsoft 在 5xx / WAF 拦截时可能返回 HTML 或空响应，旧代码 ``resp.json()``
    会抛 ValueError 进入外层 ``Exception`` 分支，把错误信息丢失成"授权过程出错: 0"。
    """
    from core.oauth2_helper import OAuth2Helper

    class FakeResp:
        def __init__(self, status, text="<html>Service Unavailable</html>"):
            self.status_code = status
            self.text = text

        def json(self):
            raise ValueError("not json")

    helper = OAuth2Helper(client_id="fake-cid")

    with patch(
        "core.oauth2_helper.requests.post",
        return_value=FakeResp(503, "<html>Service Unavailable</html>"),
    ):
        cid, rt, err = helper.exchange_code_for_token(
            "https://localhost/?code=abc"
        )
    assert cid is None
    assert rt is None
    assert err is not None
    # 错误信息应该包含原始响应（截断后），而不是被 except Exception 吞成无意义字符串
    assert "Service Unavailable" in err or "503" in err


def test_oauth2_helper_handles_non_json_success_response():
    """M5 续：200 但响应体异常的极端情况也不能崩。"""
    from core.oauth2_helper import OAuth2Helper

    class FakeResp:
        status_code = 200
        text = "<html>not json</html>"

        def json(self):
            raise ValueError("not json")

    helper = OAuth2Helper(client_id="fake-cid")
    with patch("core.oauth2_helper.requests.post", return_value=FakeResp()):
        cid, rt, err = helper.exchange_code_for_token(
            "https://localhost/?code=abc"
        )
    assert cid is None
    assert rt is None
    assert err is not None


# ── _cancel_pending 工具函数 ─────────────────────────────────────


def test_cancel_pending_cancels_unfinished_tasks():
    """S1: 验证 _cancel_pending 工具函数能 cancel 未完成 task 并 gather 等待结束。

    这是 batch SSE 客户端断开时清理 task 的核心保障。
    """
    import web_app

    async def _run():
        slow = [asyncio.create_task(asyncio.sleep(10)) for _ in range(5)]
        await web_app._cancel_pending(slow)
        # cancel 后所有 task 都已 done
        return all(t.done() for t in slow), [t.cancelled() for t in slow]

    all_done, cancelled_flags = asyncio.run(_run())
    assert all_done is True
    assert all(cancelled_flags)


def test_cancel_pending_handles_already_done_tasks():
    """已经完成的 task 不应被重复 cancel 引起异常。"""
    import web_app

    async def _run():
        finished = asyncio.create_task(asyncio.sleep(0))
        await asyncio.sleep(0.01)  # 让它真的完成
        assert finished.done()
        # 也加一个未完成的
        unfinished = asyncio.create_task(asyncio.sleep(10))
        await web_app._cancel_pending([finished, unfinished])
        return finished.done(), unfinished.cancelled()

    finished_done, cancelled = asyncio.run(_run())
    assert finished_done is True
    assert cancelled is True


# ── L8 EMAIL_WEB_TRUST_PROXY ────────────────────────────────────


def _make_request(headers: dict, peer: str = "10.0.0.1"):
    from starlette.requests import Request
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/test",
        "client": (peer, 12345),
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "query_string": b"",
        "root_path": "",
    }
    return Request(scope)


def test_client_ip_ignores_proxy_headers_by_default(client, monkeypatch):
    """默认 TRUST_PROXY=False，不能信任 X-Forwarded-For（公网直连防伪造）。"""
    import web_app
    monkeypatch.setattr(web_app, "TRUST_PROXY", False)
    req = _make_request({
        "x-forwarded-for": "1.2.3.4",
        "x-real-ip": "5.6.7.8",
        "cf-connecting-ip": "9.10.11.12",
    }, peer="10.0.0.1")
    assert web_app._client_ip(req) == "10.0.0.1"


def test_client_ip_uses_cf_connecting_ip_when_trust_on(client, monkeypatch):
    """TRUST_PROXY=True 时优先 CF-Connecting-IP（最不可伪造）。"""
    import web_app
    monkeypatch.setattr(web_app, "TRUST_PROXY", True)
    req = _make_request({
        "x-forwarded-for": "9.9.9.9",
        "cf-connecting-ip": "1.2.3.4",
    })
    assert web_app._client_ip(req) == "1.2.3.4"


def test_client_ip_falls_back_to_xff_when_trust_on(client, monkeypatch):
    """TRUST_PROXY=True 且没有 CF 头时回退到 XFF 第一段。"""
    import web_app
    monkeypatch.setattr(web_app, "TRUST_PROXY", True)
    req = _make_request({"x-forwarded-for": "9.9.9.9, 5.5.5.5"})
    assert web_app._client_ip(req) == "9.9.9.9"


# ── L2 index.html 不存在 ─────────────────────────────────────────


def test_serve_index_returns_503_when_file_missing(client, monkeypatch, tmp_path):
    """index.html 被运维误删时不应让 web 进程 500，而要给出明确 503。"""
    import web_app
    bogus_dir = tmp_path / "no_static"
    bogus_dir.mkdir()
    monkeypatch.setattr(web_app, "STATIC_DIR", str(bogus_dir))
    # 清缓存避免命中之前的 index
    web_app._INDEX_CACHE.update({"path": None, "mtime": 0.0, "html": None, "version": "0"})

    r = client.get("/")
    assert r.status_code == 503
    assert "index.html" in r.text


# ── L5 SSE 响应头 + L6 审计日志（端点集成）─────────────────────


def _import_n_accounts(client, n: int):
    text = "\n".join(f"acc{i}@gmail.com----pw{i}" for i in range(n))
    client.post("/api/accounts/import", json={
        "text": text, "group": "默认分组", "skip_duplicate": False,
    })
    return [a["id"] for a in client.get("/api/accounts").json()]


def test_sse_headers_include_no_buffering(client):
    """L5: batch SSE 响应必须带 X-Accel-Buffering: no、Cache-Control: no-cache。
    防止 nginx / Cloudflare 把流缓冲到关闭，进度条卡 99% 突然完成。"""
    ids = _import_n_accounts(client, 1)

    def fake_check(owner_id, aid):
        return {"email": "x", "status": "正常", "has_aws": False, "found": True}

    with patch("web_app._check_one_sync", side_effect=fake_check):
        with client.stream("POST", "/api/batch/check", json={"account_ids": ids}) as r:
            assert r.status_code == 200
            # 头部检查必须在 stream 关闭前
            assert r.headers.get("X-Accel-Buffering") == "no"
            assert "no-cache" in r.headers.get("Cache-Control", "")
            # 消费完 body 让连接干净关闭
            for _ in r.iter_text():
                pass


def test_audit_for_update_account_group(client):
    ids = _import_n_accounts(client, 1)
    aid = ids[0]
    r = client.put(f"/api/accounts/{aid}/group", json={"group": "新分组A"})
    assert r.status_code == 200
    items = client.get("/api/audit?action=update_account_group").json()["items"]
    assert any(
        i["target"] == str(aid) and "新分组A" in (i["detail"] or "")
        for i in items
    )


def test_audit_for_update_account_remark(client):
    ids = _import_n_accounts(client, 1)
    aid = ids[0]
    r = client.put(f"/api/accounts/{aid}/remark", json={"remark": "测试备注"})
    assert r.status_code == 200
    items = client.get("/api/audit?action=update_account_remark").json()["items"]
    assert any(i["target"] == str(aid) for i in items)


def test_audit_for_mark_read_and_delete_email(client):
    """mark_read / delete_email 通过 mock client 触发审计写入，验证字段完整。"""
    ids = _import_n_accounts(client, 1)
    aid = ids[0]

    class FakeClient:
        def mark_as_read(self, *a, **kw):
            return True, "ok"

        def delete_email(self, *a, **kw):
            return True, "ok"

        def disconnect(self):
            pass

    with patch("web_app.create_client", return_value=FakeClient()):
        r1 = client.post(
            f"/api/accounts/{aid}/emails/mark-read",
            json={"email_id": "msg-1", "folder": "inbox", "is_read": True},
        )
        r2 = client.post(
            f"/api/accounts/{aid}/emails/delete",
            json={"email_id": "msg-1", "folder": "inbox"},
        )
    assert r1.status_code == 200
    assert r2.status_code == 200

    a1 = client.get("/api/audit?action=mark_email_read").json()["items"]
    a2 = client.get("/api/audit?action=delete_email").json()["items"]
    assert any(i["target"] == str(aid) for i in a1)
    assert any(i["target"] == str(aid) for i in a2)


# ── M1 + L7 OAuth refresh_token 不丢失 ──────────────────────────


def _get_state_via_auth_url(client) -> str:
    """从 ``/api/oauth2/auth-url`` 拿到本轮颁发的 state。

    新版 ``/api/oauth2/exchange`` 强制校验 state（CSRF 防御），测试要先
    走 auth-url 拿到合法 state，再把它拼到 redirect_url 里提交。
    """
    from urllib.parse import parse_qs, urlparse

    r = client.get("/api/oauth2/auth-url")
    assert r.status_code == 200, r.text
    auth_url = r.json()["url"]
    qs = parse_qs(urlparse(auth_url).query)
    assert "state" in qs and qs["state"][0]
    return qs["state"][0]


def test_oauth_exchange_returns_needs_email_when_email_unfetchable(client):
    """M1: _fetch_oauth2_email 失败时不能丢失已换到的 refresh_token，应返回 needs_email。
    服务端把 refresh_token 暂存到内存，让用户手动补 email 后二次提交。"""
    import web_app

    fake_helper_result = ("fake-client-id", "M.C123-fake-refresh-token", None)
    state = _get_state_via_auth_url(client)

    with patch.object(
        web_app.OAuth2Helper, "exchange_code_for_token",
        return_value=fake_helper_result,
    ), patch("web_app._fetch_oauth2_email", return_value=None):
        r = client.post(
            "/api/oauth2/exchange",
            json={
                "redirect_url": f"https://localhost/?code=abc&state={state}",
                "group": "测试分组",
            },
        )
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False
    assert body.get("needs_email") is True
    # refresh_token 绝不能回显给前端
    assert "refresh_token" not in str(body).lower()
    assert "M.C123-fake-refresh-token" not in str(body)


def test_oauth_exchange_two_phase_completes(client):
    """M1 续：第一次失败暂存，第二次仅传 email 时能从暂存读出 token 完成入库。"""
    import web_app

    fake_helper_result = ("fake-cid", "M.C-fake-rt", None)
    state = _get_state_via_auth_url(client)

    with patch.object(
        web_app.OAuth2Helper, "exchange_code_for_token",
        return_value=fake_helper_result,
    ), patch("web_app._fetch_oauth2_email", return_value=None):
        r1 = client.post(
            "/api/oauth2/exchange",
            json={
                "redirect_url": f"https://localhost/?code=abc&state={state}",
                "group": "g1",
            },
        )
        assert r1.json().get("needs_email") is True

        # 用户手动补 email 后二次提交（不再带 redirect_url）
        r2 = client.post(
            "/api/oauth2/exchange",
            json={"email": "manual@outlook.com"},
        )
    assert r2.status_code == 200
    body = r2.json()
    assert body["success"] is True
    assert body["email"] == "manual@outlook.com"

    accs = client.get("/api/accounts").json()
    found = [a for a in accs if a["email"] == "manual@outlook.com"]
    assert len(found) == 1
    assert found[0]["client_id"] == "fake-cid"
    assert found[0]["group"] == "g1"


def test_oauth_exchange_second_phase_without_pending_returns_error(client):
    """没有暂存 + 仅传 email 应直接报错（不要假装成功）。"""
    r = client.post(
        "/api/oauth2/exchange",
        json={"email": "stranger@outlook.com"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False
    assert "重新点击授权" in body.get("error", "") or "过期" in body.get("error", "")


def test_oauth_exchange_add_account_failure_surfaces_error(client):
    """L7: db.add_account 失败时旧代码静默吞掉，新代码必须把失败原因暴露给前端。"""
    import web_app

    fake_helper_result = ("fake-cid", "M.C-fake-rt", None)
    state = _get_state_via_auth_url(client)

    with patch.object(
        web_app.OAuth2Helper, "exchange_code_for_token",
        return_value=fake_helper_result,
    ), patch(
        "web_app._fetch_oauth2_email", return_value="failure@outlook.com",
    ), patch.object(
        web_app.db, "add_account", return_value=(False, "模拟落库失败"),
    ):
        r = client.post(
            "/api/oauth2/exchange",
            json={"redirect_url": f"https://localhost/?code=abc&state={state}"},
        )
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False
    assert "模拟落库失败" in body.get("error", "")
