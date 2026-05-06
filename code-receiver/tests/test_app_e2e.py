# -*- coding: utf-8 -*-
"""端到端 (E2E) 测试 — 用 FastAPI TestClient 模拟真实 HTTP 请求。

目标：在不连接真实 IMAP 的情况下，验证：
- 路由全注册、安全响应头生效
- 422 错误不回显 input 凭据
- SSRF 防护拒绝未知邮箱域名
- 公开账号路径走通（mock EmailClient.fetch_emails 返回 cursor 邮件 → 提取出码）
- 限流与失败锁定生效
"""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

import pytest


@pytest.fixture(scope="module")
def app_module():
    """import app 一次，复用整个测试 session（_ensure_master_key_exists 已在 import 时跑过）。"""
    # app 在 import 时会强制要求 EMAIL_DATA_DIR/.master.key 存在；conftest 已把
    # ../data 加到 EMAIL_DATA_DIR 路径上，原项目跑过测试已生成 master.key。
    if "app" in sys.modules:
        del sys.modules["app"]
    import app  # noqa: F401
    return app


@pytest.fixture
def client(app_module):
    from fastapi.testclient import TestClient
    return TestClient(app_module.app)


def test_root_returns_html(client):
    r = client.get("/")
    assert r.status_code == 200
    # 品牌名 / 应用主标题（UI 重新设计后改为"验证码助手"）
    assert "验证码助手" in r.text
    # 关键安全头
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in r.headers.get("Content-Security-Policy", "")


def test_root_no_longer_lists_oauth2_format(client):
    """UI 改版后：底部"支持格式"应当不再展示
    ``email----密码----client_id----refresh_token (Outlook OAuth2)`` 这一项。

    底层 `parse_user_input` 仍然支持 OAuth2 4 段输入（向后兼容），
    只是不再在 UI 上把这种格式当作明确的"使用方式"暴露给终端用户。
    """
    text = client.get("/").text
    assert "OAuth2" not in text, "UI 不应再显式提及 OAuth2 输入格式"
    assert "refresh_token" not in text, "UI 不应再展示 refresh_token 字段名"


def test_root_no_longer_includes_security_disclaimer(client):
    """UI 改版后：底部"安全说明：您输入的密码/授权码..."段已删除。"""
    text = client.get("/").text
    assert "安全说明" not in text
    assert "授权码仅在本次请求" not in text


def test_app_js_blocks_javascript_protocol_in_link(client):
    """前端必须有 ``safeHttpUrl`` 之类的协议白名单，防止后端被攻破或邮件被
    篡改时返回 ``link: 'javascript:alert(1)'`` 触发存储型 XSS。
    """
    r = client.get("/static/app.js")
    assert r.status_code == 200
    body = r.text
    assert "safeHttpUrl" in body, "app.js 应导出 safeHttpUrl 协议白名单函数"
    # 校验函数体中明确白名单 http(s)，且把它用在 link 渲染前
    assert "https?:" in body, "safeHttpUrl 应仅放行 http(s) 协议"
    assert "safeHttpUrl(data.link)" in body, (
        "渲染 link 之前必须先经过 safeHttpUrl 过滤，禁止 a.href = data.link"
    )


def test_healthz_ok(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["db"] is True
    assert body["rules"] is True


def test_lookup_validation_does_not_leak_input(client):
    """422 响应不能回显用户的 input 字段（我们覆盖了默认 handler）。"""
    secret_pwd = "MySuperSecretPasswordXYZ"
    r = client.post(
        "/api/lookup",
        json={
            "input": f"alice@outlook.com----{secret_pwd}",
            "category": "github",  # 非法分类，会触发 422
        },
    )
    assert r.status_code == 422
    body_text = r.text
    # 关键安全：响应里**绝不能**含有用户原始密码
    assert secret_pwd not in body_text, f"422 响应泄漏了原始密码！body={body_text}"
    body = r.json()
    assert "errors" in body or "detail" in body


def test_lookup_rejects_byo_input_with_dashes(client):
    """byo 路径已下线：含 ---- 的输入一律在 pydantic 阶段（422）就被拦下，
    不会进入 lookup 函数体（也不会消耗限流配额或触发 IMAP 连接）。
    """
    secret_pwd = "AnotherSecretPwd123"
    r = client.post(
        "/api/lookup",
        json={
            "input": f"alice@outlook.com----{secret_pwd}",
            "category": "cursor",  # 合法分类，单纯 input 校验失败
        },
    )
    assert r.status_code == 422
    # 关键安全：响应里**绝不能**含有用户原始密码
    assert secret_pwd not in r.text, "422 响应泄漏了密码字段"
    body = r.json()
    # 字段错误信息应明确说明只支持邮箱
    err_text = " ".join(
        e.get("msg", "") for e in body.get("errors", []) if isinstance(e, dict)
    ) + body.get("detail", "")
    assert "邮箱" in err_text or "扩展格式" in err_text


def test_lookup_rejects_byo_unknown_domain(client):
    """未知域名 + 含 ---- → 仍然 422 在 pydantic 阶段拦下（连 SSRF 检查都不需要）。"""
    r = client.post(
        "/api/lookup",
        json={
            "input": "victim@internal-server.local----whatever",
            "category": "cursor",
        },
    )
    assert r.status_code == 422


def test_lookup_email_only_not_public_returns_404(client):
    """仅输入邮箱，但该邮箱不是 public 账号 → 404。"""
    r = client.post(
        "/api/lookup",
        json={"input": "stranger@outlook.com", "category": "cursor"},
    )
    # 404 因为查 DB 找不到 is_public=1 + 属于 xiaoxuan 的账号
    assert r.status_code == 404
    body = r.json()
    assert "白名单" in body.get("detail", "") or "未授权" in body.get("detail", "") \
        or "未公开" in body.get("detail", "")  # 兼容旧文案


def _make_fake_account(email: str = "owner@outlook.com"):
    """构造一个假的 Account 对象用来 mock 公开账号查询。"""
    from core.models import Account
    return Account(
        id=1,
        email=email,
        password="placeholder",
        group_name="cursor",
        status="正常",
        account_type="普通",
        imap_server="outlook.office365.com",
        imap_port=993,
        smtp_server="smtp.office365.com",
        smtp_port=587,
        client_id=None,
        refresh_token=None,
        created_at="2026-05-05T00:00:00",
        last_check=None,
        has_aws_code=0,
        remark="",
    )


def test_lookup_success_path_public_cursor(app_module, client):
    """公开账号路径：mock DB lookup_public_account 返回 cursor 账号 + IMAP 拉到验证码邮件。"""
    fake_mails = [
        {
            "sender": "no-reply@cursor.sh",
            "from": "no-reply@cursor.sh",
            "subject": "Your Cursor verification code",
            "body": "Hi,\n\nYour Cursor verification code is 248135.\n",
            "preview": "Your Cursor verification code is 248135.",
            "date": "2026-05-05T12:00:00",
        }
    ]

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def fetch_emails(self, *a, **kw):
            return fake_mails, "ok"

        def disconnect(self):
            pass

    fake_account = _make_fake_account("alice@outlook.com")

    with patch.object(app_module, "EmailClient", FakeClient), \
         patch.object(app_module._db, "lookup_public_account", return_value=fake_account), \
         patch.object(app_module._db, "incr_query_count", return_value=True):
        r = client.post(
            "/api/lookup",
            json={"input": "alice@outlook.com", "category": "cursor"},
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["found"] is True
    assert body["code"] == "248135"
    assert body["category"] == "cursor"
    # byo 已下线，source 永远是 public
    assert body["source"] == "public"
    assert body["sender"].startswith("no-reply@cursor.sh")


def test_lookup_success_path_openai_link(app_module, client):
    """OpenAI Magic-Link 提取（包括 SafeLinks unwrap）路径。"""
    safelinked = (
        "https://nam11.safelinks.protection.outlook.com/?url=https%3A%2F%2Fauth.openai.com"
        "%2Flog-in%2Fidentifier%3Fsession%3Dxyz&data=z"
    )
    fake_mails = [
        {
            "sender": "noreply@tm.openai.com",
            "from": "noreply@tm.openai.com",
            "subject": "Log in to OpenAI",
            "body": f"Click here to sign in: {safelinked}",
            "preview": "Click here to sign in",
            "date": "2026-05-05T12:00:00",
        }
    ]

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def fetch_emails(self, *a, **kw):
            return fake_mails, "ok"

        def disconnect(self):
            pass

    fake_account = _make_fake_account("bob@outlook.com")

    with patch.object(app_module, "EmailClient", FakeClient), \
         patch.object(app_module._db, "lookup_public_account", return_value=fake_account), \
         patch.object(app_module._db, "incr_query_count", return_value=True):
        r = client.post(
            "/api/lookup",
            json={"input": "bob@outlook.com", "category": "openai"},
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["found"] is True
    assert body["link"] is not None
    # SafeLinks 必须被 unwrap
    assert body["link"].startswith("https://auth.openai.com/log-in/identifier")


def test_security_headers_on_api(client):
    """API 路由也应带 5 项安全头。"""
    r = client.post(
        "/api/lookup",
        json={"input": "stranger@outlook.com", "category": "cursor"},
    )
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("Referrer-Policy") == "no-referrer"


def test_client_ip_prefers_cloudflare_when_proxy_trusted(app_module, monkeypatch):
    """TRUST_PROXY=True 时，CF-Connecting-IP 应该优先于 X-Forwarded-For 被采纳。"""
    monkeypatch.setattr(app_module, "TRUST_PROXY", True)
    from starlette.requests import Request

    def make_req(headers: dict, peer: str = "10.0.0.1"):
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/lookup",
            "client": (peer, 12345),
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
            "query_string": b"",
            "root_path": "",
        }
        return Request(scope)

    # 1) CF-Connecting-IP 优先
    ip = app_module._client_ip(
        make_req({
            "cf-connecting-ip": "1.2.3.4",
            "x-forwarded-for": "9.9.9.9, 5.5.5.5",
            "x-real-ip": "8.8.8.8",
        })
    )
    assert ip == "1.2.3.4"

    # 2) 没有 cf-connecting-ip 时回退 XFF 首段
    ip = app_module._client_ip(
        make_req({"x-forwarded-for": "9.9.9.9, 5.5.5.5", "x-real-ip": "8.8.8.8"})
    )
    assert ip == "9.9.9.9"


def test_client_ip_ignores_proxy_headers_when_trust_off(app_module, monkeypatch):
    """TRUST_PROXY=False 时，绝对不能信任任何反代头（防止伪造 IP 绕限流）。"""
    monkeypatch.setattr(app_module, "TRUST_PROXY", False)
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/lookup",
        "client": ("10.0.0.1", 12345),
        "headers": [
            (b"cf-connecting-ip", b"1.2.3.4"),
            (b"x-forwarded-for", b"9.9.9.9"),
            (b"x-real-ip", b"8.8.8.8"),
        ],
        "query_string": b"",
        "root_path": "",
    }
    ip = app_module._client_ip(Request(scope))
    assert ip == "10.0.0.1", "TRUST_PROXY=False 必须只用 client.host，绝不能信任伪造头"
