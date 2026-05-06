# -*- coding: utf-8 -*-
"""本轮硬化修复对应的回归测试。

覆盖修复点：
- M2 ``_sort_mails_newest_first`` 对 RFC 2822 日期 fallback
- M3 ``_AUTH_ERROR_NEEDLES`` 扩充：AADSTS / bad credentials / mailbox 等
- L3 ``LookupRequest.input`` 字段长度上限放宽到 4000
- S2 ``/api/lookup`` parse 失败也走 IP 维度限流计数
- M6 ``get_public_account_for_lookup`` email 查询大小写不敏感
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

import pytest


# ── 单元测试：_sort_mails_newest_first ──────────────────────────────


def test_sort_mails_newest_first_handles_rfc2822_dates():
    """IMAP 后端可能透传 RFC 2822 格式日期字符串（"Mon, 01 Jan 2024 ..."），
    旧实现 fromisoformat 解析失败会把它排到末尾，可能导致取到老验证码。"""
    from app import _sort_mails_newest_first

    mails = [
        {"id": "old", "date": "Mon, 01 Jan 2024 00:00:00 +0000"},
        {"id": "new", "date": "Wed, 06 May 2026 12:00:00 +0000"},
        {"id": "newest", "date": "Wed, 06 May 2026 13:00:00 +0000"},
    ]
    sorted_ = _sort_mails_newest_first(mails)
    assert [m["id"] for m in sorted_] == ["newest", "new", "old"]


def test_sort_mails_newest_first_handles_iso_dates():
    """ISO 8601 仍然能正常排序（不能因为加了 RFC 2822 fallback 就破坏 ISO）。"""
    from app import _sort_mails_newest_first

    mails = [
        {"id": "old", "date": "2024-01-01T00:00:00Z"},
        {"id": "newest", "date": "2026-05-06T13:00:00+00:00"},
    ]
    sorted_ = _sort_mails_newest_first(mails)
    assert [m["id"] for m in sorted_] == ["newest", "old"]


def test_sort_mails_newest_first_mixed_formats():
    """同一批邮件里可能混合 datetime 对象 / ISO 字符串 / RFC 2822 字符串。"""
    from app import _sort_mails_newest_first

    mails = [
        {"id": "rfc", "date": "Mon, 01 Jan 2024 00:00:00 +0000"},
        {"id": "iso", "date": "2025-03-15T10:00:00+00:00"},
        {"id": "dt", "date": datetime(2026, 1, 1, tzinfo=timezone.utc)},
        {"id": "missing", "date": ""},
        {"id": "garbage", "date": "not-a-date"},
    ]
    sorted_ = _sort_mails_newest_first(mails)
    # dt > iso > rfc，garbage / missing 排到最后
    head = [m["id"] for m in sorted_[:3]]
    assert head == ["dt", "iso", "rfc"]
    tail_ids = {m["id"] for m in sorted_[3:]}
    assert tail_ids == {"missing", "garbage"}


# ── 单元测试：_is_auth_failure ────────────────────────────────────


def test_is_auth_failure_detects_aadsts_codes():
    """Microsoft Azure AD STS 的 token / refresh_token 失效错误码必须被识别为认证失败。"""
    from app import _is_auth_failure

    aadsts_messages = (
        "AADSTS50034: The user account does not exist",
        "AADSTS70008: The provided refresh_token is expired",
        "AADSTS50173: The provided grant has been revoked",
        "AADSTS700003: Device used to sign in is unknown",
        "AADSTS700082: The refresh token has expired due to inactivity",
    )
    for msg in aadsts_messages:
        assert _is_auth_failure(msg), f"未识别 AADSTS 错误: {msg}"


def test_is_auth_failure_detects_extra_keywords():
    from app import _is_auth_failure

    assert _is_auth_failure("Bad credentials")
    assert _is_auth_failure("user not found")
    assert _is_auth_failure("Mailbox not enabled for IMAP")
    assert _is_auth_failure("IMAP is disabled")
    assert _is_auth_failure("invalid_request")


def test_is_auth_failure_does_not_overmatch():
    """非认证失败的常见服务异常不能被误判为 auth failure（避免误锁定 IP）。"""
    from app import _is_auth_failure

    assert not _is_auth_failure("Connection timeout to imap.outlook.com")
    assert not _is_auth_failure("502 Bad Gateway from upstream")
    assert not _is_auth_failure("DNS resolution failed")
    assert not _is_auth_failure("")


# ── 单元测试：LookupRequest 字段长度 ───────────────────────────────


def test_lookup_request_accepts_long_input():
    """Microsoft refresh_token 平均 1500-2000 字节 + email + client_id + 分隔符
    可达 2300+，旧 max_length=2000 会切断；放宽到 4000 才能容纳。"""
    from app import LookupRequest

    long_input = "x@outlook.com----pwd----" + ("M" * 3500)
    assert len(long_input) > 2000
    assert len(long_input) < 4000
    # 不抛 ValidationError 即视为通过
    req = LookupRequest(input=long_input, category="cursor")
    assert req.input == long_input


def test_lookup_request_rejects_oversized_input():
    """超出新上限 4000 仍应被拦截。"""
    from pydantic import ValidationError

    from app import LookupRequest

    with pytest.raises(ValidationError):
        LookupRequest(input="x@outlook.com" + ("y" * 5000), category="cursor")


# ── 单元测试：M6 — email 大小写不敏感查询 ────────────────────────


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setenv("EMAIL_DATA_DIR", str(tmp_path))
    if "core.security" in sys.modules:
        sys.modules["core.security"].SecretBox._instance = None
    from database.db_manager import DatabaseManager
    db = DatabaseManager(db_path=str(tmp_path / "emails.db"))
    yield db
    if "core.security" in sys.modules:
        sys.modules["core.security"].SecretBox._instance = None


def test_lookup_email_case_insensitive(fresh_db):
    """账号以 ``User@Outlook.COM`` 入库，前台用 ``user@outlook.com`` 查询也应命中。"""
    db = fresh_db
    uid = db.create_user("xiaoxuan", "fake-pbkdf2")
    assert uid is not None
    ok, _ = db.add_account(
        owner_id=uid, email="User@Outlook.COM", password="x", group="cursor",
    )
    assert ok is True
    acc_id = db.get_account_by_email(uid, "User@Outlook.COM").id
    db.set_account_public(uid, acc_id, is_public=True, allowed_categories=None)

    # 不同大小写形态都能命中
    for variant in (
        "user@outlook.com",
        "USER@OUTLOOK.COM",
        "User@Outlook.COM",
        "useR@OUTLOOK.com",
    ):
        result = db.get_public_account_for_lookup("xiaoxuan", variant, "cursor")
        assert result is not None, f"大小写形态 {variant!r} 未命中公开账号"
