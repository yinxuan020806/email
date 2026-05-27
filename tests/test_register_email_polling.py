# -*- coding: utf-8 -*-
"""注册机邮箱接码轮询节奏回归测试。"""

from __future__ import annotations

import sys
from pathlib import Path


CHATGPT_REGISTER_DIR = Path(__file__).resolve().parents[1] / "chatgpt注册机"
if str(CHATGPT_REGISTER_DIR) not in sys.path:
    sys.path.insert(0, str(CHATGPT_REGISTER_DIR))

import email_service  # noqa: E402


def test_external_code_wait_uses_fast_poll_then_returns(monkeypatch):
    """第一轮没拿到验证码时，应按快轮询节奏重查，而不是固定等 5 秒。"""
    account = email_service.ExternalMailAccount(
        address="user@example.com",
        mail_password="pw",
        api_url="https://mail.example.test/api",
        source_line="user@example.com----pw----https://mail.example.test/api",
    )
    batches = [
        [],
        [
            {
                "subject": "Your ChatGPT verification code",
                "body": "Your verification code is 246810.",
                "from": "noreply@tm.openai.com",
                "date": "2026-05-27T00:00:01Z",
            }
        ],
    ]
    calls = {"n": 0}
    sleeps: list[tuple[int, float]] = []

    def fake_fetch(_account):
        idx = min(calls["n"], len(batches) - 1)
        calls["n"] += 1
        return batches[idx]

    def fake_sleep(started_at, timeout, initial_interval=email_service.FAST_POLL_INTERVAL):
        sleeps.append((timeout, initial_interval))

    monkeypatch.setattr(email_service, "fetch_external_emails", fake_fetch)
    monkeypatch.setattr(email_service, "_sleep_before_next_poll", fake_sleep)

    code = email_service.wait_for_external_code(account, timeout=20)

    assert code == "246810"
    assert calls["n"] == 2
    assert sleeps == [(20, 1)]


def test_poll_delay_backs_off_after_fast_window():
    """退避节奏：前段 1 秒，中段 2 秒，后段 5 秒。"""
    now = email_service.time.time()
    assert email_service._next_poll_delay(now) == email_service.FAST_POLL_INTERVAL
    assert email_service._next_poll_delay(now - 30) == email_service.MID_POLL_INTERVAL
    assert email_service._next_poll_delay(now - 90) == email_service.SLOW_POLL_INTERVAL
