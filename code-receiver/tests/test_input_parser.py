# -*- coding: utf-8 -*-
"""input_parser.parse_user_input 单元测试。"""

from __future__ import annotations

import pytest

from input_parser import InputParseError, parse_user_input


def test_email_only():
    cred = parse_user_input("alice@outlook.com")
    assert cred.email == "alice@outlook.com"
    assert cred.needs_lookup is True
    assert cred.password == ""
    assert cred.is_oauth is False


def test_email_password():
    cred = parse_user_input("alice@gmail.com----abcd-efgh-ijkl-mnop")
    assert cred.email == "alice@gmail.com"
    assert cred.password == "abcd-efgh-ijkl-mnop"
    assert cred.needs_lookup is False
    assert cred.is_oauth is False


def test_email_password_with_remark():
    """3 段且第 2 段不像 UUID → 视为 (email, password, 备注被忽略)。"""
    cred = parse_user_input("alice@yahoo.com----my-token-xx----组A")
    assert cred.email == "alice@yahoo.com"
    assert cred.password == "my-token-xx"
    assert cred.is_oauth is False


def test_email_oauth_3_segments():
    """3 段且第 2 段是 UUID → 视为 (email, client_id, refresh_token)。"""
    cred = parse_user_input(
        "a@outlook.com----9e5f94bc-e8a4-4e73-b8be-63364c29d753----M.C501_BAY.0.U.-x..."
    )
    assert cred.email == "a@outlook.com"
    assert cred.client_id == "9e5f94bc-e8a4-4e73-b8be-63364c29d753"
    assert cred.refresh_token == "M.C501_BAY.0.U.-x..."
    assert cred.is_oauth is True
    assert cred.password == ""


def test_email_oauth_4_segments():
    cred = parse_user_input(
        "b@outlook.com----password!----9e5f94bc-e8a4-4e73-b8be-63364c29d753----rt-xxx"
    )
    assert cred.email == "b@outlook.com"
    assert cred.password == "password!"
    assert cred.client_id == "9e5f94bc-e8a4-4e73-b8be-63364c29d753"
    assert cred.refresh_token == "rt-xxx"
    assert cred.is_oauth is True


def test_invalid_email():
    with pytest.raises(InputParseError):
        parse_user_input("notanemail")


def test_blank_input():
    with pytest.raises(InputParseError):
        parse_user_input("")


def test_repr_does_not_leak_secret():
    cred = parse_user_input("alice@outlook.com----super-secret")
    s = repr(cred)
    assert "super-secret" not in s
    assert "***" in s
