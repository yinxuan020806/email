# -*- coding: utf-8 -*-
"""input_parser.parse_user_input 单元测试（v8: 仅 email----token 双段）。"""

from __future__ import annotations

import pytest

from input_parser import InputParseError, parse_user_input


def test_email_only_marks_needs_token():
    """仅邮箱：不抛错，但 needs_token=True 让上层回 401 提示补凭证。"""
    cred = parse_user_input("alice@outlook.com")
    assert cred.email == "alice@outlook.com"
    assert cred.needs_token is True
    assert cred.access_token == ""


def test_email_token_two_segments():
    """正常 email----token 双段。"""
    cred = parse_user_input("alice@gmail.com----Ab3xK9")
    assert cred.email == "alice@gmail.com"
    assert cred.access_token == "Ab3xK9"
    assert cred.needs_token is False


def test_email_token_extra_segments_ignored():
    """3 段及以上：第 3 段起忽略（兼容用户粘贴带尾随内容）。"""
    cred = parse_user_input("alice@yahoo.com----Mn8pQ2----some-extra")
    assert cred.email == "alice@yahoo.com"
    assert cred.access_token == "Mn8pQ2"


def test_invalid_email_rejected():
    with pytest.raises(InputParseError):
        parse_user_input("notanemail")


def test_blank_input_rejected():
    with pytest.raises(InputParseError):
        parse_user_input("")


def test_token_with_illegal_chars_rejected():
    """token 含 ``$`` / 空格 / 中文 等非字符集字符 → 立即 InputParseError。"""
    for bad in (
        "alice@x.com----Ab 3xK",     # 含空格
        "alice@x.com----Ab$3xK",     # 含 $
        "alice@x.com----ab3xkO",     # 含 O（歧义字符被排除）
        "alice@x.com----abc",        # 过短（<4）
        "alice@x.com----" + "a" * 17,  # 过长 (>16)
    ):
        with pytest.raises(InputParseError):
            parse_user_input(bad)


def test_repr_does_not_leak_secret():
    cred = parse_user_input("alice@outlook.com----Ab3xK9")
    s = repr(cred)
    assert "Ab3xK9" not in s
    assert "***" in s


def test_empty_token_section_marks_needs_token():
    """email---- 末尾就停（用户漏粘 token）→ needs_token=True 而不是抛错。"""
    cred = parse_user_input("alice@outlook.com----")
    assert cred.email == "alice@outlook.com"
    assert cred.needs_token is True
