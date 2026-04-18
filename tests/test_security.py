# -*- coding: utf-8 -*-
"""SecretBox 加解密测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.security import SecretBox, _TOKEN_PREFIX


@pytest.fixture
def box(tmp_path):
    SecretBox._instance = None  # noqa: SLF001
    b = SecretBox(key_path=tmp_path / ".master.key")
    yield b
    SecretBox._instance = None  # noqa: SLF001


def test_encrypt_then_decrypt_roundtrip(box):
    plain = "Pa$$word-123-中文"
    enc = box.encrypt(plain)
    assert enc != plain
    assert enc.startswith(_TOKEN_PREFIX)
    assert box.decrypt(enc) == plain


def test_encrypt_idempotent(box):
    once = box.encrypt("hello")
    twice = box.encrypt(once)
    assert once == twice  # 不会重复加密


def test_decrypt_plaintext_passthrough(box):
    """旧库中的明文，不带前缀，直接原样返回。"""
    assert box.decrypt("legacy_plain_text") == "legacy_plain_text"


def test_encrypt_empty_and_none(box):
    assert box.encrypt(None) is None
    assert box.encrypt("") == ""
    assert box.decrypt(None) is None
    assert box.decrypt("") == ""


def test_persisted_key_reused(tmp_path):
    SecretBox._instance = None  # noqa: SLF001
    key_file = tmp_path / ".master.key"
    b1 = SecretBox(key_path=key_file)
    secret = b1.encrypt("xyz")
    SecretBox._instance = None  # noqa: SLF001

    b2 = SecretBox(key_path=key_file)
    assert b2.decrypt(secret) == "xyz"


def test_corrupted_key_regenerated(tmp_path, caplog):
    SecretBox._instance = None  # noqa: SLF001
    key_file = tmp_path / ".master.key"
    key_file.write_bytes(b"not-a-valid-key")
    b = SecretBox(key_path=key_file)
    # 应能正常使用（已重新生成新 key）
    enc = b.encrypt("v")
    assert b.decrypt(enc) == "v"
