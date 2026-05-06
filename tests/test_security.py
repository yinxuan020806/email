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


def test_corrupted_key_raises_runtime_error(tmp_path):
    """损坏的 master.key 必须 raise，绝不静默覆盖（覆盖会导致旧密文不可解）。

    新合约（替代旧的"自动重新生成"行为）：
    - 内容非法 → 启动失败，raise RuntimeError
    - 真要重置：调用方手动删除 .master.key 后再启动
    """
    import pytest
    SecretBox._instance = None  # noqa: SLF001
    key_file = tmp_path / ".master.key"
    key_file.write_bytes(b"not-a-valid-key")
    with pytest.raises(RuntimeError, match=r"主密钥.*内容非法"):
        SecretBox(key_path=key_file)
    # 文件应保持原样（损坏内容仍在，便于运维取证）
    assert key_file.read_bytes() == b"not-a-valid-key"


def test_missing_key_auto_generates(tmp_path):
    """不存在的 master.key 仍允许首次自动生成（首次部署 / 全新环境）。"""
    SecretBox._instance = None  # noqa: SLF001
    key_file = tmp_path / ".master.key"
    assert not key_file.exists()
    b = SecretBox(key_path=key_file)
    enc = b.encrypt("v")
    assert b.decrypt(enc) == "v"
    assert key_file.exists()
