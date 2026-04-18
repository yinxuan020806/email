# -*- coding: utf-8 -*-
"""
用户认证：密码哈希、强度校验、用户名规范化。

使用 PBKDF2-HMAC-SHA256（Python 标准库自带，无需额外依赖），
存储格式: ``pbkdf2$<iterations>$<salt_hex>$<hash_hex>``。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Final

PBKDF2_ITERATIONS: Final[int] = 200_000
SALT_BYTES: Final[int] = 16
HASH_BYTES: Final[int] = 32

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.\-]{3,32}$")
MIN_PASSWORD_LEN = 6
MAX_PASSWORD_LEN = 128


def normalize_username(username: str) -> str:
    """统一小写并去掉首尾空白，便于唯一性约束生效。"""
    return (username or "").strip().lower()


def validate_username(username: str) -> tuple[bool, str]:
    """检查用户名格式，返回 (ok, message)。"""
    if not username:
        return False, "用户名不能为空"
    if not USERNAME_PATTERN.match(username):
        return False, "用户名仅支持字母/数字/下划线/点/短横线，长度 3-32"
    return True, ""


def validate_password(password: str) -> tuple[bool, str]:
    """检查密码长度，返回 (ok, message)。"""
    if not password:
        return False, "密码不能为空"
    if len(password) < MIN_PASSWORD_LEN:
        return False, f"密码长度至少 {MIN_PASSWORD_LEN} 位"
    if len(password) > MAX_PASSWORD_LEN:
        return False, f"密码长度不能超过 {MAX_PASSWORD_LEN} 位"
    return True, ""


def hash_password(password: str) -> str:
    """生成密码哈希字符串。"""
    salt = os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=HASH_BYTES
    )
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """常量时间校验密码。"""
    if not password or not stored:
        return False
    try:
        scheme, iterations_s, salt_hex, hash_hex = stored.split("$", 3)
    except ValueError:
        return False
    if scheme != "pbkdf2":
        return False
    try:
        iterations = int(iterations_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, TypeError):
        return False
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected)
    )
    return hmac.compare_digest(digest, expected)
