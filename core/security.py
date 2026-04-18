# -*- coding: utf-8 -*-
"""
本地敏感字段加密工具。

使用 Fernet（AES128-CBC + HMAC-SHA256）对 password / refresh_token 等字段进行
对称加密。主密钥保存在 data/.master.key，首次运行自动生成。

向后兼容：旧库中以明文存储的字段读取时返回原值，写入时自动升级为密文。
"""

from __future__ import annotations

import base64
import logging
import os
import stat
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken


logger = logging.getLogger(__name__)


_TOKEN_PREFIX = "enc::v1::"  # 标识密文，便于识别旧明文数据并迁移


class SecretBox:
    """加解密外观，单例风格。"""

    _instance: Optional["SecretBox"] = None

    def __init__(self, key_path: Path) -> None:
        self.key_path = key_path
        self._key = self._load_or_create_key()
        self._fernet = Fernet(self._key)

    # ── 公共 API ────────────────────────────────────────────────────

    @classmethod
    def instance(cls, key_path: Optional[Path] = None) -> "SecretBox":
        if cls._instance is None:
            if key_path is None:
                raise RuntimeError(
                    "SecretBox 尚未初始化，首次调用必须传入 key_path"
                )
            cls._instance = cls(key_path)
        return cls._instance

    def encrypt(self, plaintext: Optional[str]) -> Optional[str]:
        if plaintext is None or plaintext == "":
            return plaintext
        if self._is_ciphertext(plaintext):
            return plaintext  # 已经是密文，幂等
        token = self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")
        return _TOKEN_PREFIX + token

    def decrypt(self, value: Optional[str]) -> Optional[str]:
        """解密；若是旧的明文则原样返回（兼容迁移期）。"""
        if value is None or value == "":
            return value
        if not self._is_ciphertext(value):
            return value  # 旧明文
        try:
            raw = value[len(_TOKEN_PREFIX):]
            return self._fernet.decrypt(raw.encode("ascii")).decode("utf-8")
        except InvalidToken:
            logger.warning("无法解密字段，返回空字符串。请检查 master.key 是否被替换")
            return ""

    @staticmethod
    def _is_ciphertext(value: str) -> bool:
        return isinstance(value, str) and value.startswith(_TOKEN_PREFIX)

    # ── 内部 ────────────────────────────────────────────────────────

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            data = self.key_path.read_bytes().strip()
            try:
                # 验证一下是合法 Fernet key
                Fernet(data)
                return data
            except (ValueError, base64.binascii.Error):
                logger.error("master.key 内容非法，已重新生成（旧密文将无法解密）")
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        new_key = Fernet.generate_key()
        self.key_path.write_bytes(new_key)
        try:
            # POSIX：仅文件所有者可读写；Windows 上忽略
            os.chmod(self.key_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        logger.info("已生成新的主密钥: %s", self.key_path)
        return new_key
