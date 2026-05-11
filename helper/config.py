"""
Helper 配置：读写 ``%APPDATA%/EmailHelper/config.json``
"""
from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from typing import Any, Optional

logger = logging.getLogger(__name__)


# 默认服务器：本机部署 127.0.0.1:8000；放到公网时用户在「🚀 启动助手」
# 流程中自动通过 URL 协议拿到 server_url，无需手动改。
DEFAULT_SERVER_URL = "http://127.0.0.1:8000"


def _appdata_dir() -> str:
    """返回 Helper 的配置目录。

    - Windows: ``%APPDATA%/EmailHelper``
    - macOS:   ``~/Library/Application Support/EmailHelper``
    - Linux:   ``~/.config/EmailHelper``
    """
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = (
            os.environ.get("XDG_CONFIG_HOME")
            or os.path.expanduser("~/.config")
        )
    path = os.path.join(base, "EmailHelper")
    os.makedirs(path, exist_ok=True)
    return path


class HelperConfig:
    """读写 config.json + 提供日志 / token 路径。"""

    def __init__(self, dir_override: Optional[str] = None):
        self.dir = dir_override or _appdata_dir()
        self.path = os.path.join(self.dir, "config.json")
        self.log_path = os.path.join(self.dir, "helper.log")
        self._data: dict[str, Any] = {}
        self.load()

    # ── 文件读写 ───────────────────────────────────────────────

    def load(self) -> dict:
        if not os.path.exists(self.path):
            self._data = {}
            return self._data
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._data = data
            else:
                logger.warning("config.json 顶层不是 dict，已重置")
                self._data = {}
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("读取 config.json 失败：%s，使用空配置", e)
            self._data = {}
        return self._data

    def save(self) -> None:
        os.makedirs(self.dir, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=self.dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, self.path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # ── 字段访问 ───────────────────────────────────────────────

    @property
    def server_url(self) -> str:
        return (self._data.get("server_url") or DEFAULT_SERVER_URL).rstrip("/")

    @server_url.setter
    def server_url(self, value: str) -> None:
        self._data["server_url"] = (value or "").rstrip("/")

    @property
    def token(self) -> str:
        return str(self._data.get("token") or "")

    @token.setter
    def token(self, value: str) -> None:
        self._data["token"] = (value or "").strip()

    @property
    def version(self) -> str:
        return str(self._data.get("version") or "")

    @version.setter
    def version(self, value: str) -> None:
        self._data["version"] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value

    def update(self, **kwargs: Any) -> None:
        self._data.update(kwargs)


__all__ = ("HelperConfig", "DEFAULT_SERVER_URL")
