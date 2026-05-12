"""
辅助邮箱 / IMAP 配置加载器
==========================

从参考项目 cursor-manager ``config.py`` 移植 ``load_config()`` 兜底实现。

本项目里大部分 IMAP 凭据通过 **服务器派发的 imap_config 参数** 透传给
``core.outlook_service.bind_recovery_email`` —— ``load_config()`` 仅作为
fallback 返回默认值或本地 helper 配置目录里的 ``imap_config.json``（如果
用户手动放了）。

调用方一律 ``cfg = load_config()`` 然后 ``imap_config`` 参数覆盖之，因此本
函数即便永远返回默认 dict，业务也能通过 imap_config 透传正常工作。
"""
from __future__ import annotations

import json
import logging
import os
import sys
import threading

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    # ── 辅助邮箱 (recovery email) 相关 ──
    # 默认后缀留空：参考项目 cursor-manager 的默认 ``evuzdnd.cn`` 是作者私有
    # catch-all 域名，用户用了会落到 Cloudflare 524 死域名。本项目强制用户
    # 在 Help 页「✉ 辅助邮箱凭据」卡片里填写**自己的**域名。
    "recovery_alias_suffix": "",
    # QQ IMAP 凭据：用户手动配。helper 模式下也可通过服务器 imap_config 透传覆盖
    "qq_imap_user": "",
    "qq_imap_password": "",
    "qq_imap_host": "imap.qq.com",
    "qq_imap_port": 993,
}

_config_cache: dict | None = None
_config_mtime: float | None = None
_lock = threading.Lock()


def _config_path() -> str:
    """返回 imap_config.json 路径。

    - helper 进程（``getattr(sys, "frozen", False)`` = True 或本地命令行）：
      ``%APPDATA%/EmailHelper/imap_config.json``
    - server 进程：``EMAIL_DATA_DIR/imap_config.json``（如果未设则项目根 data/）
    """
    if getattr(sys, "frozen", False) or "helper" in sys.argv[0].lower():
        # helper 模式
        if sys.platform == "win32":
            base = os.environ.get("APPDATA") or os.path.expanduser("~")
        elif sys.platform == "darwin":
            base = os.path.expanduser("~/Library/Application Support")
        else:
            base = (
                os.environ.get("XDG_CONFIG_HOME")
                or os.path.expanduser("~/.config")
            )
        return os.path.join(base, "EmailHelper", "imap_config.json")
    # server 模式（容器 / 本机 Web 进程）
    data_dir = os.environ.get("EMAIL_DATA_DIR", "").strip()
    if not data_dir:
        # 项目根 data/
        here = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(os.path.dirname(here), "data")
    return os.path.join(data_dir, "imap_config.json")


def _current_mtime(path: str) -> float | None:
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def load_config() -> dict:
    """加载 IMAP / 辅助邮箱配置。

    缓存 + mtime 失效：
    - 文件不存在 → 返回 DEFAULT_CONFIG.copy()
    - 文件存在但缓存里的 mtime 与磁盘一致 → 返回缓存
    - 文件被外部覆写过（ssh / 部署脚本）→ 重新读盘
    """
    global _config_cache, _config_mtime
    path = _config_path()
    cur_mtime = _current_mtime(path)
    with _lock:
        if _config_cache is not None and cur_mtime == _config_mtime:
            return _config_cache

        cfg = DEFAULT_CONFIG.copy()
        if cur_mtime is not None:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                if isinstance(saved, dict):
                    cfg.update(saved)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(
                    "load_config 读取 %s 失败：%s，回退到默认配置",
                    path, e,
                )

        _config_cache = cfg
        _config_mtime = cur_mtime
        return cfg


def save_config(updates: dict) -> dict:
    """合并更新到磁盘配置。仅 server 进程会调用。"""
    global _config_cache, _config_mtime
    path = _config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _lock:
        current = load_config().copy()
        current.update(updates or {})
        with open(path, "w", encoding="utf-8") as f:
            json.dump(current, f, ensure_ascii=False, indent=2)
        _config_cache = current
        _config_mtime = _current_mtime(path)
        return current


__all__ = ("load_config", "save_config", "DEFAULT_CONFIG")
