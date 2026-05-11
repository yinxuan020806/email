"""
开机自启（Windows）
=====================

写注册表 ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run``，
键名 ``EmailHelper``，值 ``"<exe>" --silent``。

不写 HKLM 是为了不需要管理员权限。
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Optional

logger = logging.getLogger(__name__)

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "EmailHelper"


def _exe_command() -> str:
    """返回写入注册表的完整命令。"""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --silent'
    main_py = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "main.py",
    )
    pythonw = sys.executable.replace("python.exe", "pythonw.exe")
    if not os.path.exists(pythonw):
        pythonw = sys.executable
    return f'"{pythonw}" "{main_py}" --silent'


def enable_autostart(command_override: Optional[str] = None) -> None:
    if sys.platform != "win32":
        logger.info("[autostart] 非 Windows，跳过")
        return
    import winreg

    cmd = command_override or _exe_command()
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        RUN_KEY,
        0,
        winreg.KEY_SET_VALUE,
    ) as k:
        winreg.SetValueEx(k, VALUE_NAME, 0, winreg.REG_SZ, cmd)
    logger.info("[autostart] 已启用：%s", cmd)


def disable_autostart() -> None:
    if sys.platform != "win32":
        return
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            RUN_KEY,
            0,
            winreg.KEY_SET_VALUE,
        ) as k:
            winreg.DeleteValue(k, VALUE_NAME)
        logger.info("[autostart] 已禁用")
    except OSError as e:
        logger.debug("[autostart] 禁用失败 / 未启用: %s", e)


def is_autostart_enabled() -> bool:
    if sys.platform != "win32":
        return False
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_QUERY_VALUE,
        ) as k:
            value, _ = winreg.QueryValueEx(k, VALUE_NAME)
            return bool(value)
    except OSError:
        return False


__all__ = (
    "enable_autostart", "disable_autostart", "is_autostart_enabled",
    "RUN_KEY", "VALUE_NAME",
)
