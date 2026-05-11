"""
注册 / 注销 ``emailhelper://`` URL 协议
=========================================

Windows: 写 HKCU\\Software\\Classes\\emailhelper （不需要管理员权限）。

写在 HKCU 而不是 HKLM 的原因：
- 普通用户就能改，不需要 UAC 提权
- 卸载干净，不影响系统范围

非 Windows 平台：直接 no-op（macOS / Linux 暂不支持）。
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Optional

logger = logging.getLogger(__name__)

PROTOCOL = "emailhelper"
DESCRIPTION = "URL:Email Helper"


def _exe_path() -> str:
    """返回 Helper 可执行文件路径。

    - PyInstaller 打包：sys.executable 就是 .exe
    - 源码运行：用 ``pythonw "main.py"`` 命令
    """
    if getattr(sys, "frozen", False):
        return sys.executable
    main_py = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "main.py",
    )
    pythonw = sys.executable.replace("python.exe", "pythonw.exe")
    if not os.path.exists(pythonw):
        pythonw = sys.executable
    return f'"{pythonw}" "{main_py}"'


def install_url_protocol(exe_override: Optional[str] = None) -> None:
    """注册 emailhelper:// 协议。"""
    if sys.platform != "win32":
        logger.info("[protocol] 非 Windows 平台，跳过 URL 协议注册")
        return
    import winreg

    exe = exe_override or _exe_path()
    if not exe.startswith('"'):
        exe_quoted = f'"{exe}"'
    else:
        exe_quoted = exe
    command = f'{exe_quoted} "%1"'

    base_key = rf"Software\Classes\{PROTOCOL}"
    cmd_key = rf"{base_key}\shell\open\command"

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base_key) as k:
        winreg.SetValue(k, "", winreg.REG_SZ, DESCRIPTION)
        winreg.SetValueEx(k, "URL Protocol", 0, winreg.REG_SZ, "")

    icon_path = exe.split('"')[1] if (
        exe.startswith('"') and exe.count('"') >= 2
    ) else exe
    with winreg.CreateKey(
        winreg.HKEY_CURRENT_USER, base_key + r"\DefaultIcon",
    ) as k:
        winreg.SetValue(k, "", winreg.REG_SZ, f"{icon_path},0")

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, cmd_key) as k:
        winreg.SetValue(k, "", winreg.REG_SZ, command)

    logger.info("[protocol] 已注册 %s:// → %s", PROTOCOL, command)


def uninstall_url_protocol() -> None:
    """删除 emailhelper:// 协议注册。"""
    if sys.platform != "win32":
        return
    import winreg

    paths = [
        rf"Software\Classes\{PROTOCOL}\shell\open\command",
        rf"Software\Classes\{PROTOCOL}\shell\open",
        rf"Software\Classes\{PROTOCOL}\shell",
        rf"Software\Classes\{PROTOCOL}\DefaultIcon",
        rf"Software\Classes\{PROTOCOL}",
    ]
    for path in paths:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        except OSError as e:
            logger.debug("[protocol] 删除 %s: %s", path, e)
    logger.info("[protocol] 已注销 %s://", PROTOCOL)


def is_protocol_installed() -> bool:
    """检测是否已注册。"""
    if sys.platform != "win32":
        return False
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            rf"Software\Classes\{PROTOCOL}\shell\open\command",
        ):
            return True
    except OSError:
        return False


__all__ = (
    "install_url_protocol",
    "uninstall_url_protocol",
    "is_protocol_installed",
    "PROTOCOL",
)
