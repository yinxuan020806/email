"""
运行环境判断（单一事实源，从 cursor-manager utils/runtime.py 移植）

把散落在多处的 ``IS_HEADLESS_ENV = sys.platform != "win32"`` 收敛到这一份。

"GUI 是否可用" 在本项目里的语义：
- Windows 桌面（``sys.platform == 'win32'``）= 有桌面 / GUI 可用 / 浏览器可见
- 其他（Linux / Docker / WSL 头）= 无桌面 / 必须靠 helper 转发到用户机器执行

约定使用方式::

    from core.runtime import IS_HEADLESS_ENV, HEADLESS_MAILBOX_REJECT_MSG
    if IS_HEADLESS_ENV:
        return {"success": False, "error": HEADLESS_MAILBOX_REJECT_MSG}

仅 helper 进程或本机 Windows 模式下能跑 GUI；server 进程跑在 Linux 容器里
时本变量为 True，所有走 GUI 的 action 必须走 helper 而非本进程。
"""

from __future__ import annotations

import os
import sys

# ─── 运行平台 ──────────────────────────────────────────────────────────────

PLATFORM: str = sys.platform

# 是否运行在"无可见桌面"环境（Linux / Docker 容器 / 服务器）
# 这是项目里所有"能否启动 chromium 让用户手动操作"决策的唯一开关。
IS_HEADLESS_ENV: bool = sys.platform != "win32"

# Linux 容器（更严格：只在生产 Docker 部署里为 True）
IS_LINUX_CONTAINER: bool = sys.platform.startswith("linux")


# ─── 用户拒绝消息（GUI 操作在 headless 环境的统一文案）────────────────────

HEADLESS_REJECT_MSG: str = (
    "服务器/Linux 环境不支持本进程启动浏览器（无可见桌面、Turnstile 无法自动通过）。"
    "请启动本机 Email Helper（Windows EXE）后重试。"
)

HEADLESS_MAILBOX_REJECT_MSG: str = (
    "服务器模式下不支持邮箱浏览器操作（需要您在弹出的浏览器里手动完成 Outlook 安全验证）。"
    "请在本地 Windows 客户端 (Email Helper) 上使用此功能。"
)


# ─── pytest 运行检测（避免后台线程在测试启动时被拉起）─────────────────────

def is_pytest_running() -> bool:
    """pytest 进程内永远返回 True。"""
    if "pytest" in sys.modules:
        return True
    arg0 = (sys.argv[0] or "").lower()
    if "pytest" in arg0:
        return True
    return arg0.endswith("/pytest") or arg0.endswith("\\pytest")


# ─── chromium 二进制定位 ───────────────────────────────────────────────────

def get_chromium_path() -> str | None:
    """返回环境变量里设置的 chromium 可执行文件路径。"""
    return (
        os.environ.get("CHROME_PATH")
        or os.environ.get("BROWSER_PATH")
        or None
    )


__all__ = (
    "PLATFORM",
    "IS_HEADLESS_ENV",
    "IS_LINUX_CONTAINER",
    "HEADLESS_REJECT_MSG",
    "HEADLESS_MAILBOX_REJECT_MSG",
    "is_pytest_running",
    "get_chromium_path",
)
