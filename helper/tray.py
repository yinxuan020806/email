"""
系统托盘 UI（pystray）
========================

托盘图标颜色随连接状态变化：
- 🟢 绿  CONNECTED
- 🟡 黄  CONNECTING（重连中）
- 🔴 红  OFFLINE

菜单：
- 版本 / 状态（不可点）
- 查看状态…   弹一个 tk dialog 显示完整信息
- 打开日志    用系统默认应用打开 helper.log
- 打开配置目录
- 打开 Web 面板
- 自启切换
- ───
- 退出
"""
from __future__ import annotations

import logging
import os
import sys
import threading
import webbrowser
from typing import Optional

from helper import __version__
from helper.client import HelperClient, ConnState
from helper.config import HelperConfig

logger = logging.getLogger(__name__)


def _make_color_icon(color: tuple[int, int, int], size: int = 64):
    """生成一个圆形彩色图标（运行时画，省一份资源文件）。"""
    from PIL import Image, ImageDraw  # pystray 依赖 Pillow，必装
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pad = max(2, size // 16)
    d.ellipse((0, 0, size - 1, size - 1), fill=(20, 20, 30, 255))
    d.ellipse(
        (pad, pad, size - 1 - pad, size - 1 - pad),
        fill=color + (255,),
    )
    return img


def _icon_for(state: ConnState):
    if state == ConnState.CONNECTED:
        return _make_color_icon((46, 204, 113))   # 绿
    if state == ConnState.CONNECTING:
        return _make_color_icon((241, 196, 15))   # 黄
    return _make_color_icon((231, 76, 60))         # 红


def _state_label(state: ConnState) -> str:
    return {
        ConnState.CONNECTED: "已连接",
        ConnState.CONNECTING: "重连中",
        ConnState.OFFLINE: "离线",
    }.get(state, "未知")


def _show_status_dialog(client: HelperClient, config: HelperConfig) -> None:
    """打开一个简单 tk 弹窗显示完整状态。在新线程里跑（避免阻塞 pystray）。"""
    def _do():
        try:
            import tkinter as tk
            from tkinter import scrolledtext
        except Exception as e:  # noqa: BLE001
            logger.warning("[tray] tkinter 不可用: %s", e)
            return

        info_lines = [
            f"版本     : v{__version__}",
            f"状态     : {_state_label(client.state)}",
            f"helper_id: {client.helper_id or '(未注册)'}",
            f"server   : {config.server_url}",
            (
                "token    : "
                + (
                    (config.token[:12] + "..." + config.token[-4:])
                    if config.token else "(未设置)"
                )
            ),
            f"配置文件 : {config.path}",
            f"日志文件 : {config.log_path}",
        ]
        if client.last_error:
            info_lines.append(f"最近错误 : {client.last_error}")

        root = tk.Tk()
        root.title("Email Helper")
        root.geometry("560x320")
        try:
            root.attributes("-topmost", True)
        except Exception:  # noqa: BLE001
            pass

        txt = scrolledtext.ScrolledText(
            root, font=("Consolas", 10), wrap="word",
        )
        txt.pack(fill="both", expand=True, padx=10, pady=10)
        txt.insert("1.0", "\n".join(info_lines))
        txt.configure(state="disabled")

        btn_frame = tk.Frame(root)
        btn_frame.pack(fill="x", padx=10, pady=(0, 10))
        tk.Button(
            btn_frame, text="打开日志",
            command=lambda: _open_path(config.log_path),
        ).pack(side="left", padx=4)
        tk.Button(
            btn_frame, text="打开配置目录",
            command=lambda: _open_path(config.dir),
        ).pack(side="left", padx=4)
        tk.Button(
            btn_frame, text="关闭", command=root.destroy,
        ).pack(side="right")

        root.mainloop()

    threading.Thread(target=_do, daemon=True).start()


def _open_path(path: str) -> None:
    """跨平台打开文件 / 目录。"""
    try:
        if not os.path.exists(path):
            return
        if sys.platform == "win32":
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            import subprocess
            subprocess.Popen(["open", path])
        else:
            import subprocess
            subprocess.Popen(["xdg-open", path])
    except Exception as e:  # noqa: BLE001
        logger.warning("[tray] 打开 %s 失败: %s", path, e)


def run_tray(client: HelperClient, config: HelperConfig) -> None:
    """主线程阻塞调用：构造 pystray.Icon 并运行其 mainloop。"""
    import pystray
    from helper import autostart, protocol

    icon: Optional["pystray.Icon"] = None

    def _on_status(*_):
        _show_status_dialog(client, config)

    def _on_open_log(*_):
        _open_path(config.log_path)

    def _on_open_dir(*_):
        _open_path(config.dir)

    def _on_open_panel(*_):
        try:
            webbrowser.open(config.server_url)
        except Exception:  # noqa: BLE001
            pass

    def _on_toggle_autostart(_, __):
        if autostart.is_autostart_enabled():
            autostart.disable_autostart()
        else:
            autostart.enable_autostart()
        if icon:
            icon.update_menu()

    def _toggle_autostart_checked(_):
        return autostart.is_autostart_enabled()

    def _on_install_protocol(*_):
        protocol.install_url_protocol()

    def _on_quit(*_):
        def _bg_shutdown():
            try:
                client.shutdown(join_timeout=2.0)
            except Exception:  # noqa: BLE001
                pass
            try:
                os._exit(0)
            except Exception:  # noqa: BLE001
                pass

        threading.Thread(
            target=_bg_shutdown, daemon=True, name="helper-quit",
        ).start()
        try:
            if icon:
                icon.visible = False
                icon.stop()
        except Exception:  # noqa: BLE001
            pass

    menu = pystray.Menu(
        pystray.MenuItem(f"版本：v{__version__}", None, enabled=False),
        pystray.MenuItem(
            lambda _: f"状态：{_state_label(client.state)}",
            None, enabled=False,
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("查看状态…", _on_status),
        pystray.MenuItem("打开日志", _on_open_log),
        pystray.MenuItem("打开配置目录", _on_open_dir),
        pystray.MenuItem("打开 Web 面板", _on_open_panel),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            "开机自启",
            _on_toggle_autostart,
            checked=_toggle_autostart_checked,
        ),
        pystray.MenuItem("注册 URL 协议", _on_install_protocol),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("退出", _on_quit),
    )

    icon = pystray.Icon(
        "EmailHelper",
        _icon_for(client.state),
        f"Email Helper v{__version__} ({_state_label(client.state)})",
        menu=menu,
    )

    def _status_callback(state: ConnState, _msg: str) -> None:
        if not icon:
            return
        try:
            icon.icon = _icon_for(state)
            icon.title = (
                f"Email Helper v{__version__} ({_state_label(state)})"
            )
            icon.update_menu()
        except Exception:  # noqa: BLE001
            pass

    _orig_cb = client._status_cb  # noqa: SLF001

    def _combo(state: ConnState, msg: str) -> None:
        try:
            _orig_cb(state, msg)
        except Exception:  # noqa: BLE001
            pass
        _status_callback(state, msg)

    client._status_cb = _combo  # noqa: SLF001
    _status_callback(client.state, "")

    icon.run()


__all__ = ("run_tray",)
