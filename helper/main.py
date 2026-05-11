"""
Helper 入口
=================

支持的命令行形式::

    # 1. 用 emailhelper:// URL 协议拉起（首次绑定）
    EmailHelper.exe "emailhelper://connect?token=abc&server=http://1.2.3.4:8000"

    # 2. 平时开机自启
    EmailHelper.exe --silent

    # 3. 调试 / 手动指定
    EmailHelper.exe --token abc --server http://127.0.0.1:8000

    # 4. 注册 / 注销 URL 协议（不启动主循环）
    EmailHelper.exe --install-protocol
    EmailHelper.exe --uninstall-protocol

    # 5. 开机自启相关
    EmailHelper.exe --enable-autostart
    EmailHelper.exe --disable-autostart
"""
from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import sys
import time
from typing import Optional
from urllib.parse import parse_qs, urlparse

# pyinstaller 打包后通过 --hidden-import 拉依赖；脚本运行时把项目根加 sys.path
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_THIS_DIR)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from helper.config import HelperConfig, DEFAULT_SERVER_URL  # noqa: E402
from helper.client import HelperClient, ConnState           # noqa: E402
from helper import handlers as _handlers                     # noqa: E402

logger = logging.getLogger("helper.main")


# ── 日志初始化 ─────────────────────────────────────────────────


def _init_logging(config: HelperConfig, debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    handlers: list[logging.Handler] = []
    try:
        fh = logging.handlers.RotatingFileHandler(
            config.log_path, maxBytes=1024 * 1024, backupCount=5,
            encoding="utf-8",
        )
        fh.setFormatter(logging.Formatter(fmt))
        handlers.append(fh)
    except OSError as e:
        print(f"无法写日志文件 {config.log_path}: {e}", file=sys.stderr)

    if not getattr(sys, "frozen", False):
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter(fmt))
        handlers.append(sh)

    logging.basicConfig(level=level, handlers=handlers, force=True)


# ── URL 协议解析 ───────────────────────────────────────────────


def _parse_protocol_url(url: str) -> dict:
    """emailhelper://connect?token=abc&server=http://...

    返回 {"action": "connect", "token": "...", "server": "..."}
    """
    if not url or not url.startswith("emailhelper://"):
        return {}
    parsed = urlparse(url)
    action = (parsed.netloc or parsed.path.lstrip("/")) or ""
    qs = parse_qs(parsed.query or "")
    out: dict = {"action": action}
    for k, vs in qs.items():
        if vs:
            out[k] = vs[0]
    return out


# ── 参数解析 ───────────────────────────────────────────────────


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="EmailHelper",
        description="Email Helper —— 本地浏览器自动化客户端",
    )
    p.add_argument("--token", help="覆盖配置里的 token")
    p.add_argument("--server", help="覆盖配置里的 server_url")
    p.add_argument(
        "--silent", action="store_true",
        help="开机自启时用：进系统托盘，无窗口",
    )
    p.add_argument(
        "--no-tray", action="store_true",
        help="不加载系统托盘 UI（headless 调试用）",
    )
    p.add_argument("--debug", action="store_true", help="开启 DEBUG 日志")
    p.add_argument(
        "--install-protocol", action="store_true",
        help="向系统注册 emailhelper:// URL 协议后退出",
    )
    p.add_argument(
        "--uninstall-protocol", action="store_true",
        help="清除 emailhelper:// URL 协议注册后退出",
    )
    p.add_argument(
        "--enable-autostart", action="store_true",
        help="启用开机自启（写注册表 Run 项）后退出",
    )
    p.add_argument(
        "--disable-autostart", action="store_true",
        help="禁用开机自启后退出",
    )
    p.add_argument(
        "--print-config", action="store_true",
        help="打印配置文件路径与内容后退出（调试）",
    )
    p.add_argument(
        "url", nargs="?", default=None,
        help="emailhelper:// URL（被系统拉起时自动传入）",
    )
    return p.parse_args(argv)


# ── 一次性子命令 ───────────────────────────────────────────────


def _run_oneshot(args: argparse.Namespace) -> Optional[int]:
    """处理 --install-protocol 等一次性命令；处理过则返回 exit_code，
    否则返回 None。
    """
    if args.install_protocol:
        from helper import protocol
        protocol.install_url_protocol()
        print("[ok] emailhelper:// URL 协议已注册")
        return 0
    if args.uninstall_protocol:
        from helper import protocol
        protocol.uninstall_url_protocol()
        print("[ok] emailhelper:// URL 协议已注销")
        return 0
    if args.enable_autostart:
        from helper import autostart
        autostart.enable_autostart()
        print("[ok] 开机自启已启用")
        return 0
    if args.disable_autostart:
        from helper import autostart
        autostart.disable_autostart()
        print("[ok] 开机自启已禁用")
        return 0
    if args.print_config:
        cfg = HelperConfig()
        print(f"config dir : {cfg.dir}")
        print(f"config path: {cfg.path}")
        print(f"server_url : {cfg.server_url}")
        print(
            "token      : "
            + (cfg.token[:12] + "..." if cfg.token else "(未设置)"),
        )
        return 0
    return None


# ── 主入口 ─────────────────────────────────────────────────────


def main(argv: Optional[list[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    args = _parse_args(argv)

    code = _run_oneshot(args)
    if code is not None:
        return code

    config = HelperConfig()
    _init_logging(config, debug=args.debug)
    logger.info(
        "Email Helper 启动 v%s pid=%d",
        _import_version(), os.getpid(),
    )

    # URL 协议拉起：解析 URL 把 token / server 写到 config
    if args.url and args.url.startswith("emailhelper://"):
        data = _parse_protocol_url(args.url)
        if data.get("action") == "connect":
            tk = data.get("token")
            sv = data.get("server")
            if tk:
                config.token = tk
                logger.info(
                    "[helper] 已通过 URL 协议接收 token (...%s)",
                    tk[-4:] if len(tk) >= 4 else "",
                )
            if sv:
                config.server_url = sv
                logger.info(
                    "[helper] 已通过 URL 协议设置 server=%s", sv,
                )
            try:
                config.save()
            except Exception as e:  # noqa: BLE001
                logger.error("[helper] 保存 config 失败: %s", e)

    # CLI 参数覆盖
    if args.token:
        config.token = args.token
        try:
            config.save()
        except Exception:  # noqa: BLE001
            pass
    if args.server:
        config.server_url = args.server
        try:
            config.save()
        except Exception:  # noqa: BLE001
            pass

    if not config.token:
        logger.error(
            "本地未保存 token。请到 Web 面板「邮箱助手」页面点「🚀 启动助手」，"
            "或用 --token 手工指定。",
        )
        if args.no_tray:
            return 2

    _handlers.install_default_handlers()

    client = HelperClient(
        config=config,
        status_callback=_make_status_logger(),
    )
    client.start()

    if args.no_tray:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("收到 Ctrl+C，准备退出")
        finally:
            client.shutdown()
        return 0

    try:
        from helper.tray import run_tray
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "[helper] 系统托盘加载失败 → 退化到 no-tray 模式: %s", e,
        )
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            client.shutdown()
        return 0

    try:
        run_tray(client, config)
    finally:
        try:
            client.shutdown(join_timeout=2.0)
        except Exception:  # noqa: BLE001
            pass
    try:
        os._exit(0)
    except Exception:  # noqa: BLE001
        return 0
    return 0


def _make_status_logger():
    def _cb(state: ConnState, msg: str) -> None:
        logger.info("[helper] [status] %s %s", state.value, msg)
    return _cb


def _import_version() -> str:
    from helper import __version__
    return __version__


if __name__ == "__main__":
    sys.exit(main())
