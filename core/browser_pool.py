"""
浏览器创建工具（从 cursor-manager utils/browser.py 移植）

- 使用 DrissionPage，反检测能力强
- 含无头浏览器池（headless），减少重复冷启动
- 邮箱场景用 ``create_mailbox_browser()`` 每次全新实例（不池化）

Windows 桌面/源码模式：
- DrissionPage 自己探测 Chrome / Edge 路径
- 浏览器可见，用户能手动完成 Outlook 验证

Linux/Docker 环境（仅守卫服务器，本项目主要给本机 Windows 用）：
- 必须有 xvfb（容器内 entrypoint.sh 启动 Xvfb :99）
- chromium 在 /usr/bin/chromium（apt 包名: chromium）
- BROWSER_PATH 环境变量可显式覆盖

环境变量：
- HEADLESS_POOL_SIZE          (默认 1)   池容量
- HEADLESS_POOL_IDLE_TIMEOUT  (默认 60)  空闲多久后回收（秒）
- BROWSER_PATH                显式 chromium 路径（Linux）
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time

logger = logging.getLogger(__name__)


def _env_int(name: str, default: int, lo: int = 0, hi: int | None = None) -> int:
    """读取环境变量为整数，失败 / 越界则回退到 default。"""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        v = int(raw)
    except ValueError:
        logger.warning("invalid env %s=%r, fallback to %d", name, raw, default)
        return default
    if v < lo:
        return lo
    if hi is not None and v > hi:
        return hi
    return v


def _detect_browser_path() -> str | None:
    """Windows 让 DrissionPage 自己找；Linux 优先 chromium 包。"""
    explicit = os.environ.get("BROWSER_PATH", "").strip()
    if explicit and os.path.exists(explicit):
        return explicit
    if sys.platform == "win32":
        return None
    for candidate in (
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
    ):
        if os.path.exists(candidate):
            return candidate
    return None


_BROWSER_PATH = _detect_browser_path()


_COMMON_ARGS = (
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--window-size=1200,900",
    "--disable-blink-features=AutomationControlled",
)


def _apply_common_options(co):
    """把通用配置 + 浏览器路径应用到 ChromiumOptions。"""
    co.auto_port()
    if _BROWSER_PATH:
        try:
            co.set_browser_path(_BROWSER_PATH)
        except Exception:  # noqa: BLE001
            pass
    for arg in _COMMON_ARGS:
        co.set_argument(arg)
    return co


def create_mailbox_browser():
    """创建邮箱浏览器（每次全新进程，不池化）。

    用户场景：弹出可见浏览器让用户能看到 Outlook 登录过程 / 完成安全验证。
    必须新进程避免和 headless 池实例互相干扰。
    """
    from DrissionPage import Chromium, ChromiumOptions
    co = _apply_common_options(ChromiumOptions())
    return Chromium(co)


def _new_headless_browser():
    from DrissionPage import Chromium, ChromiumOptions
    co = _apply_common_options(ChromiumOptions())
    co.set_argument("--incognito")
    co.set_argument("--headless=new")
    return Chromium(co)


def _quit_browser_safe(browser) -> None:
    """安全 quit，吞掉所有异常 + 记录 debug 日志（不向上传播错误）。"""
    if browser is None:
        return
    try:
        browser.quit()
    except Exception as e:  # noqa: BLE001
        logger.debug("quit browser ignored: %s", e)


def _is_browser_healthy(browser) -> bool:
    """快速检测浏览器是否还活着：能正常拿到 latest_tab 即认为健康。"""
    if browser is None:
        return False
    try:
        _ = browser.latest_tab
        return True
    except Exception:  # noqa: BLE001
        return False


def _reset_browser_for_pool(browser) -> bool:
    """把浏览器恢复到"干净"状态准备入池：清 cookie + 跳到 about:blank。"""
    try:
        tab = browser.latest_tab
        tab.get("about:blank")
        tab.clear_cache()
    except Exception as e:  # noqa: BLE001
        logger.debug("pool reset (about:blank) failed: %s", e)
        return False
    try:
        for ck in browser.latest_tab.cookies():
            browser.latest_tab.set.cookies.remove(ck.get("name", ""))
    except Exception as e:  # noqa: BLE001
        logger.debug("pool reset (cookies) failed (ignored): %s", e)
    return True


class _HeadlessBrowserPool:
    """无头浏览器实例池，空闲超时自动回收。

    设计权衡：容器内总内存有限，单个 chromium headless ~250-400MiB。
    max_size 默认 1 = 单 hot 实例；冷启动 ~1.5s 用户基本无感。
    """

    def __init__(self, max_size: int = 1, idle_timeout: int = 60):
        self._pool: list = []
        self._max_size = max_size
        self._idle_timeout = idle_timeout
        self._lock = threading.Lock()
        self._cleanup_timer = None

    def acquire(self):
        """获取一个池化浏览器实例（不命中则创建新实例）。"""
        expired = self._evict_expired_locked()
        for browser in expired:
            _quit_browser_safe(browser)

        while True:
            popped = self._pop_locked()
            if popped is None:
                return _new_headless_browser()
            if _is_browser_healthy(popped):
                return popped
            _quit_browser_safe(popped)

    def _evict_expired_locked(self) -> list:
        with self._lock:
            now = time.time()
            kept = []
            expired = []
            for browser, ts in self._pool:
                if now - ts > self._idle_timeout:
                    expired.append(browser)
                else:
                    kept.append((browser, ts))
            self._pool = kept
        return expired

    def _pop_locked(self):
        with self._lock:
            if self._pool:
                browser, _ = self._pool.pop()
                return browser
        return None

    def release(self, browser):
        if not _is_browser_healthy(browser):
            _quit_browser_safe(browser)
            return
        if not _reset_browser_for_pool(browser):
            _quit_browser_safe(browser)
            return

        should_quit = False
        with self._lock:
            if len(self._pool) >= self._max_size:
                should_quit = True
            else:
                self._pool.append((browser, time.time()))
                self._schedule_cleanup()

        if should_quit:
            _quit_browser_safe(browser)

    def _schedule_cleanup(self):
        if self._cleanup_timer and self._cleanup_timer.is_alive():
            return
        self._cleanup_timer = threading.Timer(
            self._idle_timeout + 5, self._cleanup,
        )
        self._cleanup_timer.daemon = True
        self._cleanup_timer.start()

    def _cleanup(self):
        for browser in self._evict_expired_locked():
            _quit_browser_safe(browser)

    def close_all(self) -> int:
        """清空池并 quit 所有实例，返回被关闭的实例数（紧急回收用）。"""
        with self._lock:
            old_pool = self._pool
            self._pool = []
        for browser, _ in old_pool:
            _quit_browser_safe(browser)
        return len(old_pool)


_headless_pool = _HeadlessBrowserPool(
    max_size=_env_int("HEADLESS_POOL_SIZE", 1, lo=0, hi=10),
    idle_timeout=_env_int("HEADLESS_POOL_IDLE_TIMEOUT", 60, lo=5, hi=3600),
)


def create_browser(headless: bool = False, **_kwargs):
    """创建浏览器实例。

    - headless=True 从池中获取（减少冷启动），用完需调 release_browser
    - headless=False 每次创建全新实例
    """
    if headless:
        return _headless_pool.acquire()

    from DrissionPage import Chromium, ChromiumOptions
    co = _apply_common_options(ChromiumOptions())
    co.set_argument("--incognito")
    return Chromium(co)


def release_browser(browser):
    """将无头浏览器归还到池中（非无头浏览器直接 quit）。"""
    _headless_pool.release(browser)


def close_all_headless_browsers() -> int:
    """清空 headless 池（紧急回收接口用）。返回被关闭的实例数。"""
    return _headless_pool.close_all()


__all__ = (
    "create_mailbox_browser",
    "create_browser",
    "release_browser",
    "close_all_headless_browsers",
)
