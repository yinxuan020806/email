"""
Outlook 邮箱管理服务
浏览器池管理、登录、MS OAuth、改密

⚠ 设计前提：这些功能依赖"用户在弹出的浏览器里手动完成 Outlook 安全验证"，
  因此**只能在本地 Windows 桌面上工作**。Linux/Docker 服务器上虽然能在 Xvfb 里启动浏览器，
  但用户根本看不到、没法点 → 一律会卡到超时。
  服务器模式下入口函数会立刻返回明确错误，避免无意义的 5 分钟超时。
"""

import logging
import os
import sys  # 仅用于 sys.frozen（PyInstaller helper EXE 检测）；headless 判断已迁到 utils.runtime
import threading
import time
import tempfile
import hashlib
import requests

from core.browser_pool import create_mailbox_browser
from core.helper_log_bridge import add_log
from core.ms_oauth import MS_CLIENT_ID, MS_REDIRECT_URI, MS_SCOPE, MS_AUTH_URL, MS_TOKEN_URL
# IS_HEADLESS_ENV 保留 module attribute 形式，保持测试 monkeypatch 兼容（同 auth_service）。
from core.runtime import (
    IS_HEADLESS_ENV,
    HEADLESS_MAILBOX_REJECT_MSG as _HEADLESS_REJECT_MSG,
)

logger = logging.getLogger(__name__)

# P1-A：``_mailbox_browsers`` 跨线程读写（open / get_ms_token / change_email_password
# / bind_recovery_email / close_all_mailbox_browsers / _get_or_reconnect_browser
# 等多个入口都会改这个字典）。旧实现完全没锁，并发同 email 调用会让一个
# chromium 实例从 dict 里被 pop 后没人 quit，残留 ~300MB 内存。
# 这里用与 ``auth_service._kept_login_lock`` 同一模式：锁内只 detach dict，
# quit 是 IO 必须放锁外，避免一次 quit hang 把整个 _mailbox_browsers 路径锁死。
_mailbox_browsers: dict = {}
_mailbox_lock = threading.Lock()


def _quit_browser_silent(browser) -> None:
    """安全 quit（吞掉所有异常 + 仅 debug 日志）"""
    if browser is None:
        return
    try:
        browser.quit()
    except Exception as e:
        logger.debug("close mailbox browser ignored: %s", e)


def _take_mailbox_browser(email: str):
    """线程安全地从 _mailbox_browsers 弹出 email 对应的实例（不 quit，由调用方处理）。"""
    with _mailbox_lock:
        return _mailbox_browsers.pop(email, None)


def _store_mailbox_browser(email: str, browser) -> object:
    """线程安全地把 email 对应的浏览器塞进 dict；如果已有旧值，返回供调用方在锁外 quit。"""
    with _mailbox_lock:
        old = _mailbox_browsers.get(email)
        _mailbox_browsers[email] = browser
        return old


def _peek_mailbox_browser(email: str):
    """线程安全地读引用（不弹出）。"""
    with _mailbox_lock:
        return _mailbox_browsers.get(email)


def _drop_mailbox_browser(email: str) -> None:
    """take + 锁外 quit：用在 open_outlook_mailbox 启动前清理同 email 老实例。"""
    prev = _take_mailbox_browser(email)
    _quit_browser_silent(prev)


def close_all_mailbox_browsers() -> dict:
    """关闭所有已打开的邮箱浏览器实例，释放内存。

    锁内只 detach dict、锁外 quit：避免一次 chromium quit hang 锁死整个回收路径。
    """
    with _mailbox_lock:
        snapshot = dict(_mailbox_browsers)
        _mailbox_browsers.clear()

    closed = 0
    failed = 0
    for browser in snapshot.values():
        try:
            browser.quit()
            closed += 1
        except Exception:
            failed += 1
    return {"closed": closed, "failed": failed}


def _get_mailbox_port_file(email: str) -> str:
    email_hash = hashlib.md5(email.encode()).hexdigest()[:8]
    return os.path.join(tempfile.gettempdir(), f"cursor_manager_mailbox_port_{email_hash}.txt")


def _save_mailbox_port(browser, email: str):
    try:
        addr = browser.address
        port = str(addr).split(":")[-1].strip()
        with open(_get_mailbox_port_file(email), "w") as f:
            f.write(port)
    except Exception:
        pass


def _is_port_alive(port: int) -> bool:
    import socket
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def _try_reconnect_mailbox_browser(email: str):
    try:
        port_file = _get_mailbox_port_file(email)
        with open(port_file, "r") as f:
            port = int(f.read().strip())
        if not _is_port_alive(port):
            return None
        from DrissionPage import Chromium, ChromiumOptions
        co = ChromiumOptions()
        co.set_local_port(port)
        browser = Chromium(co)
        _ = browser.latest_tab
        return browser
    except Exception:
        return None


def _get_or_reconnect_browser(email: str) -> tuple:
    """获取已打开的邮箱浏览器，如需要则重连。返回 (browser, error_dict_or_None)。

    P1-A：所有 ``_mailbox_browsers`` 读写过 ``_mailbox_lock``。
    """
    browser = _peek_mailbox_browser(email)

    if browser is None:
        add_log("内存引用丢失，尝试通过端口文件重连浏览器...", "info")
        browser = _try_reconnect_mailbox_browser(email)
        if browser:
            # 重连成功：原子 store；如果同时另一线程刚好也存了一个 displaced，
            # 那一个我们这里 quit 掉避免泄漏。
            displaced = _store_mailbox_browser(email, browser)
            if displaced is not None and displaced is not browser:
                _quit_browser_silent(displaced)
            add_log("✓ 已重连到已打开的邮箱浏览器", "success")
        else:
            return None, {"success": False, "error": "没有已打开的浏览器，请先点击「打开邮箱」"}

    try:
        _ = browser.latest_tab
    except Exception:
        # browser 是死的：原子地把它从 dict 里拿掉（只 pop 当前这个引用，
        # 避免与刚 store 的新实例打架）。
        with _mailbox_lock:
            if _mailbox_browsers.get(email) is browser:
                _mailbox_browsers.pop(email, None)
        return None, {"success": False, "error": "浏览器已关闭，请重新点击「打开邮箱」"}

    return browser, None


def _try_switch_to_password_login(tab) -> bool:
    """
    输入邮箱 + 点完"下一步"后，MS 端可能落在两类"非密码登录优先"页面，
    都需要尽快切到密码登录：

    A) 老链路（账号绑了 Authenticator / 安全密钥）：
       - 默认页是"使用 XXX 登录"，底部有"使用另一种方式登录"
       - 点开后展开列表，里面才有"使用密码"

    B) 新链路（账号已绑辅助邮箱）：
       - **直接**落到"验证你的电子邮件"页：要求把验证码发到 `lt****@xxx.cn`
       - 当前页就有"使用密码" / "Use your password" 链接（form button 形式）

    两条路径互斥但出口都是"使用密码"链接，统一处理。

    返回:
        True  — 至少点到了一次"使用密码"链接
        False — 当前页不需要切换（已是密码登录页）或选择器没匹配上
    """
    clicked = False

    # 先尝试 B) 新链路：当前页可能已经露出"使用密码"链接
    pwd_link_selectors = (
        'text:使用密码',
        'text:Use your password',
        'text=使用密码',
        'text=Use your password',
    )
    for sel in pwd_link_selectors:
        try:
            link = tab.ele(sel, timeout=1)
            if link:
                add_log("检测到「验证你的电子邮件」页，点击「使用密码」绕过验证码登录...", "info")
                try:
                    link.click(by_js=True)
                except Exception:
                    link.click()
                time.sleep(2)
                clicked = True
                break
        except Exception:
            continue

    if clicked:
        return True

    # A) 老链路：需要先展开"使用另一种方式登录"
    try:
        other_way = tab.ele('text:使用另一种方式登录', timeout=2) or tab.ele(
            'text:Sign in another way', timeout=1
        )
        if other_way:
            add_log("检测到密钥/Authenticator 登录页，切换到密码登录...", "info")
            try:
                other_way.click(by_js=True)
            except Exception:
                other_way.click()
            time.sleep(2)
            for sel in pwd_link_selectors:
                try:
                    pwd_option = tab.ele(sel, timeout=2)
                    if pwd_option:
                        try:
                            pwd_option.click(by_js=True)
                        except Exception:
                            pwd_option.click()
                        time.sleep(2)
                        clicked = True
                        break
                except Exception:
                    continue
    except Exception:
        pass

    return clicked


def open_outlook_mailbox(email: str, email_password: str) -> dict:
    """
    登录 Outlook 邮箱并保持浏览器打开，方便用户查看验证码。
    登录成功后将浏览器实例存入字典，供后续 MS Token / 改密使用。
    """
    if IS_HEADLESS_ENV:
        add_log(f"❌ {_HEADLESS_REJECT_MSG}", "error")
        return {"success": False, "error": _HEADLESS_REJECT_MSG}

    # P1-A：原子地把同 email 的旧实例 take 出来后在锁外 quit。
    # 旧实现 ``get + quit + del`` 三步未加锁，并发场景下另一线程可能在 get
    # 与 del 之间又 set 了新值，会被这里 del 掉但不被 quit，造成泄漏。
    _drop_mailbox_browser(email)

    add_log(f"开始登录邮箱: {email}", "info")

    browser = None
    try:
        add_log("正在启动浏览器...", "info")
        browser = create_mailbox_browser()
        tab = browser.latest_tab
        add_log("✓ 浏览器已启动", "success")

        add_log("正在访问 Outlook 登录页面...", "info")
        tab.get("https://login.live.com/")
        time.sleep(2)

        add_log("正在输入邮箱...", "info")
        email_input = None
        for retry in range(3):
            try:
                email_input = tab.ele('@id=usernameEntry', timeout=3)
                if not email_input:
                    email_input = tab.ele('@name=loginfmt', timeout=2)
                if not email_input:
                    email_input = tab.ele('@type=email', timeout=2)
                if email_input:
                    email_input.clear()
                    email_input.input(email)
                    add_log("✓ 邮箱已输入", "success")
                    break
            except Exception as e:
                add_log(f"尝试 {retry + 1}/3: {str(e)}", "warning")
                time.sleep(1)
                email_input = None

        if not email_input:
            add_log("❌ 无法找到邮箱输入框", "error")
            return {"success": False, "error": "无法找到邮箱输入框"}

        time.sleep(0.3)

        add_log("点击下一步...", "info")
        try:
            next_btn = tab.ele('@id=idSIButton9', timeout=2) or tab.ele('@type=submit', timeout=1)
            if next_btn:
                next_btn.click()
        except Exception:
            pass
        time.sleep(2)

        # 接下来 MS 可能跳两种"非密码登录优先"页面，必须主动切回密码登录：
        #   A) 老链路: "使用另一种方式登录" → 弹出 list → "使用密码"
        #   B) 新链路（账号已绑辅助邮箱）: 直接落到 "验证你的电子邮件"
        #      页（要求把验证码发到 lt****@xxx.cn 才能继续），底部带一个
        #      "使用密码" 链接，必须点它绕过验证码登录。
        # 两条路径互斥但都依赖"使用密码"这条链接的存在，集中在一处处理。
        _try_switch_to_password_login(tab)

        add_log("正在查找密码输入框...", "info")
        password_entered = False
        switched_again = False
        for retry in range(15):
            try:
                password_input = tab.ele('@name=passwd', timeout=2) or tab.ele('@type=password', timeout=1)
                if password_input:
                    add_log("正在输入密码...", "info")
                    password_input.clear()
                    password_input.input(email_password)
                    time.sleep(0.3)
                    add_log("✓ 密码已输入", "success")
                    password_entered = True
                    break
                # 第 3 次仍找不到密码框时，兜底再尝试一次"使用密码"切换：
                # MS 在账号已绑辅助邮箱场景偶尔会延迟把"验证你的电子邮件"
                # 页 render 出来，第一次切换时链接还没挂上 DOM。
                if retry == 3 and not switched_again:
                    if _try_switch_to_password_login(tab):
                        switched_again = True
                        time.sleep(1)
            except Exception as e:
                add_log(f"密码输入尝试 {retry + 1}/15: {str(e)}", "warning")
                time.sleep(1)

        if not password_entered:
            add_log("⚠ 自动输入密码失败，浏览器已保持打开", "warning")
            # P1-A：原子 store + 锁外 quit 旧实例（如有），不会泄漏并发场景下
            # 另一线程刚 set 进来的 displaced 浏览器
            displaced = _store_mailbox_browser(email, browser)
            if displaced is not None and displaced is not browser:
                _quit_browser_silent(displaced)
            _save_mailbox_port(browser, email)
            return {"success": True, "message": "浏览器已打开，请手动输入密码完成登录后点击「获取邮箱Token」"}

        add_log("点击登录按钮...", "info")
        try:
            login_btn = tab.ele('@id=idSIButton9', timeout=2) or tab.ele('@type=submit', timeout=1)
            if login_btn:
                login_btn.click()
        except Exception:
            pass
        time.sleep(2)

        try:
            skip_link = tab.ele('text:暂时跳过', timeout=3)
            if skip_link:
                add_log("跳过安全验证...", "info")
                skip_link.click()
                time.sleep(2)
        except Exception:
            pass

        try:
            yes_btn = tab.ele('text=是', timeout=3) or tab.ele('@id=acceptButton', timeout=2)
            if yes_btn:
                add_log("确认保持登录状态...", "info")
                yes_btn.click()
                time.sleep(2)
        except Exception:
            pass

        add_log("正在导航到邮箱收件箱...", "info")
        tab.get("https://outlook.live.com/mail/")
        time.sleep(3)

        for _ in range(10):
            if "outlook.live.com/mail" in tab.url:
                break
            time.sleep(1)

        current_url = tab.url
        add_log(f"当前页面: {current_url}", "info")

        # P1-A：原子 store + 锁外 quit 旧 displaced
        displaced = _store_mailbox_browser(email, browser)
        if displaced is not None and displaced is not browser:
            _quit_browser_silent(displaced)
        _save_mailbox_port(browser, email)

        if "outlook.live.com/mail" in current_url:
            add_log("✅ 邮箱已打开！", "success")
            return {"success": True, "message": "邮箱已打开，请在浏览器中查看验证码邮件"}
        else:
            add_log("⚠ 可能需要手动完成验证", "warning")
            return {"success": True, "message": "浏览器已打开，请手动完成登录后查看邮件"}

    except Exception as e:
        add_log(f"❌ 发生错误: {str(e)}", "error")
        if browser:
            # P1-A：异常路径同样走原子 store
            displaced = _store_mailbox_browser(email, browser)
            if displaced is not None and displaced is not browser:
                _quit_browser_silent(displaced)
            _save_mailbox_port(browser, email)
        return {"success": False, "error": str(e)}


def get_ms_token_from_open_browser(email: str) -> dict:
    """
    在已打开的邮箱浏览器中完成 MS OAuth2 授权，获取 refresh_token。
    """
    import urllib.parse as _up

    if IS_HEADLESS_ENV:
        return {"success": False, "error": _HEADLESS_REJECT_MSG}

    browser, err = _get_or_reconnect_browser(email)
    if err:
        return err

    add_log("在已打开的浏览器中获取 MS Token...", "info")

    auth_params = {
        "client_id": MS_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": MS_REDIRECT_URI,
        "scope": MS_SCOPE,
        "response_mode": "query",
        "login_hint": email,
    }
    oauth_url = MS_AUTH_URL + "?" + _up.urlencode(auth_params)
    add_log("正在新标签页中打开 OAuth2 授权页...", "info")

    oauth_tab = browser.new_tab(oauth_url)
    time.sleep(2)

    for sel in ['@id=idBtn_Accept', 'text:接受', 'text:Accept', '@type=submit']:
        try:
            btn = oauth_tab.ele(sel, timeout=3)
            if btn:
                btn.click()
                add_log("✓ 已点击 OAuth2 授权接受", "success")
                time.sleep(2)
                break
        except Exception:
            pass

    deadline = time.time() + 30
    ms_code = None
    while time.time() < deadline:
        try:
            cur = oauth_tab.url or ""
            if "code=" in cur and ("localhost" in cur or "127.0.0.1" in cur):
                parsed = _up.urlparse(cur)
                params = _up.parse_qs(parsed.query)
                ms_code = params.get("code", [None])[0]
                if ms_code:
                    add_log("✓ 从浏览器 URL 提取到授权码", "info")
                    break
        except Exception:
            pass
        time.sleep(0.5)

    try:
        oauth_tab.close()
    except Exception:
        pass

    if not ms_code:
        return {"success": False, "error": "30 秒内未获取到 OAuth2 授权码，请重试"}

    add_log("授权码已获取，正在换取 Refresh Token...", "info")
    try:
        resp = requests.post(
            MS_TOKEN_URL,
            data={
                "client_id": MS_CLIENT_ID,
                "grant_type": "authorization_code",
                "code": ms_code,
                "redirect_uri": MS_REDIRECT_URI,
                "scope": MS_SCOPE,
            },
            timeout=30,
        )
        if resp.status_code != 200:
            return {"success": False, "error": f"Token 请求失败: {resp.status_code} {resp.text[:200]}"}
        ms_refresh_token = resp.json().get("refresh_token", "")
        if not ms_refresh_token:
            return {"success": False, "error": "响应中无 refresh_token"}
        add_log("✅ MS Refresh Token 已获取！", "success")
        return {"success": True, "ms_refresh_token": ms_refresh_token, "ms_client_id": MS_CLIENT_ID}
    except Exception as e:
        return {"success": False, "error": str(e)}


def change_outlook_email_password(
    email: str,
    email_password: str,
    new_password: str,
    *,
    imap_config: dict | None = None,
) -> dict:
    """
    在已打开的邮箱浏览器中修改 Outlook 邮箱密码。

    ``imap_config``：可选。由服务器派发到本地 Helper 时透传的 QQ IMAP 凭据 +
    recovery_alias_suffix。改密链路里 MS 偶尔会跳到 ``proofs/Add`` 强制要求
    绑定辅助邮箱，本函数会自动接管走一次 ``bind_recovery_email``，那时同样
    需要 IMAP 凭据。helper 进程因为是 PyInstaller frozen 环境，自己的
    ``load_config()`` 拿不到 ``config.json``，必须靠本参数把凭据带进来。
    """
    if IS_HEADLESS_ENV:
        return {"success": False, "error": _HEADLESS_REJECT_MSG}
    if not email_password:
        return {"success": False, "error": "未设置邮箱密码，请先点击「📧」保存邮箱密码"}
    if not new_password or len(new_password) < 8:
        return {"success": False, "error": "新密码至少需要 8 个字符"}

    browser, err = _get_or_reconnect_browser(email)
    if err:
        return err

    add_log(f"在已打开的浏览器中修改邮箱密码: {email}", "info")

    try:
        add_log("正在新标签页中打开改密页面...", "info")
        tab = browser.new_tab("https://account.live.com/password/change")
        time.sleep(4)

        deadline = time.time() + 25
        while time.time() < deadline:
            cur = tab.url or ""
            if "login.live.com" in cur or "login.microsoftonline" in cur:
                break
            if "password/change" in cur and "login" not in cur:
                add_log("✓ 已有有效 session，直接在改密页", "success")
                break
            time.sleep(0.5)

        current_url = tab.url or ""
        add_log(f"当前页面: {current_url[:80]}", "info")

        if "login.live.com" in current_url or "login.microsoftonline" in current_url:
            add_log("⏳ 检测到安全验证页面，请在浏览器中手动完成验证", "warning")

            deadline = time.time() + 300
            reached_change_page = False
            last_log_time = time.time()
            recovery_tried = False
            while time.time() < deadline:
                time.sleep(2)
                try:
                    cur = tab.url or ""
                except Exception:
                    cur = ""

                # 中途如果跳到 proofs/Add 让用户绑辅助邮箱 → 自动接管
                if _is_proofs_add_url(cur) and not recovery_tried:
                    recovery_tried = True
                    add_log("🛡️ 检测到 proofs/Add 安全验证页，自动绑定辅助邮箱...", "info")
                    # 把 imap_config 透传下去，否则 helper 进程内的 load_config()
                    # 在 frozen 模式下读不到 config.json，会误报"未配置 QQ"。
                    bind_result = bind_recovery_email(
                        email,
                        expect_proofs_page=False,
                        imap_config=imap_config,
                    )
                    if not bind_result.get("success"):
                        add_log(
                            f"❌ 自动绑定辅助邮箱失败: {bind_result.get('error', '')}",
                            "error",
                        )
                        try:
                            tab.close()
                        except Exception:
                            pass
                        return {
                            "success": False,
                            "error": f"自动绑定辅助邮箱失败: {bind_result.get('error', '')}",
                        }
                    add_log(
                        f"✅ 已自动绑定辅助邮箱 {bind_result.get('alias_email','')}，继续改密...",
                        "success",
                    )
                    # 主动跳回改密页
                    try:
                        tab.get("https://account.live.com/password/change")
                    except Exception:
                        pass
                    time.sleep(3)
                    continue

                if "account.live.com/password/change" in cur:
                    reached_change_page = True
                    add_log("✓ 验证完成，已到达改密页", "success")
                    break

                if ("login.live.com" not in cur and "login.microsoftonline" not in cur
                        and "microsoftonline" not in cur and not _is_proofs_add_url(cur)):
                    if ("account.live.com" in cur or "account.microsoft.com" in cur
                            or "outlook.live.com" in cur):
                        add_log("验证通过，主动跳转改密页...", "info")
                        tab.get("https://account.live.com/password/change")
                        time.sleep(3)
                        if "account.live.com/password/change" in (tab.url or ""):
                            reached_change_page = True
                            add_log("✓ 已到达改密页", "success")
                        break

                now = time.time()
                if now - last_log_time >= 30:
                    remaining = max(0, int(deadline - now))
                    add_log(f"⏳ 等待安全验证完成... 剩余约 {remaining} 秒", "info")
                    last_log_time = now

            if not reached_change_page:
                final_url = tab.url or ""
                try:
                    tab.close()
                except Exception:
                    pass
                return {"success": False, "error": f"等待超时，未到达改密页，当前页: {final_url[:80]}"}

        add_log("等待改密表单加载...", "info")
        time.sleep(4)

        all_pwd_inputs = []
        form_wait_deadline = time.time() + 45
        form_wait_round = 0
        while time.time() < form_wait_deadline:
            form_wait_round += 1
            try:
                inputs = tab.eles('@type=password', timeout=2)
                if inputs and len(inputs) >= 1:
                    all_pwd_inputs = list(inputs)
                    break
            except Exception:
                pass
            if form_wait_round % 5 == 0:
                remaining = max(0, int(form_wait_deadline - time.time()))
                add_log(f"继续等待改密表单加载... 剩余约 {remaining} 秒", "info")
            time.sleep(1)

        if not all_pwd_inputs:
            page_url = tab.url or ""
            try:
                tab.close()
            except Exception:
                pass
            return {"success": False, "error": f"未找到改密表单（当前页: {page_url[:80]}）"}

        add_log(f"找到 {len(all_pwd_inputs)} 个密码输入框，填写新密码...", "info")

        def _set_input_js(el, value):
            try:
                el.clear()
                el.input(value)
            except Exception:
                pass
            try:
                tab.run_js(
                    "(function(el,val){"
                    "var s=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;"
                    "s.call(el,val);"
                    "el.dispatchEvent(new Event('input',{bubbles:true}));"
                    "el.dispatchEvent(new Event('change',{bubbles:true}));"
                    "})(arguments[0], arguments[1]);",
                    el, value
                )
            except Exception:
                pass

        _set_input_js(all_pwd_inputs[0], new_password)
        time.sleep(0.3)
        if len(all_pwd_inputs) >= 2:
            _set_input_js(all_pwd_inputs[1], new_password)
            time.sleep(0.3)
            add_log("✓ 新密码和确认密码已填写", "success")
        else:
            add_log("✓ 新密码已填写", "success")

        add_log("✅ 新密码已填写完毕，请在浏览器中点击 Save 按钮完成提交", "success")
        return {"success": True, "message": "新密码已填写完毕，请在浏览器中手动点击 Save 按钮提交"}

    except Exception as e:
        add_log(f"❌ 改密出错: {str(e)}", "error")
        return {"success": False, "error": f"改密出错: {str(e)}"}


# ============================================================
# 辅助邮箱（recovery email）相关：
#   1) derive_recovery_alias —— 把 outlook 用户名末尾数字去掉 + 加配置后缀
#   2) _fetch_recovery_code_from_qq —— 用 IMAP 从 catch-all QQ 邮箱里
#      按收件人精确匹配，捞 MS 发来的 6/7 位验证码
#   3) bind_recovery_email —— 在已打开的邮箱浏览器（停在 proofs/Add 页）里
#      自动完成"填备用邮箱 → 下一步 → 填验证码 → 下一步"
# ============================================================

import re as _re_mod


def derive_recovery_alias(outlook_email: str, suffix: str = "evuzdnd.cn") -> str:
    """
    根据 outlook 邮箱用户名生成辅助邮箱（去掉末尾连续数字 + @suffix）。

    例：mtcscvcffk2900@outlook.com → mtcscvcffk@evuzdnd.cn
    """
    suffix = (suffix or "evuzdnd.cn").lstrip("@")
    local = (outlook_email or "").split("@", 1)[0]
    if not local:
        raise ValueError(f"无法从 {outlook_email!r} 解析出用户名")
    stripped = _re_mod.sub(r"\d+$", "", local)
    if not stripped:
        # 全是数字的极端情况，原样返回避免空 local part
        stripped = local
    return f"{stripped}@{suffix}"


def _fetch_recovery_code_from_qq(
    alias_email: str,
    trigger_time: float,
    qq_user: str,
    qq_password: str,
    qq_host: str = "imap.qq.com",
    qq_port: int = 993,
    max_wait: int = 180,
    poll_interval: int = 5,
) -> dict:
    """
    通过 IMAP 从 catch-all QQ 邮箱里，按"收件人 = alias_email"过滤
    Microsoft 发来的安全验证邮件，提取 6~8 位数字验证码。

    Returns: {"success": bool, "code": str, "error": str}
    """
    import imaplib
    import email as _email_mod
    from email.header import decode_header
    from datetime import datetime, timezone

    if not qq_user or not qq_password:
        is_frozen = bool(getattr(sys, "frozen", False))
        msg = (
            "本机 Helper 没拿到 QQ IMAP 凭据（多半是 Helper EXE < 0.1.6 太旧）；"
            "请到 Web 面板「📥 下载」按钮重新安装最新版 CursorManagerHelper.exe"
            if is_frozen
            else "未配置 QQ 邮箱或授权码（请在 ⚙ 设置里填）"
        )
        return {"success": False, "error": msg}

    add_log(
        f"开始 IMAP 轮询 {qq_user}\u2192{alias_email} 的 MS 验证码（最多 {max_wait}s）",
        "info",
    )

    code_re = _re_mod.compile(r"\b(\d{6,8})\b")
    alias_lower = (alias_email or "").lower()
    start = time.time()
    attempt = 0
    seen_uids: set = set()

    # IMAP SINCE 必须用英文月份缩写，避免中文 Windows locale 把 %b 翻成 "4月"
    _MON_ABBR = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

    while time.time() - start < max_wait:
        attempt += 1
        elapsed = int(time.time() - start)
        if attempt == 1 or elapsed % 30 == 0:
            add_log(f"\u2026 \u7b49\u5f85 {elapsed}s\uff0c\u7b2c {attempt} \u6b21\u8f6e\u8be2 IMAP\u2026", "info")

        imap = None
        try:
            imap = imaplib.IMAP4_SSL(qq_host, qq_port, timeout=20)
            imap.login(qq_user, qq_password)
            imap.select("INBOX")

            # MS 一般 30 秒内到，搜索最近 1 天即可
            since = datetime.fromtimestamp(trigger_time - 600, tz=timezone.utc)
            since_str = f"{since.day:02d}-{_MON_ABBR[since.month - 1]}-{since.year}"
            typ, data = imap.search(None, f'(SINCE "{since_str}")')
            if typ != "OK":
                add_log(f"IMAP search 失败: {typ}", "warning")
                time.sleep(poll_interval)
                continue

            uids = data[0].split() if data and data[0] else []
            # 倒序看最新邮件
            for uid in reversed(uids[-50:]):
                if uid in seen_uids:
                    continue
                seen_uids.add(uid)

                typ, msg_data = imap.fetch(uid, "(RFC822)")
                if typ != "OK" or not msg_data or not msg_data[0]:
                    continue
                raw = msg_data[0][1]
                if not raw:
                    continue
                msg = _email_mod.message_from_bytes(raw)

                # 邮件时间
                date_hdr = msg.get("Date") or ""
                try:
                    dt = _email_mod.utils.parsedate_to_datetime(date_hdr)
                    if dt and dt.timestamp() < trigger_time - 300:
                        continue
                except Exception:
                    pass

                # 收件人字段聚合（catch-all 转发可能不保留 To，所以多挖几个 header）
                to_blob = " ".join(filter(None, [
                    msg.get("To") or "",
                    msg.get("Delivered-To") or "",
                    msg.get("X-Original-To") or "",
                    msg.get("Envelope-To") or "",
                    msg.get("X-Forwarded-To") or "",
                ])).lower()

                # 主题
                raw_subject = msg.get("Subject") or ""
                subject_parts = decode_header(raw_subject)
                subject = "".join([
                    (b.decode(c or "utf-8", errors="ignore") if isinstance(b, bytes) else b)
                    for b, c in subject_parts
                ]).lower()

                # 正文
                body_text = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        ctype = part.get_content_type()
                        if ctype in ("text/plain", "text/html"):
                            try:
                                payload = part.get_payload(decode=True) or b""
                                charset = part.get_content_charset() or "utf-8"
                                body_text += payload.decode(charset, errors="ignore")
                            except Exception:
                                continue
                else:
                    try:
                        payload = msg.get_payload(decode=True) or b""
                        charset = msg.get_content_charset() or "utf-8"
                        body_text = payload.decode(charset, errors="ignore")
                    except Exception:
                        body_text = ""

                blob_lower = (subject + "\n" + body_text).lower()

                # 收件人匹配：headers 找不到时回退到正文里搜 alias
                # （MS 邮件正文一般会写"to mtcscvcffk@evuzdnd.cn"或 alias）
                if alias_lower:
                    if alias_lower not in to_blob and alias_lower not in blob_lower:
                        continue

                # 必须是"安全/验证/Microsoft account/security code"相关，否则跳过
                ms_keywords = (
                    "microsoft", "security code", "verification code", "安全代码",
                    "验证代码", "security info", "verify your email",
                    "microsoft 帐户", "microsoft account", "代码",
                )
                if not any(k in blob_lower for k in ms_keywords):
                    continue

                m = code_re.search(subject + "\n" + body_text)
                if m:
                    code = m.group(1)
                    add_log(f"\u2705 \u5df2\u4ece QQ \u90ae\u7bb1\u63d0\u53d6\u9a8c\u8bc1\u7801: {code}", "success")
                    return {"success": True, "code": code}

        except imaplib.IMAP4.error as e:
            add_log(f"IMAP \u9519\u8bef: {e}\uff08\u8bf7\u68c0\u67e5\u6388\u6743\u7801\uff09", "error")
            return {"success": False, "error": f"IMAP 登录失败: {e}"}
        except Exception as e:
            add_log(f"IMAP \u8f6e\u8be2\u5f02\u5e38: {e}", "warning")
        finally:
            try:
                if imap is not None:
                    imap.logout()
            except Exception:
                pass

        time.sleep(poll_interval)

    return {
        "success": False,
        "error": f"等待 {max_wait}s 仍未在 QQ 邮箱里找到 {alias_email} 的 MS 验证码",
    }


def _is_proofs_add_url(url: str) -> bool:
    if not url:
        return False
    u = url.lower()
    return "account.live.com/proofs/add" in u or "proofs/add" in u


def _fill_input_robust(tab, el, value: str):
    """同时用 DrissionPage 和原生 setter 触发，兼容 React 控件"""
    try:
        el.clear()
        el.input(value)
    except Exception:
        pass
    try:
        tab.run_js(
            "(function(el,val){"
            "var s=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;"
            "s.call(el,val);"
            "el.dispatchEvent(new Event('input',{bubbles:true}));"
            "el.dispatchEvent(new Event('change',{bubbles:true}));"
            "})(arguments[0], arguments[1]);",
            el, value,
        )
    except Exception:
        pass


def bind_recovery_email(
    email: str,
    alias_suffix: str = "",
    alias_email: str = "",
    expect_proofs_page: bool = True,
    *,
    imap_config: dict | None = None,
) -> dict:
    """
    在已打开的邮箱浏览器中绑定备用邮箱（recovery email）。

    参数:
        email: outlook 账号邮箱（用于定位浏览器实例 + 推算别名）
        alias_suffix: 可选后缀（默认走 config.recovery_alias_suffix）
        alias_email: 直接传完整辅助邮箱（优先级高于 alias_suffix 推算）
        expect_proofs_page: 是否要求当前必须在 proofs/Add 页
            （False 时由调用方在改密链路里直接调用，不再主动跳转）
        imap_config: 可选。由服务器派发到 *本地 Helper* 时传入 QQ IMAP /
            recovery 后缀，避免 Helper 进程内 ``load_config()`` 读到打包环境
            里的空 ``config.json``。同机直接调用（无 Helper）可省略，沿用本机 ``config.json``。

    步骤:
      1. 找到 proofs/Add 页（或主动跳转）
      2. 填备用邮箱 (#EmailAddress)，点下一步
      3. IMAP 从 QQ 收件箱读取验证码并填入
      4. 再点下一步直至离开 proofs/Add
    """
    if IS_HEADLESS_ENV:
        return {"success": False, "error": _HEADLESS_REJECT_MSG}

    from core.config_loader import load_config

    cfg = load_config()
    if imap_config:
        merged = dict(cfg)
        for k in (
            "recovery_alias_suffix",
            "qq_imap_user",
            "qq_imap_password",
            "qq_imap_host",
            "qq_imap_port",
        ):
            if k in imap_config:
                merged[k] = imap_config[k]
        cfg = merged

    suffix = (alias_suffix or cfg.get("recovery_alias_suffix") or "evuzdnd.cn").lstrip("@")

    if not alias_email:
        try:
            alias_email = derive_recovery_alias(email, suffix)
        except Exception as e:
            return {"success": False, "error": f"推算辅助邮箱失败: {e}"}

    qq_user = cfg.get("qq_imap_user") or ""
    qq_password = cfg.get("qq_imap_password") or ""
    qq_host = cfg.get("qq_imap_host") or "imap.qq.com"
    try:
        qq_port = int(cfg.get("qq_imap_port") or 993)
    except (TypeError, ValueError):
        qq_port = 993
    if not qq_user or not qq_password:
        # PyInstaller frozen 环境下 sys.frozen 为 True：本进程是 helper EXE，
        # 它的 load_config() 永远拿不到 web 后端的 config.json。这种情况下给出
        # 与"用户去设置里填"完全不同的修复指引；并区分"调用方根本没传
        # imap_config"和"传了但里面就是空的"两种子场景，便于排查。
        is_frozen = bool(getattr(sys, "frozen", False))
        if is_frozen and imap_config is None:
            # 调用方（多半是 change_outlook_email_password 自动接管 proofs/Add）
            # 根本没把 imap_config 透传过来 —— 服务端路由可能也没派发 IMAP 凭据。
            err_msg = (
                "本机 Helper 没拿到 QQ IMAP 凭据：调用方未透传 imap_config。"
                "如果你刚走的是「修改邮箱密码」中途自动跳到 proofs/Add 的链路，"
                "请确认 Web 服务器版本 ≥0.1.8（旧版改密路由不会派发 IMAP）；"
                "也确认本机 Helper EXE 版本 ≥0.1.8。"
            )
        elif is_frozen:
            err_msg = (
                "本机 Helper 收到了 imap_config 但里面 qq_imap_user/password 是空的。"
                "请检查 Web 面板 ⚙ 设置 → 辅助邮箱 (recovery email) 区块两个字段是否填好；"
                "或确认浏览器里点「保存」时弹了 toast 提示成功。"
            )
        else:
            err_msg = (
                "未配置 QQ 邮箱地址或授权码（请在 ⚙ 设置中填写 qq_imap_user / qq_imap_password）"
            )
        return {"success": False, "error": err_msg}

    browser, err = _get_or_reconnect_browser(email)
    if err:
        return err

    add_log(f"准备给 {email} 绑定辅助邮箱: {alias_email}（后缀 @{suffix}）", "info")

    try:
        # 1. 定位/打开 proofs/Add 页 ------------------------------------
        proofs_url_default = (
            "https://account.live.com/proofs/Add?mkt=ZH-CN&uiflavor=web"
        )

        target_tab = None
        try:
            for t in (browser.tabs or [browser.latest_tab]):
                cur = (t.url or "").lower()
                if _is_proofs_add_url(cur):
                    target_tab = t
                    break
        except Exception:
            pass

        if target_tab is None:
            if expect_proofs_page:
                add_log("当前没有 proofs/Add 标签页，新开一个并自动跳转...", "info")
            target_tab = browser.new_tab(proofs_url_default)

        tab = target_tab
        try:
            tab.set.activate()
        except Exception:
            pass

        # 等页面稳定
        time.sleep(2)
        for _ in range(20):
            cur = (tab.url or "").lower()
            if _is_proofs_add_url(cur):
                break
            time.sleep(1)
        if not _is_proofs_add_url(tab.url or ""):
            return {
                "success": False,
                "error": f"当前页不是 proofs/Add（{(tab.url or '')[:120]}），请先让浏览器停在该页",
            }

        # 2. 切下拉到「备用电子邮件地址」（不是必须，默认通常就是它）
        try:
            tab.run_js(
                "var s=document.querySelector('select[name=\"proofType\"], select#proofType, select');"
                "if(s){"
                "  for(var i=0;i<s.options.length;i++){"
                "    var t=(s.options[i].text||'')+' '+(s.options[i].value||'');"
                "    if(t.indexOf('email')>=0||t.indexOf('Email')>=0||t.indexOf('备用')>=0||t.indexOf('邮件')>=0){"
                "      s.selectedIndex=i; s.dispatchEvent(new Event('change',{bubbles:true})); break;"
                "    }"
                "  }"
                "}"
            )
        except Exception:
            pass
        time.sleep(0.5)

        # 3. 找邮箱输入框 + 填值
        email_input = None
        for sel in ['@id=EmailAddress', '@name=EmailAddress', '@type=email', 'tag:input@type=email']:
            try:
                email_input = tab.ele(sel, timeout=3)
                if email_input:
                    break
            except Exception:
                continue

        if not email_input:
            return {"success": False, "error": "未找到 #EmailAddress 输入框"}

        _fill_input_robust(tab, email_input, alias_email)
        add_log(f"\u2705 \u5df2\u586b\u5165\u5907\u7528\u90ae\u7bb1: {alias_email}", "success")
        time.sleep(0.5)

        # 4. 点击第一个「下一步」
        trigger_ts = time.time()
        next_btn = None
        for sel in ['@id=iNext', '@type=submit', 'css:input.btn-primary[type=submit]']:
            try:
                next_btn = tab.ele(sel, timeout=3)
                if next_btn:
                    break
            except Exception:
                continue
        if not next_btn:
            return {"success": False, "error": "未找到 #iNext 下一步按钮"}
        try:
            next_btn.scroll.to_see()
            time.sleep(0.3)
        except Exception:
            pass
        next_btn.click(by_js=True)
        add_log("\u2705 \u5df2\u70b9\u51fb\u300c\u4e0b\u4e00\u6b65\u300d\uff0cMS \u6b63\u5728\u53d1\u9a8c\u8bc1\u7801\u2026", "success")
        time.sleep(3)

        # 5. 等验证码输入框出现（页面跳到验证码页）
        code_input = None
        deadline_code_input = time.time() + 30
        while time.time() < deadline_code_input:
            for sel in ['@id=iOttText', '@name=iOttText', 'css:input[type=tel][maxlength="16"]']:
                try:
                    code_input = tab.ele(sel, timeout=1)
                    if code_input:
                        break
                except Exception:
                    continue
            if code_input:
                break
            time.sleep(1)

        if not code_input:
            # 30s 还没跳走 → 大概率页面里有 MS 报的错（如"邮箱已被使用"），
            # 把错误提示文本抓出来一起返给前端，方便定位。
            page_err = ""
            try:
                page_err = tab.run_js(
                    "var els=document.querySelectorAll("
                    "'.alert,.error,#iEmailError,#iAjaxError,.text-danger,[role=\"alert\"]');"
                    "var out=[];els.forEach(function(e){var t=(e.innerText||'').trim();"
                    "if(t&&out.indexOf(t)<0)out.push(t);});return out.join(' | ');"
                ) or ""
            except Exception:
                pass
            cur = (tab.url or "")[:120]
            return {
                "success": False,
                "error": f"30s 内未出现验证码输入框（当前页 {cur}）"
                         + (f" | 页面报错: {page_err}" if page_err else ""),
                "alias_email": alias_email,
            }

        # 6. IMAP 拿 MS 验证码
        code_result = _fetch_recovery_code_from_qq(
            alias_email=alias_email,
            trigger_time=trigger_ts,
            qq_user=qq_user,
            qq_password=qq_password,
            qq_host=qq_host,
            qq_port=qq_port,
            max_wait=180,
            poll_interval=5,
        )
        if not code_result.get("success"):
            return {
                "success": False,
                "error": code_result.get("error", "未能从 QQ 邮箱获取验证码"),
                "alias_email": alias_email,
            }
        code = code_result["code"]

        # 7. 填验证码
        _fill_input_robust(tab, code_input, code)
        add_log(f"\u2705 \u5df2\u586b\u5165\u9a8c\u8bc1\u7801 {code}", "success")
        time.sleep(0.5)

        # 8. 点击第二个「下一步」（同 ID iNext，但页面已变）
        submit2 = None
        for sel in ['@id=iNext', '@type=submit', 'css:input.btn-primary[type=submit]']:
            try:
                submit2 = tab.ele(sel, timeout=3)
                if submit2:
                    break
            except Exception:
                continue
        if not submit2:
            return {
                "success": False,
                "error": "未找到验证码页的 #iNext 按钮（验证码已填，请手动点）",
                "alias_email": alias_email,
                "code": code,
            }
        try:
            submit2.scroll.to_see()
            time.sleep(0.3)
        except Exception:
            pass
        submit2.click(by_js=True)
        add_log("\u2705 \u5df2\u63d0\u4ea4\u9a8c\u8bc1\u7801\uff0c\u7b49\u5f85\u9875\u9762\u8df3\u8f6c\u2026", "success")

        # 9. 等页面跳走
        post_deadline = time.time() + 30
        while time.time() < post_deadline:
            cur = (tab.url or "").lower()
            if not _is_proofs_add_url(cur):
                break
            time.sleep(1)

        add_log(f"\u2705 \u8f85\u52a9\u90ae\u7bb1\u7ed1\u5b9a\u6210\u529f: {alias_email}", "success")
        return {
            "success": True,
            "message": f"已成功为 {email} 绑定辅助邮箱 {alias_email}",
            "alias_email": alias_email,
            "code": code,
        }

    except Exception as e:
        add_log(f"\u274c \u7ed1\u5b9a\u8f85\u52a9\u90ae\u7bb1\u51fa\u9519: {e}", "error")
        return {"success": False, "error": f"绑定辅助邮箱出错: {e}", "alias_email": alias_email}


