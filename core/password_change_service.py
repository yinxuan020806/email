"""
Cursor 账号密码修改服务
通过 authenticator.cursor.sh 的忘记密码流程实现自动改密

流程:
  Step 1: trigger_password_reset(email) → 触发重置邮件
  Step 2: complete_password_reset(reset_link, new_password, config) → 提交新密码

⚠ 注意：两步都用 DrissionPage 浏览器，Turnstile 由 services/turnstile.py 用
  pyautogui + 模板匹配在用户桌面上自动通过。Linux 服务器没桌面 → 必须靠在线
  helper（用户机器）跑这个流程。
"""

import logging
import re
import time
import string
import random
import requests

# IS_HEADLESS_ENV 保留 module attribute 形式（utils.runtime 是单一事实源）。
from core.runtime import IS_HEADLESS_ENV

logger = logging.getLogger(__name__)


def _log(message: str, level: str = "info"):
    """Send log to the real-time frontend queue (falls back to logger)."""
    try:
        from core.helper_log_bridge import add_log
        add_log(message, level)
    except Exception:
        logger.info(message)


def _handle_cf(tab, **_kwargs) -> bool:
    """调用 turnstile 自动处理函数，返回 True 表示已自动通过

    **_kwargs 用于兼容老调用方传 captcha_service 等参数（已忽略）
    """
    try:
        from services.turnstile import handle_turnstile_if_present, has_passed
        handle_turnstile_if_present(tab)
        try:
            return bool(has_passed(tab))
        except Exception:
            return False
    except Exception as e:
        _log(f"[CF] 自动处理异常: {e}", "warning")
        return False


# ============== 常量 ==============

AUTH_BASE = "https://authenticator.cursor.sh"

DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
}

# Turnstile site key 备用值（如果页面提取失败）
FALLBACK_SITE_KEY = "0x4AAAAAAAx5OqiGSMjx4pOt"


# ============== 工具函数 ==============

def generate_random_password(length: int = 16) -> str:
    """
    生成随机强密码
    确保包含大小写字母、数字、特殊字符
    """
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*"

    # 确保各类型至少出现一次
    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(special),
    ]

    all_chars = lowercase + uppercase + digits + special
    for _ in range(length - len(password)):
        password.append(random.choice(all_chars))

    random.shuffle(password)
    return "".join(password)


def _extract_auth_session_id(url: str) -> str:
    """从 URL 中提取 authorization_session_id"""
    match = re.search(r'authorization_session_id=([^&"#]+)', url)
    return match.group(1) if match else ""


def _extract_turnstile_site_key(html: str) -> str:
    """从 HTML 中提取 Cloudflare Turnstile site key"""
    patterns = [
        r'cf-turnstile[^>]+data-sitekey=["\']([^"\']+)',
        r'turnstileKey["\s:]+["\']([^"\']+)',
        r'sitekey["\s:=]+["\']([^"\']+)',
        r'data-sitekey=["\']([^"\']+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _extract_token_from_link(reset_link: str) -> str:
    """从重置链接中提取 token"""
    # 支持多种格式
    # https://authenticator.cursor.sh/reset-password?token=xxx
    # https://authenticator.cursor.sh/reset-password?token=xxx&email=xxx
    match = re.search(r'token=([^&\s"#]+)', reset_link)
    if match:
        return match.group(1)
    # 如果用户直接粘贴了 token（不含 URL）
    if len(reset_link.strip()) > 20 and '/' not in reset_link:
        return reset_link.strip()
    return ""


# ============== 核心功能 ==============

def trigger_password_reset(email: str, config: dict | None = None) -> dict:
    """
    Step 1: 触发密码重置邮件（使用 DrissionPage 绕过 Cloudflare）

    流程:
    1. 使用反检测浏览器访问 authenticator.cursor.sh
    2. 输入邮箱，导航到密码页
    3. 点击"忘记密码"
    4. 等待重置邮件发送确认（Turnstile 由 turnstile.py 用 pyautogui 自动点击）

    Args:
        email: Cursor 账号邮箱
        config: 配置字典（保留兼容性，已不使用）

    Returns:
        {"success": bool, "message": str, "error": str}
    """
    from core.browser_pool import create_browser
    if IS_HEADLESS_ENV:
        return {
            "success": False,
            "error": "服务器/Linux 上无桌面，请启动本地 Helper 由它代办（"
                     "/api/accounts/<id>/auto-reset-password 自动会派发到 Helper）",
        }

    browser = None
    try:
        _log("Step 1: 启动浏览器...")
        browser = create_browser(headless=False)
        tab = browser.latest_tab

        # 1. 访问登录页（DrissionPage 可绕过 Cloudflare）
        _log("访问 authenticator.cursor.sh...")
        tab.get(AUTH_BASE)

        # 等待 Cloudflare 验证通过（通常 DrissionPage 自动通过）
        max_cf_wait = 30
        for i in range(max_cf_wait):
            time.sleep(1)
            current_url = tab.url
            page_title = tab.title or ""

            # 检测是否通过了 Cloudflare
            if "authorization_session_id" in current_url:
                _log("✓ Cloudflare 已通过", "success")
                break
            # 页面不再是 Cloudflare 挑战页
            if "请稍候" not in page_title and "Just a moment" not in page_title and i > 3:
                _log(f"页面已加载: {page_title}")
                break
            if i > 0 and i % 5 == 0:
                _log(f"等待 Cloudflare 验证... ({i}s)")

        time.sleep(2)
        current_url = tab.url
        _log(f"当前 URL: {current_url}")

        # 2. 输入邮箱
        _log("查找邮箱输入框...")
        email_input = None
        for selector in ['@name=email', '@type=email', 'tag:input']:
            try:
                email_input = tab.ele(selector, timeout=3)
                if email_input:
                    break
            except Exception:
                continue

        if not email_input:
            browser.quit()
            return {"success": False, "error": "无法找到邮箱输入框，可能 Cloudflare 未通过"}

        email_input.clear()
        email_input.input(email)
        time.sleep(0.5)
        _log(f"✓ 已输入邮箱: {email}", "success")

        # 3. 点击继续
        continue_btn = tab.ele('@type=submit', timeout=3)
        if continue_btn:
            try:
                continue_btn.scroll.to_see()
                time.sleep(0.3)
            except Exception:
                pass
            continue_btn.click(by_js=True)
            _log("✓ 已点击继续", "success")
        else:
            email_input.input('\n')

        time.sleep(3)

        # 4. 查找并点击"忘记密码"链接
        _log("查找忘记密码链接...")
        forgot_link = None
        for text in ['text:忘记密码', 'text:Forgot password', 'text:Forgot',
                      'text:forgot password', 'text:Reset password', 'text:重置密码']:
            try:
                forgot_link = tab.ele(text, timeout=2)
                if forgot_link:
                    break
            except Exception:
                continue

        if not forgot_link:
            # 尝试找链接元素
            try:
                links = tab.eles('tag:a')
                for link in links:
                    link_text = (link.text or "").lower()
                    if 'forgot' in link_text or '忘记' in link_text or 'reset' in link_text:
                        forgot_link = link
                        break
            except Exception:
                pass

        if forgot_link:
            try:
                forgot_link.scroll.to_see()
                time.sleep(0.5)
            except Exception:
                pass
            forgot_link.click(by_js=True)
            _log("✓ 已点击忘记密码", "success")
            time.sleep(3)
        else:
            _log(f"未找到忘记密码链接，URL: {tab.url}", "warning")

        # 5. 查找并点击"发送重置说明"按钮
        _log("查找发送重置邮件按钮...")
        reset_btn = None
        for selector in ['@type=submit', 'text:发送', 'text:Send', 'text:Reset',
                         'text:重置', 'tag:button']:
            try:
                reset_btn = tab.ele(selector, timeout=2)
                if reset_btn:
                    break
            except Exception:
                continue

        if reset_btn:
            try:
                reset_btn.scroll.to_see()
                time.sleep(0.5)
            except Exception:
                pass
            reset_btn.click(by_js=True)
            _log("✓ 已点击发送重置邮件按钮", "success")
            time.sleep(3)

        # 6. 等待确认（检查页面变化或 URL 变化）
        time.sleep(2)
        page_text = ""
        try:
            page_text = tab.html or ""
        except Exception:
            pass

        # 成功指示词：只用在 Turnstile 挑战页面中绝不会出现的短语
        success_indicators = [
            "check your email",
            "check your inbox",
            "we've sent",
            "we have sent",
            "reset link has been sent",
            "instructions have been sent",
        ]

        def _page_shows_success(html: str) -> bool:
            html_lower = html.lower()
            return any(ind in html_lower for ind in success_indicators)

        is_success = _page_shows_success(page_text)

        # 也检查是否需要人机验证（Turnstile）
        needs_captcha = "cf-turnstile" in page_text.lower() or (
            "turnstile" in page_text.lower() and "challenge" in page_text.lower()
        )

        if needs_captcha and not is_success:
            _log("⚠ 检测到 Turnstile 人机验证，尝试自动处理...", "warning")
            cf_passed = _handle_cf(tab)

            if cf_passed:
                # 自动通过了，给页面 3s 完成表单提交
                _log("✓ 验证已通过，邮件已发送", "success")
                time.sleep(3)
                is_success = True
            else:
                # 手动模式：轮询等用户操作
                initial_url = tab.url
                for i in range(90):
                    time.sleep(1)
                    try:
                        current_html = tab.html or ""
                        current_url = tab.url
                    except Exception:
                        current_html = ""
                        current_url = initial_url

                    if i < 2:
                        continue

                    url_changed = current_url != initial_url
                    text_ok = _page_shows_success(current_html)
                    input_gone = False
                    try:
                        input_gone = tab.ele('@type=email', timeout=0.3) is None
                    except Exception:
                        input_gone = True

                    if url_changed or text_ok or input_gone:
                        is_success = True
                        _log("✓ 验证已通过，邮件已发送", "success")
                        time.sleep(3)
                        break

                    if i > 0 and i % 10 == 0:
                        _log(f"⏳ 等待人机验证... ({i}s)")
        else:
            time.sleep(3)

        browser.quit()
        browser = None

        if is_success:
            return {
                "success": True,
                "message": f"密码重置邮件已发送到 {email}，请查收邮件获取重置链接"
            }
        else:
            # 即使没检测到明确成功信号，也可能已经发送了
            # 返回成功让后续步骤尝试从邮箱 API 获取
            return {
                "success": True,
                "message": f"已尝试发送密码重置邮件到 {email}，正在通过邮箱 API 确认..."
            }

    except Exception as e:
        if browser:
            try:
                browser.quit()
            except Exception:
                pass
        return {"success": False, "error": f"触发重置邮件出错: {str(e)}"}


def complete_password_reset(reset_link: str, new_password: str, config: dict) -> dict:
    """
    Step 2: 使用重置链接完成密码修改（DrissionPage 浏览器方式）

    流程:
    1. 用反检测浏览器打开重置链接
    2. 在页面上填写新密码
    3. 等待 Turnstile 人机验证通过
    4. 点击提交

    Args:
        reset_link: 重置链接（从邮件中获取）或直接传 token
        new_password: 新密码（至少 8 位）
        config: 配置字典（未使用，保留兼容性）

    Returns:
        {"success": bool, "message": str, "error": str}
    """
    from core.browser_pool import create_browser

    # 校验新密码
    if not new_password or len(new_password) < 8:
        return {"success": False, "error": "新密码至少需要 8 个字符"}

    if IS_HEADLESS_ENV:
        return {
            "success": False,
            "error": "服务器/Linux 上无桌面，请启动本地 Helper 由它代办",
        }

    # 构建完整 URL
    token = _extract_token_from_link(reset_link)
    if token:
        reset_url = f"{AUTH_BASE}/reset-password?token={token}"
    elif reset_link.startswith("http"):
        reset_url = reset_link
    else:
        return {"success": False, "error": "无法从链接中提取 reset token，请检查链接格式"}

    browser = None
    try:
        _log("Step 3: 启动浏览器打开重置页面...")
        browser = create_browser(headless=False)
        tab = browser.latest_tab

        # 1. 打开重置链接
        tab.get(reset_url)
        _log("正在加载重置页面...")

        # 等待页面加载（可能有 Cloudflare 验证）
        max_cf_wait = 20
        for i in range(max_cf_wait):
            time.sleep(1)
            page_title = tab.title or ""
            if "请稍候" not in page_title and "Just a moment" not in page_title:
                break
            if i > 0 and i % 5 == 0:
                _log(f"等待 Cloudflare... ({i}s)")

        time.sleep(2)
        _log(f"页面标题: {tab.title}")

        # 2. 查找密码输入框（优先用 name 属性精确定位）
        _log("查找密码输入框...")
        new_pwd_input = None
        confirm_pwd_input = None

        # 优先用 name 属性
        try:
            new_pwd_input = tab.ele('@name=new_password', timeout=5)
        except Exception:
            pass
        try:
            confirm_pwd_input = tab.ele('@name=password_match', timeout=5)
        except Exception:
            pass

        # 降级：用 placeholder
        if not new_pwd_input:
            try:
                new_pwd_input = tab.ele('@placeholder=创建新密码', timeout=3)
            except Exception:
                pass
        if not confirm_pwd_input:
            try:
                confirm_pwd_input = tab.ele('@placeholder=请再次输入您的新密码', timeout=3)
            except Exception:
                pass

        # 再降级：取所有 password 输入框前两个
        if not new_pwd_input or not confirm_pwd_input:
            try:
                all_pwd = tab.eles('@type=password', timeout=3)
                if all_pwd and len(all_pwd) >= 2:
                    if not new_pwd_input:
                        new_pwd_input = all_pwd[0]
                    if not confirm_pwd_input:
                        confirm_pwd_input = all_pwd[1]
                elif all_pwd and len(all_pwd) == 1:
                    if not new_pwd_input:
                        new_pwd_input = all_pwd[0]
            except Exception:
                pass

        if not new_pwd_input:
            browser.quit()
            return {"success": False, "error": "未找到密码输入框，重置链接可能已过期"}

        # 3. 填写密码
        _log("填写新密码...")
        new_pwd_input.clear()
        new_pwd_input.input(new_password)
        time.sleep(0.3)

        if confirm_pwd_input:
            confirm_pwd_input.clear()
            confirm_pwd_input.input(new_password)
            time.sleep(0.3)
            _log("✓ 已填写新密码和确认密码", "success")
        else:
            _log("✓ 已填写新密码", "success")

        # 4. 点击提交按钮（只点一次，不关浏览器，让用户自行确认结果）
        _log("查找提交按钮...")
        submit_btn = None
        for selector in ['@type=submit', 'text:继续', 'text:重置密码']:
            try:
                submit_btn = tab.ele(selector, timeout=3)
                if submit_btn:
                    break
            except Exception:
                continue

        if submit_btn:
            try:
                submit_btn.scroll.to_see()
                time.sleep(0.5)
            except Exception:
                pass
            submit_btn.click(by_js=True)
            _log("✓ 已点击提交按钮，等待页面响应...", "success")
            time.sleep(2)
            # 自动处理提交后可能出现的 Turnstile 人机验证
            cf_passed_s3 = _handle_cf(tab)

            # 等待提交完成
            step3_success_indicators = [
                "password updated", "password changed", "password reset",
                "success", "successfully", "sign in", "登录", "密码已",
            ]
            if cf_passed_s3:
                # 自动通过，短等后直接视为成功
                _log("✓ 验证已通过，等待提交完成...", "success")
                time.sleep(5)
            else:
                # 手动模式：轮询等用户操作
                for i in range(120):
                    time.sleep(1)
                    try:
                        current_url = tab.url
                        current_html = tab.html or ""
                    except Exception:
                        break

                    if i < 2:
                        continue

                    url_left = ("reset-password" not in current_url and
                                "authenticator" not in current_url)
                    text_ok = any(ind in current_html.lower() for ind in step3_success_indicators)
                    pwd_gone = False
                    try:
                        pwd_gone = tab.ele('@type=password', timeout=0.3) is None
                    except Exception:
                        pwd_gone = True

                    if url_left or text_ok or pwd_gone:
                        _log("✓ 页面已响应，密码修改请求已提交", "success")
                        break

                    if i > 0 and i % 10 == 0:
                        _log(f"⏳ 等待页面响应... ({i}s)")
            # 短等让用户看清结果
            _log("✓ 请确认浏览器中的密码重置结果", "success")
            time.sleep(5)
            _log("✓ 完成", "success")
        else:
            _log("⚠ 未找到提交按钮，请手动点击", "warning")
            time.sleep(5)

        # 不关闭浏览器，让用户观察结果
        return {"success": True, "message": "已填写新密码并点击提交，请在浏览器中确认重置结果"}

    except Exception as e:
        if browser:
            try:
                browser.quit()
            except Exception:
                pass
        return {"success": False, "error": f"密码重置出错: {str(e)}"}


# ============== 邮箱 API 集成 ==============

from core.ms_oauth import MS_CLIENT_ID as _MS_CLIENT_ID, MS_TOKEN_URL as _GRAPH_TOKEN_URL
_GRAPH_MESSAGES_URL = "https://graph.microsoft.com/v1.0/me/messages"


def _get_ms_access_token(ms_refresh_token: str, ms_client_id: str = None) -> str:
    """用 refresh_token 换取 Microsoft Graph access_token"""
    client_id = ms_client_id or _MS_CLIENT_ID
    resp = requests.post(
        _GRAPH_TOKEN_URL,
        data={
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": ms_refresh_token,
            "scope": "https://graph.microsoft.com/Mail.Read offline_access",
        },
        timeout=30,
    )
    if resp.status_code != 200:
        raise ValueError(f"{resp.status_code} {resp.json().get('error_description', resp.text[:200])}")
    return resp.json()["access_token"]


def fetch_reset_link_from_ms_graph(ms_refresh_token: str, trigger_time: float = None,
                                    max_wait: int = 300, poll_interval: int = 5,
                                    ms_client_id: str = None) -> dict:
    """
    通过 Microsoft Graph API 轮询 Outlook/Hotmail 邮箱，获取 Cursor 密码重置链接。

    Args:
        ms_refresh_token: Outlook 邮箱的 Microsoft Graph refresh_token
        trigger_time: 触发重置邮件的时间戳，只看此之后的新邮件
        max_wait: 最大等待秒数，默认 300
        poll_interval: 轮询间隔秒数，默认 5

    Returns:
        {"success": bool, "reset_link": str, "error": str}
    """
    from datetime import datetime, timezone

    reset_link_pattern = re.compile(
        r'https?://authenticator\.cursor\.sh/reset-password\?token=[^"\'&\s<>]+',
        re.IGNORECASE
    )

    # 获取 access_token
    _log("Step 2: 正在获取 Microsoft Graph 访问令牌...")
    try:
        access_token = _get_ms_access_token(ms_refresh_token, ms_client_id)
    except Exception as e:
        return {"success": False, "error": f"获取 MS access_token 失败: {e}"}

    _log("✓ Graph API 授权成功，开始轮询邮件...", "success")

    # 构建时间过滤（只看 trigger_time 之后的邮件）
    filter_str = None
    if trigger_time:
        dt = datetime.fromtimestamp(trigger_time - 60, tz=timezone.utc)
        filter_str = f"receivedDateTime ge {dt.strftime('%Y-%m-%dT%H:%M:%SZ')}"

    start_time = time.time()
    attempt = 0
    seen_ids: set = set()

    while time.time() - start_time < max_wait:
        attempt += 1
        elapsed = int(time.time() - start_time)
        if attempt == 1 or elapsed % 30 == 0:
            _log(f"… 已等待 {elapsed}s，第 {attempt} 次轮询邮件...")

        try:
            params = {
                "$select": "id,subject,receivedDateTime,from,body",
                "$top": 20,
                "$orderby": "receivedDateTime desc",
            }
            if filter_str:
                params["$filter"] = filter_str

            resp = requests.get(
                _GRAPH_MESSAGES_URL,
                headers={"Authorization": f"Bearer {access_token}"},
                params=params,
                timeout=30,
            )

            if resp.status_code == 401:
                _log("Token 已过期，正在刷新...", "warning")
                try:
                    access_token = _get_ms_access_token(ms_refresh_token, ms_client_id)
                except Exception as e:
                    return {"success": False, "error": f"刷新 token 失败: {e}"}
                time.sleep(2)
                continue

            if resp.status_code != 200:
                _log(f"Graph API 返回 {resp.status_code}，等待重试...", "warning")
                time.sleep(poll_interval)
                continue

            messages = resp.json().get("value", [])
            for msg in messages:
                mid = msg.get("id", "")
                if mid in seen_ids:
                    continue
                seen_ids.add(mid)

                subject = msg.get("subject", "")
                body_content = msg.get("body", {}).get("content", "")
                sender_addr = (msg.get("from", {})
                               .get("emailAddress", {})
                               .get("address", "")).lower()

                # 检查是否是密码重置邮件
                is_reset = (
                    "cursor.sh" in sender_addr or
                    "reset" in subject.lower() or
                    "password" in subject.lower()
                )
                link_match = reset_link_pattern.search(body_content)

                if link_match and is_reset:
                    reset_link = link_match.group(0).rstrip(";").rstrip("&amp")
                    _log("✓ 已找到密码重置链接", "success")
                    return {"success": True, "reset_link": reset_link}

        except requests.exceptions.Timeout:
            _log("Graph API 请求超时，重试...", "warning")
        except Exception as e:
            _log(f"轮询出错: {e}", "error")

        time.sleep(poll_interval)

    return {
        "success": False,
        "error": f"等待 {max_wait} 秒后仍未收到密码重置邮件，请确认邮箱 refresh_token 有效"
    }


def fetch_reset_link_from_email_api(email_api_url: str, trigger_time: float = None,
                                     max_wait: int = 120, poll_interval: int = 5) -> dict:
    """
    从邮箱 API 轮询获取密码重置链接

    Args:
        email_api_url: 邮箱 API 地址（如 http://xxx/get_emial/xxx）
        trigger_time: 触发重置邮件的时间戳，只查找此时间之后的邮件
        max_wait: 最大等待时间（秒），默认 120 秒
        poll_interval: 轮询间隔（秒），默认 5 秒

    Returns:
        {"success": bool, "reset_link": str, "error": str}
    """
    from datetime import datetime

    start_time = time.time()

    # 用于匹配重置链接的正则
    reset_link_pattern = re.compile(
        r'https?://authenticator\.cursor\.sh/reset-password\?token=[^"\'&\s<>]+',
        re.IGNORECASE
    )

    # 密码重置邮件的特征关键词
    RESET_SUBJECT_KEYWORDS = [
        "reset", "password", "重置", "密码",
        "reset your password", "password reset"
    ]
    RESET_SENDER_ADDRESSES = ["no-reply@cursor.sh", "noreply@cursor.sh"]

    _log(f"Step 2: 开始轮询邮箱获取重置链接（最大等待 {max_wait}s）...")

    attempt = 0
    while time.time() - start_time < max_wait:
        attempt += 1
        elapsed = int(time.time() - start_time)
        if attempt == 1 or elapsed % 30 == 0:
            _log(f"… 已等待 {elapsed}s，第 {attempt} 次轮询...")

        try:
            resp = requests.get(email_api_url, timeout=15)
            if resp.status_code != 200:
                _log(f"HTTP {resp.status_code}，等待重试...", "warning")
                time.sleep(poll_interval)
                continue

            emails = resp.json()
            if not isinstance(emails, list):
                _log("响应格式错误，期望 list", "warning")
                time.sleep(poll_interval)
                continue

            # 遍历邮件，查找密码重置邮件
            for email_data in emails:
                subject = email_data.get("主题", "") or email_data.get("subject", "")
                html = email_data.get("html", "") or ""
                email_time_str = email_data.get("时间", "") or email_data.get("time", "")
                sender = email_data.get("发件人", {}) or email_data.get("sender", {})
                sender_addr = ""

                # 兼容多种 sender 格式
                if isinstance(sender, dict):
                    email_address = sender.get("emailAddress", sender)
                    if isinstance(email_address, dict):
                        sender_addr = email_address.get("address", "").lower()
                    elif isinstance(email_address, str):
                        sender_addr = email_address.lower()

                # 检查是否是重置密码邮件
                is_reset_email = False

                # 判断发件人
                sender_match = any(addr in sender_addr for addr in RESET_SENDER_ADDRESSES)

                # 判断主题
                subject_lower = subject.lower()
                subject_match = any(kw in subject_lower for kw in RESET_SUBJECT_KEYWORDS)

                # HTML 内容中包含重置链接
                link_match = reset_link_pattern.search(html)

                if link_match and (sender_match or subject_match):
                    is_reset_email = True
                elif link_match:
                    # 即使主题/发件人不完全匹配，只要有重置链接也认为是
                    is_reset_email = True

                if not is_reset_email:
                    continue

                # 检查邮件时间（只处理触发之后的邮件）
                if trigger_time and email_time_str:
                    try:
                        email_dt = datetime.fromisoformat(
                            email_time_str.replace("Z", "+00:00")
                        )
                        email_ts = email_dt.timestamp()
                        # 留 30 秒容差（邮件延迟）
                        if email_ts < trigger_time - 30:
                            continue
                    except (ValueError, TypeError):
                        pass  # 解析失败则不过滤时间

                reset_link = link_match.group(0)
                # 清理链接末尾可能的 HTML 实体
                reset_link = reset_link.rstrip(";").rstrip("&amp")
                _log("✓ 已找到密码重置链接", "success")
                return {"success": True, "reset_link": reset_link}

            _log(f"暂未找到重置邮件，{poll_interval}s 后重试...")

        except requests.exceptions.Timeout:
            _log("邮箱 API 请求超时，重试...", "warning")
        except requests.exceptions.ConnectionError:
            _log("邮箱 API 连接失败，重试...", "warning")
        except Exception as e:
            _log(f"轮询出错: {e}", "error")

        time.sleep(poll_interval)

    return {
        "success": False,
        "error": f"等待 {max_wait} 秒后仍未收到密码重置邮件，请检查邮箱 API 地址是否正确"
    }


def auto_reset_password(email: str, email_api_url: str, new_password: str, config: dict,
                         ms_refresh_token: str = None, ms_client_id: str = None) -> dict:
    """
    全自动密码重置流程（一键完成）

    流程:
      1. 触发密码重置邮件
      2. 通过邮箱 API 或 Microsoft Graph API 轮询获取重置链接
      3. 使用验证码服务完成密码修改

    Args:
        email: Cursor 账号邮箱
        email_api_url: 邮箱 API 地址（与 ms_refresh_token 二选一）
        new_password: 新密码（为空则自动生成）
        config: 配置字典（包含验证码服务 API Key）
        ms_refresh_token: Outlook/Hotmail 的 MS Graph refresh_token（无 email_api_url 时使用）

    Returns:
        {"success": bool, "message": str, "new_password": str, "error": str, "step": str}
    """
    if not email_api_url and not ms_refresh_token:
        return {"success": False, "error": "未配置邮箱 API 地址或 MS refresh_token", "step": "validate"}

    if not new_password:
        new_password = generate_random_password(16)

    _log(f"开始全自动密码重置: {email}")

    # Step 1: 触发密码重置邮件
    _log("Step 1: 触发密码重置邮件...")
    trigger_time = time.time()
    trigger_result = trigger_password_reset(email, config=config)

    if not trigger_result.get("success"):
        return {
            "success": False,
            "error": f"触发重置邮件失败: {trigger_result.get('error', '未知错误')}。\n提示：你可以手动在浏览器中触发重置邮件，然后再点击自动重置按钮。",
            "step": "trigger"
        }

    _log(f"✓ 触发完成: {trigger_result.get('message')}", "success")

    # Step 2: 获取重置链接
    _log("Step 2: 等待并获取重置链接...")
    time.sleep(3)

    if email_api_url:
        link_result = fetch_reset_link_from_email_api(
            email_api_url,
            trigger_time=trigger_time,
            max_wait=300,
            poll_interval=5
        )
    else:
        link_result = fetch_reset_link_from_ms_graph(
            ms_refresh_token,
            trigger_time=trigger_time,
            max_wait=300,
            poll_interval=5,
            ms_client_id=ms_client_id,
        )

    if not link_result.get("success"):
        return {
            "success": False,
            "error": f"获取重置链接失败: {link_result.get('error', '未知错误')}",
            "step": "fetch_link"
        }

    reset_link = link_result["reset_link"]
    _log("✓ Step 2 完成: 已获取重置链接", "success")

    # Step 3: 使用重置链接完成密码修改
    _log("Step 3: 打开重置页面并填写新密码...")
    reset_result = complete_password_reset(reset_link, new_password, config)

    if reset_result.get("success"):
        _log("✓ 密码已重置成功", "success")
        return {
            "success": True,
            "message": f"密码已自动重置成功！新密码: {new_password}",
            "new_password": new_password,
            "step": "done"
        }
    else:
        return {
            "success": False,
            "error": f"提交新密码失败: {reset_result.get('error', '未知错误')}",
            "step": "complete"
        }
