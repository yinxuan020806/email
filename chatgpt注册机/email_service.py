"""邮箱验证码服务。

保留原有 mail.chatgpt.org.uk 临时邮箱函数，并额外支持外部邮箱 API:
账号----邮箱密码----邮箱api
"""
from __future__ import annotations

import argparse
import html
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://mail.chatgpt.org.uk/api"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Origin": "https://mail.chatgpt.org.uk",
    "Referer": "https://mail.chatgpt.org.uk/",
}
DEFAULT_EXTERNAL_MAIL_FILES = ("mail.txt", "邮箱.txt", "mail_accounts.txt", "emails.txt")
VERIFY_CODE_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")
MAIL_API_TIMEOUT = 10
FAST_POLL_SECONDS = 20
MID_POLL_SECONDS = 60
FAST_POLL_INTERVAL = 1.0
MID_POLL_INTERVAL = 2.0
SLOW_POLL_INTERVAL = 5.0


def _next_poll_delay(started_at: float, initial_interval: float = FAST_POLL_INTERVAL) -> float:
    """按等待时长做退避：刚触发验证码时密集查，越往后越省请求。"""
    elapsed = time.time() - started_at
    first_interval = max(0.2, float(initial_interval or FAST_POLL_INTERVAL))
    if elapsed < FAST_POLL_SECONDS:
        return min(first_interval, FAST_POLL_INTERVAL)
    if elapsed < MID_POLL_SECONDS:
        return MID_POLL_INTERVAL
    return SLOW_POLL_INTERVAL


def _sleep_before_next_poll(
    started_at: float, timeout: int, initial_interval: float = FAST_POLL_INTERVAL
) -> None:
    remaining = timeout - (time.time() - started_at)
    if remaining <= 0:
        return
    time.sleep(min(_next_poll_delay(started_at, initial_interval), remaining))


@dataclass(frozen=True)
class ExternalMailAccount:
    """外部邮箱账号配置。

    输入: `账号----邮箱密码----邮箱api` 单行文本。
    输出: 邮箱地址、邮箱密码、邮箱 API 地址和原始行。
    """

    address: str
    mail_password: str
    api_url: str
    source_line: str


def resolve_external_mail_file(mail_file: Optional[str] = None) -> Path:
    """解析邮箱账号文件路径。

    输入: 可选文件路径。
    输出: 绝对路径；未指定时按默认文件名查找。
    """
    base_dir = Path(__file__).parent.resolve()
    if mail_file:
        path = Path(mail_file)
        return path if path.is_absolute() else base_dir / path
    for name in DEFAULT_EXTERNAL_MAIL_FILES:
        path = base_dir / name
        if path.exists():
            return path
    return base_dir / DEFAULT_EXTERNAL_MAIL_FILES[0]


def parse_external_mail_account_line(line: str) -> Optional[ExternalMailAccount]:
    """解析外部邮箱账号行。

    输入: `账号----邮箱密码----邮箱api`。
    输出: ExternalMailAccount；空行和注释返回 None。
    """
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None
    parts = raw.split("----", 2)
    if len(parts) != 3:
        raise ValueError("格式应为: 账号----邮箱密码----邮箱api")
    address, mail_password, api_url = parts
    address = address.strip()
    mail_password = mail_password.strip()
    api_url = api_url.strip()
    if not address or not mail_password or not api_url:
        raise ValueError("账号、邮箱密码、邮箱api 均不能为空")
    if not api_url.lower().startswith(("http://", "https://")):
        raise ValueError("邮箱api 必须是 http/https 地址")
    return ExternalMailAccount(
        address=address,
        mail_password=mail_password,
        api_url=api_url,
        source_line=raw,
    )


def load_external_mail_accounts(mail_file: str | Path | None = None) -> list[ExternalMailAccount]:
    """读取外部邮箱账号文件。

    输入: 邮箱账号文件。
    输出: 可用账号列表；格式错误会抛出 ValueError 并带行号。
    """
    path = resolve_external_mail_file(str(mail_file)) if mail_file else resolve_external_mail_file()
    if not path.exists():
        raise FileNotFoundError(f"邮箱账号文件不存在: {path}")

    accounts: list[ExternalMailAccount] = []
    errors: list[str] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        try:
            account = parse_external_mail_account_line(line)
        except ValueError as exc:
            errors.append(f"第 {line_no} 行: {exc}")
            continue
        if account:
            accounts.append(account)

    if not accounts and errors:
        raise ValueError(errors[0])
    return accounts


def _parse_mail_time(value: Any) -> Optional[datetime]:
    """解析邮件时间字段为 UTC 时间。"""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        seconds = float(value) / 1000 if value > 10_000_000_000 else float(value)
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _message_time(message: dict[str, Any]) -> Optional[datetime]:
    """从常见邮件字段中读取时间。"""
    for key in ("时间", "receivedDateTime", "received_at", "receivedAt", "date", "created_at", "time", "timestamp"):
        parsed = _parse_mail_time(message.get(key))
        if parsed:
            return parsed
    return None


def _iter_external_messages(payload: Any) -> Iterable[dict[str, Any]]:
    """从多种 API 响应壳中迭代邮件对象。"""
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
        return
    if not isinstance(payload, dict):
        return

    message_keys = {"主题", "subject", "title", "内容预览", "bodyPreview", "html", "text", "发件人", "from"}
    if any(key in payload for key in message_keys):
        yield payload
        return

    for key in ("value", "messages", "data", "items", "hydra:member", "result", "list", "emails"):
        if key in payload:
            yield from _iter_external_messages(payload.get(key))


def _value_to_text(value: Any) -> str:
    """把 API 字段安全转成文本。"""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        parts = [_value_to_text(value.get(key)) for key in ("content", "text", "value", "html", "address", "name") if key in value]
        return "\n".join(part for part in parts if part) if parts else json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "\n".join(_value_to_text(item) for item in value)
    return str(value)


def _html_to_visible_text(value: Any) -> str:
    """把 HTML 字段转成可见文本，避免 URL 里的数字干扰。"""
    text = _value_to_text(value)
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return html.unescape(text)


def _external_text_candidates(message: dict[str, Any]) -> list[str]:
    """生成验证码提取候选文本。"""
    fields: list[str] = []
    for key in ("主题", "subject", "title"):
        fields.append(_value_to_text(message.get(key)))
    for key in (
        "内容预览",
        "bodyPreview",
        "intro",
        "preview",
        "snippet",
        "summary",
        "text",
        "plain",
        "content",
        "body",
        "text_content",
    ):
        fields.append(_value_to_text(message.get(key)))
    for key in ("html", "html_content", "bodyHtml", "htmlBody"):
        fields.append(_html_to_visible_text(message.get(key)))
    return [field for field in fields if field.strip()]


def _looks_like_external_code_mail(message: dict[str, Any]) -> bool:
    """判断邮件是否像验证码邮件。"""
    text = "\n".join(_external_text_candidates(message)).lower()
    sender = json.dumps(
        message.get("发件人") or message.get("from") or message.get("sender") or "",
        ensure_ascii=False,
    ).lower()
    haystack = f"{text}\n{sender}"
    return any(
        marker in haystack
        for marker in (
            "chatgpt",
            "openai",
            "noreply@tm.openai.com",
            "验证码",
            "临时验证码",
            "verification code",
            "temporary code",
        )
    )


def extract_external_code(email_data: dict[str, Any]) -> Optional[str]:
    """从外部邮箱 API 邮件对象中提取验证码。

    输入: 邮件 JSON 对象。
    输出: 6 位验证码；找不到则返回 None。
    """
    for text in _external_text_candidates(email_data):
        focused = re.search(
            r"(?:验证码|code|verification|继续|continue)[^\d]{0,120}(\d{6})(?!\d)",
            text,
            re.IGNORECASE,
        )
        if focused:
            return focused.group(1)
        match = VERIFY_CODE_RE.search(text)
        if match:
            return match.group(1)
    return None


def fetch_external_emails(account: ExternalMailAccount) -> list[dict[str, Any]]:
    """访问外部邮箱 API 获取邮件列表。"""
    r = requests.get(
        account.api_url,
        headers={"Accept": "application/json", "User-Agent": HEADERS["User-Agent"], "Cache-Control": "no-cache"},
        timeout=MAIL_API_TIMEOUT,
    )
    if r.status_code != 200:
        raise RuntimeError(f"邮箱 API 请求失败: HTTP {r.status_code}")
    payload = r.json()
    return list(_iter_external_messages(payload))


def wait_for_external_code(
    account: ExternalMailAccount,
    *,
    timeout: int = 120,
    interval: int = 1,
    after_timestamp: Optional[datetime] = None,
) -> Optional[str]:
    """轮询外部邮箱 API 等待验证码。

    输入: 外部邮箱账号、超时时间、可选时间过滤。
    输出: 最新验证码；超时返回 None。
    """
    start = time.time()
    cutoff = after_timestamp - timedelta(seconds=30) if after_timestamp else None
    last_error = ""

    while time.time() - start < timeout:
        try:
            messages = fetch_external_emails(account)
            messages.sort(key=lambda item: _message_time(item) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
            for message in messages:
                received_at = _message_time(message)
                if cutoff and received_at and received_at < cutoff:
                    continue
                if not _looks_like_external_code_mail(message):
                    continue
                code = extract_external_code(message)
                if code:
                    return code
        except Exception as exc:
            last_error = str(exc)

        _sleep_before_next_poll(start, timeout, interval)

    if last_error:
        print(f"[email] 外部邮箱 API 最后错误: {last_error}")
    return None


def create_temp_email() -> Optional[str]:
    """创建临时邮箱，返回邮箱地址"""
    try:
        r = requests.get(
            f"{BASE_URL}/generate-email",
            headers={**HEADERS, "Content-Type": "application/json"},
            timeout=10,
            verify=False,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("success") and data.get("data", {}).get("email"):
                return data["data"]["email"]
    except Exception as e:
        print(f"[email] 创建失败: {e}")
    return None


def fetch_emails(email_address: str) -> list[dict]:
    """获取邮件列表"""
    try:
        ts = int(time.time() * 1000)
        r = requests.get(
            f"{BASE_URL}/emails?email={email_address}&_t={ts}",
            headers={**HEADERS, "Cache-Control": "no-cache"},
            timeout=MAIL_API_TIMEOUT,
            verify=False,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("success") and data.get("data", {}).get("emails"):
                return data["data"]["emails"]
    except Exception as e:
        print(f"[email] 获取邮件错误: {e}")
    return []


def extract_code(email_data: dict) -> Optional[str]:
    """从邮件中提取验证码"""
    for field in ["subject", "html_content", "content", "text_content", "body"]:
        content = email_data.get(field, "")
        if not content:
            continue
        # HTML <div class="code">
        m = re.search(r'<div[^>]*class="code"[^>]*>(\d{6})</div>', content, re.I)
        if m:
            return m.group(1)
        # verification code: XXXXXX
        m = re.search(r'[Vv]erification\s+code:?\s*(\d{6})', content)
        if m:
            return m.group(1)
        # code: XXXXXX
        m = re.search(r'code:?\s*(\d{6})', content, re.I)
        if m:
            return m.group(1)
        # 独立6位数字
        clean = re.sub(r'<[^>]+>', ' ', content)
        m = re.search(r'\b(\d{6})\b', clean)
        if m and m.group(1) != "177010":
            return m.group(1)
    return None


def wait_for_code(email_address: str, timeout: int = 120) -> Optional[str]:
    """轮询等待验证码"""
    start = time.time()
    seen = set()
    while time.time() - start < timeout:
        for mail in fetch_emails(email_address):
            mid = mail.get("id") or mail.get("date")
            if mid in seen:
                continue
            seen.add(mid)
            sender = str(mail.get("from", "") or mail.get("sender", "")).lower()
            subject = str(mail.get("subject", "")).lower()
            if any(k in sender or k in subject for k in ("openai", "chatgpt", "verification")):
                code = extract_code(mail)
                if code:
                    return code
        _sleep_before_next_poll(start, timeout)
    return None


def _main() -> int:
    """独立验证外部邮箱 API 解析，不触发任何注册流程。"""
    parser = argparse.ArgumentParser(description="验证外部邮箱 API 验证码解析")
    parser.add_argument("--mail-file", default=None, help="邮箱账号文件，格式: 账号----邮箱密码----邮箱api")
    parser.add_argument("--index", type=int, default=0, help="使用第几个邮箱账号，从 0 开始")
    parser.add_argument("--timeout", type=int, default=120, help="等待验证码超时秒数")
    parser.add_argument("--fresh", action="store_true", help="只接受命令启动后收到的邮件")
    args = parser.parse_args()

    accounts = load_external_mail_accounts(args.mail_file)
    if not accounts:
        print("[email] 没有可用邮箱账号")
        return 1
    if args.index < 0 or args.index >= len(accounts):
        print(f"[email] index 越界: {args.index}, 共 {len(accounts)} 个账号")
        return 1

    account = accounts[args.index]
    after_timestamp = datetime.now(timezone.utc) if args.fresh else None
    print(f"[email] 使用邮箱: {account.address}")
    code = wait_for_external_code(account, timeout=args.timeout, after_timestamp=after_timestamp)
    if not code:
        print("[email] 未获取到验证码")
        return 1

    print(f"[email] 验证码: {code}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
