# -*- coding: utf-8 -*-
"""
IMAP / SMTP 客户端封装。

设计原则：
- 通过 `session(folder)` 上下文管理器复用同一连接，避免反复 login。
- 错误返回 (ok, msg) 二元组，便于上层透传给前端。
"""

from __future__ import annotations

import base64
import contextlib
import email
import imaplib
import logging
import os
import re
import smtplib
import ssl
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import parsedate_to_datetime
from typing import Iterator, Optional, Tuple

from core.folder_map import imap_folder_for
from core.log_utils import mask_email
from core.mail_parser import (
    decode_str,
    extract_email_address,
    get_email_body,
    has_attachments,
)
from core.oauth_token import TokenManager
from core.server_config import detect_server, get_smtp_config


logger = logging.getLogger(__name__)


def _xoauth2_string(email_addr: str, access_token: str) -> bytes:
    """构造 XOAUTH2 SASL 字符串（IMAP / SMTP 都用这种格式）。"""
    return f"user={email_addr}\x01auth=Bearer {access_token}\x01\x01".encode()


class IMAPClient:
    """对单个邮箱的 IMAP / SMTP 操作。

    认证模式：
    - 提供 `password` → 普通密码登录
    - 提供 `token_manager` → XOAUTH2 (推荐用于 Outlook OAuth)
    """

    def __init__(
        self,
        email_addr: str,
        password: str,
        imap_server: Optional[str] = None,
        imap_port: int = 993,
        token_manager: Optional[TokenManager] = None,
    ) -> None:
        self.email_addr = email_addr
        self.password = password
        self.imap_server = imap_server or self._detect_server(email_addr)
        self.imap_port = imap_port or 993
        self.token_manager = token_manager
        self._connection: Optional[imaplib.IMAP4_SSL] = None

    @staticmethod
    def _detect_server(email_addr: str) -> str:
        profile = detect_server(email_addr)
        if profile:
            return profile.imap_host
        return f"imap.{email_addr.split('@')[-1].lower()}"

    # ── 连接管理 ────────────────────────────────────────────────

    def connect(self) -> Tuple[bool, str]:
        try:
            ctx = ssl.create_default_context()
            self._connection = imaplib.IMAP4_SSL(
                self.imap_server, self.imap_port, ssl_context=ctx
            )
            if self.token_manager is not None:
                token, msg = self.token_manager.get()
                if not token:
                    self._connection = None
                    return False, msg
                auth_bytes = _xoauth2_string(self.email_addr, token)
                self._connection.authenticate("XOAUTH2", lambda _challenge: auth_bytes)
            else:
                self._connection.login(self.email_addr, self.password)
            return True, "连接成功"
        except (imaplib.IMAP4.error, OSError) as exc:
            logger.warning("IMAP 连接失败 %s: %s", mask_email(self.email_addr), exc)
            return False, f"连接失败: {exc}"

    def disconnect(self) -> None:
        if self._connection is not None:
            try:
                self._connection.logout()
            except (imaplib.IMAP4.error, OSError):
                logger.debug("IMAP logout 异常（忽略）")
            finally:
                self._connection = None

    @contextlib.contextmanager
    def session(self, folder: Optional[str] = None) -> Iterator["IMAPClient"]:
        """上下文管理器：自动 connect/select/disconnect。

        例：
            with client.session("inbox") as s:
                s.fetch_emails(...)
                s.check_aws(...)   # 同一连接内多次操作
        """
        already = self._connection is not None
        if not already:
            ok, msg = self.connect()
            if not ok:
                raise IOError(msg)
        try:
            if folder:
                actual = imap_folder_for(self.email_addr, folder)
                self._connection.select(actual)
            yield self
        finally:
            if not already:
                self.disconnect()

    # ── 操作 ────────────────────────────────────────────────────

    def check_status(self) -> Tuple[str, str]:
        ok, msg = self.connect()
        if ok:
            self.disconnect()
            return "正常", msg
        return "异常", msg

    def fetch_emails(self, folder: str = "inbox", limit: int = 50) -> Tuple[list[dict], str]:
        ok, msg = self.connect()
        if not ok:
            return [], msg
        try:
            actual = imap_folder_for(self.email_addr, folder)
            sel_status, sel_data = self._connection.select(actual)
            if sel_status != "OK":
                return [], f"无法打开文件夹 {actual}: {sel_data}"

            status, messages = self._connection.search(None, "ALL")
            if status != "OK":
                return [], "获取邮件失败"

            ids = messages[0].split()
            ids = ids[-limit:] if len(ids) > limit else ids
            if not ids:
                return [], "获取成功"

            id_set = b",".join(ids)
            status, fetched = self._connection.fetch(id_set, "(RFC822 FLAGS)")
            if status != "OK":
                return [], "获取邮件失败"

            parsed = []
            for item in fetched:
                if not isinstance(item, tuple) or len(item) < 2:
                    continue
                header_bytes, raw = item[0], item[1]
                header_str = (
                    header_bytes.decode(errors="ignore")
                    if isinstance(header_bytes, bytes)
                    else str(header_bytes)
                )
                flags_match = re.search(r"FLAGS \(([^)]*)\)", header_str)
                flags = flags_match.group(1) if flags_match else ""
                seq_match = re.match(r"\s*(\d+)\s*\(", header_str)
                uid = seq_match.group(1) if seq_match else ""

                try:
                    msg_obj = email.message_from_bytes(raw)
                except Exception:
                    logger.exception("解析邮件失败")
                    continue

                date_str = msg_obj.get("Date", "")
                try:
                    date = parsedate_to_datetime(date_str)
                except (TypeError, ValueError):
                    date = None
                sender = decode_str(msg_obj.get("From", ""))
                parsed.append({
                    "uid": uid,
                    "subject": decode_str(msg_obj.get("Subject", "")),
                    "sender": sender,
                    "sender_email": extract_email_address(sender),
                    "date": date,
                    "body": get_email_body(msg_obj),
                    "is_read": "\\Seen" in flags,
                    "has_attachments": has_attachments(msg_obj),
                })
            parsed.reverse()
            return parsed, "获取成功"
        except (imaplib.IMAP4.error, OSError) as exc:
            logger.exception("IMAP fetch_emails 异常")
            return [], f"获取邮件失败: {exc}"
        finally:
            self.disconnect()

    def mark_as_read(self, email_id: str, folder: str, is_read: bool = True) -> Tuple[bool, str]:
        ok, msg = self.connect()
        if not ok:
            return False, msg
        try:
            self._connection.select(imap_folder_for(self.email_addr, folder))
            flag = "+FLAGS" if is_read else "-FLAGS"
            eid = email_id.encode() if isinstance(email_id, str) else email_id
            self._connection.store(eid, flag, "\\Seen")
            return True, "标记成功"
        except (imaplib.IMAP4.error, OSError) as exc:
            logger.warning("IMAP mark_as_read 失败: %s", exc)
            return False, f"标记失败: {exc}"
        finally:
            self.disconnect()

    def delete_email(self, email_id: str, folder: str) -> Tuple[bool, str]:
        ok, msg = self.connect()
        if not ok:
            return False, msg
        try:
            self._connection.select(imap_folder_for(self.email_addr, folder))
            eid = email_id.encode() if isinstance(email_id, str) else email_id
            self._connection.store(eid, "+FLAGS", "\\Deleted")
            self._connection.expunge()
            return True, "删除成功"
        except (imaplib.IMAP4.error, OSError) as exc:
            logger.warning("IMAP delete_email 失败: %s", exc)
            return False, f"删除失败: {exc}"
        finally:
            self.disconnect()

    # ── SMTP ────────────────────────────────────────────────────

    def send_email(
        self,
        to_addr: str,
        subject: str,
        body: str,
        cc_addr: Optional[str] = None,
        attachments: Optional[list[str]] = None,
    ) -> Tuple[bool, str]:
        smtp_host, smtp_port = get_smtp_config(self.email_addr)
        try:
            msg = MIMEMultipart()
            msg["From"] = self.email_addr
            msg["To"] = to_addr
            msg["Subject"] = subject
            if cc_addr:
                msg["Cc"] = cc_addr
            msg.attach(MIMEText(body, "plain", "utf-8"))

            if attachments:
                for path in attachments:
                    if not os.path.exists(path):
                        continue
                    with open(path, "rb") as f:
                        part = MIMEBase("application", "octet-stream")
                        part.set_payload(f.read())
                    encoders.encode_base64(part)
                    part.add_header(
                        "Content-Disposition",
                        f'attachment; filename="{os.path.basename(path)}"',
                    )
                    msg.attach(part)

            recipients = [a.strip() for a in to_addr.split(",") if a.strip()]
            if cc_addr:
                recipients.extend(a.strip() for a in cc_addr.split(",") if a.strip())

            if smtp_port == 465:
                ctx = ssl.create_default_context()
                server = smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx, timeout=30)
            else:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
                server.ehlo()
                if server.has_extn("STARTTLS"):
                    server.starttls()
                    server.ehlo()
            try:
                if self.token_manager is not None:
                    token, msg_t = self.token_manager.get()
                    if not token:
                        return False, msg_t
                    import base64
                    auth_b64 = base64.b64encode(
                        _xoauth2_string(self.email_addr, token)
                    ).decode()
                    code, resp = server.docmd("AUTH", "XOAUTH2 " + auth_b64)
                    if code not in (235, 334):
                        return False, f"XOAUTH2 认证失败: {code} {resp.decode(errors='ignore') if isinstance(resp, bytes) else resp}"
                else:
                    server.login(self.email_addr, self.password)
                server.sendmail(self.email_addr, recipients, msg.as_string())
            finally:
                try:
                    server.quit()
                except smtplib.SMTPException:
                    pass
            return True, "发送成功"
        except smtplib.SMTPAuthenticationError as exc:
            return False, f"认证失败: {exc}"
        except smtplib.SMTPException as exc:
            return False, f"SMTP 错误: {exc}"
        except OSError as exc:
            return False, f"网络错误: {exc}"

    # ── 附件 / AWS 检测 ────────────────────────────────────────

    def get_attachments(self, email_id: str, folder: str) -> Tuple[list[dict], str]:
        ok, msg = self.connect()
        if not ok:
            return [], msg
        try:
            self._connection.select(imap_folder_for(self.email_addr, folder))
            eid = email_id.encode() if isinstance(email_id, str) else email_id
            status, data = self._connection.fetch(eid, "(RFC822)")
            if status != "OK":
                return [], "获取邮件失败"
            msg_obj = email.message_from_bytes(data[0][1])
            atts = []
            for part in msg_obj.walk():
                if "attachment" not in (part.get("Content-Disposition") or ""):
                    continue
                fname = part.get_filename()
                if not fname:
                    continue
                fname = decode_str(fname)
                content = part.get_payload(decode=True) or b""
                atts.append({
                    "id": fname,
                    "name": fname,
                    "size": len(content),
                    "content_type": part.get_content_type(),
                    "content_bytes": base64.b64encode(content).decode(),
                })
            return atts, "获取成功"
        except (imaplib.IMAP4.error, OSError) as exc:
            return [], f"获取附件失败: {exc}"
        finally:
            self.disconnect()
