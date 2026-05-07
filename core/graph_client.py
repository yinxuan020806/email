# -*- coding: utf-8 -*-
"""
Microsoft Graph API / Outlook REST API 客户端封装。

OAuth2 token 由 TokenManager 管理；本类只负责具体业务接口调用。
"""

from __future__ import annotations

import base64
import logging
import os
import time
from datetime import datetime
from typing import Optional, Tuple

import certifi
import requests

from core.folder_map import graph_folder_for
from core.oauth_token import SESSION, TokenManager


logger = logging.getLogger(__name__)


GRAPH_BASE = "https://graph.microsoft.com/v1.0/me"
OUTLOOK_BASE = "https://outlook.office.com/api/v2.0/me"

# Microsoft Graph / Outlook REST 在 per-mailbox 高频读时偶发返回 429（Too Many
# Requests）/ 503 / 504：对单用户日常刷新邮件的场景，这通常是几秒内就能自愈的
# 软抖动而非真正的封禁。旧实现一次失败就把 [] + "API 错误: 429" 直接返回，让
# 前端误把它渲染成"暂无数据"，看上去就跟"自家代码限流过严"一模一样。
#
# 这里在 fetch_emails 里加一次轻量重试：仅 429/503/504 触发，按服务端
# Retry-After（若有）退避，否则用 1.5s 固定 sleep，最多重试 1 次。
# 不做更激进的重试链路是因为：
# - 真正的 429 通常意味着调用方需要"立刻退一步"，循环重试 5 次只会让风控
#   计时器不停被踩；
# - Web 路径上单次请求阻塞 1.5-2s 已经接近用户耐受极限，再多就不如直接
#   返回错误让前端展示"稍后重试"提示。
_RETRYABLE_STATUS = frozenset({429, 503, 504})
_RETRY_BACKOFF_DEFAULT_SEC = 1.5
_RETRY_BACKOFF_MAX_SEC = 4.0


class GraphClient:
    """通过 Graph 或 Outlook REST 操作 Outlook 邮箱。"""

    def __init__(self, token_manager: TokenManager) -> None:
        self.tm = token_manager

    # ── 内部 ────────────────────────────────────────────────

    def _headers(self) -> Optional[dict]:
        token, msg = self.tm.get()
        if not token:
            return None
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def _base(self) -> str:
        # 必须先调用过 _headers 一次，确保 api_type 就绪
        return OUTLOOK_BASE if self.tm.api_type == "outlook" else GRAPH_BASE

    def _req(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            # 用 module-level Session 复用 TLS 连接，避免每次握手 (~100-300ms)
            return SESSION.request(
                method, url, timeout=kwargs.pop("timeout", 30),
                verify=certifi.where(), **kwargs,
            )
        except requests.RequestException as exc:
            logger.warning("Graph 请求失败 %s %s: %s", method, url, exc)
            return None

    @staticmethod
    def _retry_after_sec(resp: requests.Response) -> float:
        """从 429/503 响应解析合理的退避秒数。

        Microsoft Graph 在限流时通常会返回 ``Retry-After`` 头（数字秒，偶尔是
        HTTP-date）。这里只解析数字格式，并夹到 ``_RETRY_BACKOFF_MAX_SEC``，
        避免服务端给出 60s+ 的 Retry-After 把整个 web 请求阻塞过久（前端请求
        已经超时，用户看到的还是 502/504）。无 Retry-After 头时退化到固定
        1.5s，足以让大部分软抖动自愈。
        """
        ra = (resp.headers.get("Retry-After") or "").strip()
        if ra.isdigit():
            return min(_RETRY_BACKOFF_MAX_SEC, max(0.0, float(ra)))
        return _RETRY_BACKOFF_DEFAULT_SEC

    @staticmethod
    def _summarize_upstream_error(resp: requests.Response) -> str:
        """把 Graph / Outlook REST 的非 200 响应概括成一段**用户友好且不泄露
        上游 HTML / 长 body** 的简短 message。

        旧实现把 ``resp.text[:200]`` 直接拼进 message 透传到前端 —— 当 Microsoft
        在 OAuth 凭据失效时返回登录页 HTML，前端就把整段 ``<!DOCTYPE html>...``
        当错误内容渲染出来，看起来既丑又泄露上游版本指纹。

        策略（从可靠到兜底）：
        1. JSON body：只取 ``error.code`` + ``error.message`` 的前 120 字符
        2. 含 ``<html`` / ``<!DOCTYPE`` / ``<title``：识别为 HTML，按状态码给
           标准化文案（401/403 = 凭据失效；其它 = HTTP {code} 错误页）
        3. 401 / 403：补一句"请重新走 OAuth 授权"
        4. 其它：仅返回 ``API 错误: {code}`` 不带任何上游 body
        """
        code = resp.status_code
        # 1) 优先解 JSON
        try:
            data = resp.json() if resp.text else None
        except ValueError:
            data = None
        if isinstance(data, dict):
            err = data.get("error") if isinstance(data.get("error"), dict) else {}
            err_code = (err.get("code") or "").strip()
            err_msg = (err.get("message") or "").strip().replace("\r", " ").replace("\n", " ")
            if err_msg or err_code:
                summary = f"{err_code}: {err_msg}".strip(": ").strip()
                # 截短 + 强制 ASCII-safe（避免 HTML 字符出现）
                summary = summary[:120]
                if code in (401, 403):
                    return f"账号 OAuth 凭据失效或权限不足（HTTP {code}）：{summary}。请到 OAuth 页面重新授权该账号。"
                return f"API 错误 {code}: {summary}"

        # 2) 上游不是 JSON（极大概率是 HTML 登录页 / WAF 拦截页）
        body_lower = (resp.text or "")[:200].lower()
        if "<html" in body_lower or "<!doctype" in body_lower or "<title" in body_lower:
            if code in (401, 403):
                return (
                    f"账号 OAuth 凭据失效（HTTP {code}，上游返回登录页）。"
                    "该账号的 refresh_token 已过期或被吊销，请到 OAuth 页面重新授权。"
                )
            return f"API 错误 {code}: 上游返回了 HTML 错误页（可能在维护或被风控），请稍后重试。"

        # 3) 401/403 + 非 HTML：给统一友好文案
        if code in (401, 403):
            return (
                f"账号 OAuth 凭据失效或权限不足（HTTP {code}）。"
                "请到 OAuth 页面重新授权该账号。"
            )

        # 4) 兜底：只透传状态码，不再带上游 body
        return f"API 错误 {code}"

    # ── Public API ──────────────────────────────────────────

    def check_status(self) -> Tuple[str, str]:
        headers = self._headers()
        if headers is None:
            tok, msg = self.tm.get()
            return "异常", msg
        url = f"{self._base()}/{'mailfolders' if self.tm.api_type == 'outlook' else 'mailFolders'}/inbox/messages?$top=1"
        resp = self._req("GET", url, headers=headers, timeout=10)
        if resp is None:
            return "异常", "网络错误"
        if resp.status_code == 200:
            return "正常", "Token 有效"
        return "异常", self._summarize_upstream_error(resp)

    def fetch_emails(
        self, folder: str = "inbox", limit: int = 50, with_body: bool = False,
    ) -> Tuple[list[dict], str]:
        """拉取邮件列表。

        ``with_body=False``（默认）时 ``$select`` 不含 body 字段，Graph 服务器端
        不会返回 body，传输从 ~MB 级降到 ~KB 级，列表加载快得多。
        点击具体邮件时由 :meth:`get_email_body` 按需拉完整正文。
        """
        headers = self._headers()
        if headers is None:
            tok, msg = self.tm.get()
            return [], msg

        folder_name = graph_folder_for(self.tm.api_type, folder)
        if self.tm.api_type == "outlook":
            url = f"{OUTLOOK_BASE}/mailfolders/{folder_name}/messages"
            base_select = "Id,Subject,From,ReceivedDateTime,BodyPreview,IsRead,HasAttachments"
            select_fields = base_select + (",Body" if with_body else "")
            params = {
                "$top": limit, "$orderby": "ReceivedDateTime desc",
                "$select": select_fields,
            }
            field = {
                "from": "From", "subject": "Subject", "date": "ReceivedDateTime",
                "body": "Body", "preview": "BodyPreview", "id": "Id",
                "is_read": "IsRead", "att": "HasAttachments", "addr_field": "Address",
                "name_field": "Name", "email_field": "EmailAddress",
                "content": "Content", "ctype": "ContentType",
            }
        else:
            url = f"{GRAPH_BASE}/mailFolders/{folder_name}/messages"
            base_select = "id,subject,from,receivedDateTime,bodyPreview,isRead,hasAttachments"
            select_fields = base_select + (",body" if with_body else "")
            params = {
                "$top": limit, "$orderby": "receivedDateTime desc",
                "$select": select_fields,
            }
            field = {
                "from": "from", "subject": "subject", "date": "receivedDateTime",
                "body": "body", "preview": "bodyPreview", "id": "id",
                "is_read": "isRead", "att": "hasAttachments", "addr_field": "address",
                "name_field": "name", "email_field": "emailAddress",
                "content": "content", "ctype": "contentType",
            }

        # Graph 默认 body 是 HTML；如想拿 text 可以加 Prefer 头部
        # 不过 sandbox iframe 直接渲染 HTML 是首选。
        request_headers = dict(headers)
        if with_body:
            request_headers["Prefer"] = 'outlook.body-content-type="html"'

        resp = self._req(
            "GET", url, headers=request_headers, params=params, timeout=30
        )
        # 429/503/504 等"软抖动"做一次受控重试：用户日常刷新邮件几秒内就会
        # 自愈，原实现一次失败就让前端拿到 "API 错误: 429"+空列表，被误读为
        # "我们自家代码限流"。仅一次 retry 控制在 ≤ 4s，避免雪崩。
        if resp is not None and resp.status_code in _RETRYABLE_STATUS:
            backoff = self._retry_after_sec(resp)
            logger.info(
                "Graph fetch_emails %d，%ss 后重试一次（Retry-After=%s）",
                resp.status_code, backoff, resp.headers.get("Retry-After", ""),
            )
            time.sleep(backoff)
            resp = self._req(
                "GET", url, headers=request_headers, params=params, timeout=30
            )

        if resp is None:
            return [], "网络错误"
        if resp.status_code != 200:
            # 注意：日志里仍记完整状态码 + 前 300 字 body 便于运维取证；返回给
            # 上层 / 前端的 message 经过 _summarize_upstream_error 净化，避免把
            # 上游 HTML 登录页原样透传到浏览器（既丑又泄露指纹）。
            logger.warning(
                "Graph fetch_emails 失败 status=%d body=%s",
                resp.status_code, (resp.text or "")[:300],
            )
            return [], self._summarize_upstream_error(resp)

        emails: list[dict] = []
        for m in resp.json().get("value", []):
            from_info = (m.get(field["from"]) or {}).get(field["email_field"], {}) or {}
            sender = from_info.get(field["name_field"], "") or from_info.get(field["addr_field"], "")
            date_str = m.get(field["date"], "")
            try:
                date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                date = None

            body_obj = m.get(field["body"]) or {}
            body_content = body_obj.get(field["content"], "") or ""
            body_type = (body_obj.get(field["ctype"], "") or "").lower()
            preview = m.get(field["preview"], "") or ""

            # 当 body.content 为空但有 preview 时，用 preview 兜底（避免前端白屏）
            if not body_content and preview:
                body_content = preview
                if not body_type:
                    body_type = "text"
            if not body_type:
                body_type = "html" if "<" in body_content else "text"

            emails.append({
                "uid": m.get(field["id"], ""),
                "subject": m.get(field["subject"], "") or "(无主题)",
                "sender": sender,
                "sender_email": from_info.get(field["addr_field"], ""),
                "date": date,
                "body": body_content,
                "body_type": body_type,
                "preview": preview,
                "is_read": m.get(field["is_read"], True),
                "has_attachments": m.get(field["att"], False),
            })
        return emails, "获取成功"

    def get_email_body(
        self, email_id: str
    ) -> Tuple[Optional[str], str, str, str]:
        """单独拉取一封邮件的完整 body，用于列表 body 为空时的二次获取。

        返回 ``(body_html_or_text, body_type, internet_message_id, message)``。
        失败时 body 为 None。
        ``internet_message_id`` 是 RFC 5322 的全局唯一 Message-Id（含尖括号），
        用于在 Graph 拿不到 body 时用 IMAP search 反查。
        """
        headers = self._headers()
        if headers is None:
            tok, msg = self.tm.get()
            return None, "", "", msg

        if self.tm.api_type == "outlook":
            url = f"{OUTLOOK_BASE}/messages/{email_id}"
            select_fields = "Id,Subject,Body,BodyPreview,InternetMessageId"
            ctype_key, content_key, body_key, preview_key, msgid_key = (
                "ContentType",
                "Content",
                "Body",
                "BodyPreview",
                "InternetMessageId",
            )
        else:
            url = f"{GRAPH_BASE}/messages/{email_id}"
            select_fields = "id,subject,body,bodyPreview,internetMessageId"
            ctype_key, content_key, body_key, preview_key, msgid_key = (
                "contentType",
                "content",
                "body",
                "bodyPreview",
                "internetMessageId",
            )

        request_headers = dict(headers)
        request_headers["Prefer"] = 'outlook.body-content-type="html"'

        resp = self._req(
            "GET", url, headers=request_headers,
            params={"$select": select_fields}, timeout=30,
        )
        # 与 fetch_emails 对齐：429/503/504 单次受控重试，避免用户点开邮件时
        # 偶发软抖动直接报"API 错误"。
        if resp is not None and resp.status_code in _RETRYABLE_STATUS:
            backoff = self._retry_after_sec(resp)
            logger.info(
                "Graph get_email_body %d，%ss 后重试一次（Retry-After=%s）",
                resp.status_code, backoff, resp.headers.get("Retry-After", ""),
            )
            time.sleep(backoff)
            resp = self._req(
                "GET", url, headers=request_headers,
                params={"$select": select_fields}, timeout=30,
            )
        if resp is None:
            logger.warning("Graph get_email_body 网络错误 url=%s", url)
            return None, "", "", "网络错误"
        if resp.status_code != 200:
            logger.warning(
                "Graph get_email_body 失败 status=%d body=%s",
                resp.status_code, (resp.text or "")[:300],
            )
            return None, "", "", self._summarize_upstream_error(resp)

        m = resp.json()
        body_obj = m.get(body_key) or {}
        body_content = body_obj.get(content_key, "") or ""
        body_type = (body_obj.get(ctype_key, "") or "").lower()
        preview = m.get(preview_key, "") or ""
        internet_msg_id = m.get(msgid_key, "") or ""

        logger.info(
            "Graph get_email_body api=%s id=%s body_len=%d type=%s preview_len=%d msgid=%s",
            self.tm.api_type, email_id[:30],
            len(body_content), body_type, len(preview), internet_msg_id[:80],
        )

        if not body_content and preview:
            body_content = preview
            body_type = body_type or "text"
        if not body_type:
            body_type = "html" if "<" in body_content else "text"
        return body_content, body_type, internet_msg_id, "获取成功"

    def mark_as_read(self, email_id: str, is_read: bool = True) -> Tuple[bool, str]:
        headers = self._headers()
        if headers is None:
            tok, msg = self.tm.get()
            return False, msg
        url = f"{self._base()}/messages/{email_id}"
        data = {"IsRead": is_read} if self.tm.api_type == "outlook" else {"isRead": is_read}
        resp = self._req("PATCH", url, headers=headers, json=data)
        if resp is None:
            return False, "网络错误"
        if resp.status_code == 200:
            return True, "标记成功"
        return False, f"标记失败: {resp.status_code}"

    def delete_email(self, email_id: str) -> Tuple[bool, str]:
        headers = self._headers()
        if headers is None:
            tok, msg = self.tm.get()
            return False, msg
        url = f"{self._base()}/messages/{email_id}"
        resp = self._req("DELETE", url, headers=headers)
        if resp is None:
            return False, "网络错误"
        if resp.status_code in (200, 204):
            return True, "删除成功"
        return False, f"删除失败: {resp.status_code}"

    def send_email(
        self,
        to_addr: str,
        subject: str,
        body: str,
        cc_addr: Optional[str] = None,
        attachments: Optional[list[str]] = None,
    ) -> Tuple[bool, str]:
        headers = self._headers()
        if headers is None:
            tok, msg = self.tm.get()
            return False, msg

        att_data = []
        if attachments:
            for path in attachments:
                if not os.path.exists(path):
                    continue
                with open(path, "rb") as f:
                    att_data.append({
                        "name": os.path.basename(path),
                        "content_b64": base64.b64encode(f.read()).decode(),
                    })

        if self.tm.api_type == "outlook":
            url = f"{OUTLOOK_BASE}/sendmail"
            payload = {"Message": {
                "Subject": subject,
                "Body": {"ContentType": "Text", "Content": body},
                "ToRecipients": [
                    {"EmailAddress": {"Address": a.strip()}}
                    for a in to_addr.split(",") if a.strip()
                ],
                "Attachments": [
                    {"@odata.type": "#Microsoft.OutlookServices.FileAttachment",
                     "Name": a["name"], "ContentBytes": a["content_b64"]}
                    for a in att_data
                ],
            }}
            if cc_addr:
                payload["Message"]["CcRecipients"] = [
                    {"EmailAddress": {"Address": a.strip()}}
                    for a in cc_addr.split(",") if a.strip()
                ]
        else:
            url = f"{GRAPH_BASE}/sendMail"
            payload = {"message": {
                "subject": subject,
                "body": {"contentType": "Text", "content": body},
                "toRecipients": [
                    {"emailAddress": {"address": a.strip()}}
                    for a in to_addr.split(",") if a.strip()
                ],
                "attachments": [
                    {"@odata.type": "#microsoft.graph.fileAttachment",
                     "name": a["name"], "contentBytes": a["content_b64"]}
                    for a in att_data
                ],
            }}
            if cc_addr:
                payload["message"]["ccRecipients"] = [
                    {"emailAddress": {"address": a.strip()}}
                    for a in cc_addr.split(",") if a.strip()
                ]

        resp = self._req("POST", url, headers=headers, json=payload, timeout=60)
        if resp is None:
            return False, "网络错误"
        if resp.status_code in (200, 202):
            return True, "发送成功"
        return False, f"发送失败: {resp.status_code} - {resp.text[:200]}"

    def get_attachments(self, email_id: str) -> Tuple[list[dict], str]:
        headers = self._headers()
        if headers is None:
            tok, msg = self.tm.get()
            return [], msg
        url = f"{self._base()}/messages/{email_id}/attachments"
        resp = self._req("GET", url, headers=headers)
        if resp is None:
            return [], "网络错误"
        if resp.status_code != 200:
            return [], f"获取附件失败: {resp.status_code}"

        atts = []
        is_outlook = self.tm.api_type == "outlook"
        for a in resp.json().get("value", []):
            atts.append({
                "id": a.get("Id" if is_outlook else "id", ""),
                "name": a.get("Name" if is_outlook else "name", ""),
                "size": a.get("Size" if is_outlook else "size", 0),
                "content_type": a.get("ContentType" if is_outlook else "contentType", ""),
                "content_bytes": a.get("ContentBytes" if is_outlook else "contentBytes", ""),
            })
        return atts, "获取成功"
