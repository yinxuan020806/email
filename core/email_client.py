# -*- coding: utf-8 -*-
"""
邮件客户端统一外观 (Facade)。

路由策略：
- **普通账号**：IMAP/SMTP（密码登录）
- **Outlook OAuth 账号**：
  - IMAP/SMTP + XOAUTH2（覆盖收/发/删/标记，所有功能均可用）
  - 仅当 token 拥有 `Mail.ReadWrite`/`Mail.Read` scope 时才使用 Graph API
    （提升性能，但 Thunderbird 公开 client_id 通常不会授予此 scope）

为何不默认走 Graph？因为 Thunderbird 公开 client_id 申请的 scope 仅有
IMAP.AccessAsUser.All + SMTP.Send，Graph 的 DELETE/PATCH 接口会返回 403。
"""

from __future__ import annotations

import logging
from typing import Callable, Optional, Tuple

from core.graph_client import GraphClient
from core.imap_client import IMAPClient
from core.oauth_token import TokenManager


logger = logging.getLogger(__name__)


_OUTLOOK_DOMAINS = ("outlook.", "hotmail.", "live.", "msn.com")


def _is_outlook_domain(email_addr: str) -> bool:
    domain = email_addr.split("@")[-1].lower()
    return any(domain.startswith(p) or domain == p for p in _OUTLOOK_DOMAINS)


class EmailClient:
    """根据账号类型自动选择实现，对外接口与旧版兼容。"""

    def __init__(
        self,
        email_addr: str,
        password: str,
        imap_server: Optional[str] = None,
        imap_port: int = 993,
        client_id: Optional[str] = None,
        refresh_token: Optional[str] = None,
        account_id: Optional[int] = None,
        on_token_refresh: Optional[Callable[[int, str, str], None]] = None,
        # 兼容字段（旧接口曾接受 db_manager）
        db_manager=None,
    ) -> None:
        self.email_addr = email_addr
        self.password = password
        self.account_id = account_id
        self.client_id = client_id
        self.refresh_token = refresh_token

        self._token_manager: Optional[TokenManager] = None
        self._graph: Optional[GraphClient] = None

        if self._use_oauth():
            cb = None
            if on_token_refresh and account_id is not None:
                def _cb(cid: str, new_rt: str, _aid=account_id) -> None:
                    on_token_refresh(_aid, cid, new_rt)
                cb = _cb
            elif db_manager is not None and account_id is not None:
                def _cb(cid: str, new_rt: str, _aid=account_id, _db=db_manager) -> None:
                    _db.update_account_oauth(_aid, cid, new_rt)
                cb = _cb

            self._token_manager = TokenManager(
                client_id=client_id, refresh_token=refresh_token,
                on_token_refresh=cb,
            )
            # 仅 graph 路径已就绪；是否使用见 _can_use_graph()
            self._graph = GraphClient(self._token_manager)

        # IMAPClient：OAuth 走 XOAUTH2，其它走密码
        self._imap = IMAPClient(
            email_addr,
            password,
            imap_server,
            imap_port,
            token_manager=self._token_manager,
        )

    # ── 路由判断 ────────────────────────────────────────────

    def _use_oauth(self) -> bool:
        return bool(
            _is_outlook_domain(self.email_addr)
            and self.client_id
            and self.refresh_token
        )

    def _can_use_graph_for_writes(self) -> bool:
        """是否可走 Graph 做删除/标记 — 需要 Mail.ReadWrite 之类的 scope。"""
        if self._graph is None or self._token_manager is None:
            return False
        # 触发一次 token 获取以填充 scopes
        token, _ = self._token_manager.get()
        if not token:
            return False
        return (
            self._token_manager.has_scope("Mail.ReadWrite")
            or self._token_manager.has_scope("Mail.Modify")
        )

    # ── 上下文 ──────────────────────────────────────────────

    def __enter__(self) -> "EmailClient":
        return self

    def __exit__(self, *exc) -> bool:
        self.disconnect()
        return False

    def disconnect(self) -> None:
        self._imap.disconnect()

    # ── 业务接口（向后兼容）─────────────────────────────────

    # ── 友好提示 ────────────────────────────────────────────

    @staticmethod
    def _explain_imap_fail(msg: str) -> str:
        m = (msg or "").lower()
        if "logondenied" in m or "authenticate failed" in m or "auth failed" in m:
            return (
                "IMAP 认证失败：通常是该 Outlook 账户未启用 IMAP，"
                "请前往 https://outlook.live.com → 设置 → 邮件 → 同步邮件 → "
                "启用 POP 和 IMAP。"
            )
        return msg

    def _explain_no_write_scope(self, graph_msg: str) -> str:
        """Graph 写操作 403 且 token 缺乏 IMAP scope 时的诊断信息。"""
        if not self._token_manager:
            return graph_msg
        scopes = self._token_manager.scopes or []
        scope_str = ", ".join(s.split("/")[-1] for s in scopes) or "(空)"
        return (
            f"Token 权限不足：当前 scope = [{scope_str}]，需要 Mail.ReadWrite "
            f"(Graph) 或 IMAP.AccessAsUser.All (IMAP) 才能修改邮件。"
            f"请前往 OAuth 页面重新授权，或更换具有完整权限的 client_id。"
        )

    # ── 业务接口 ────────────────────────────────────────────

    def check_status(self) -> Tuple[str, str]:
        # OAuth 账号优先走 Graph（最便宜的 GET）
        if self._graph is not None:
            ok, msg = self._graph.check_status()
            if ok == "正常":
                return ok, msg
            # Graph 失败再试 IMAP（XOAUTH2）
        return self._imap.check_status()

    def fetch_emails(self, folder: str = "inbox", limit: int = 50) -> Tuple[list[dict], str]:
        # OAuth 账号优先走 Graph：Thunderbird scope 下 GET 可用
        if self._graph is not None:
            emails, msg = self._graph.fetch_emails(folder, limit)
            if emails:
                return emails, msg
            # 空列表可能是真的没邮件，也可能 Graph 出错；保留消息，前端不再二次请求
            return emails, msg
        return self._imap.fetch_emails(folder, limit)

    def mark_as_read(
        self, email_id: str, folder: str = "inbox", is_read: bool = True
    ) -> Tuple[bool, str]:
        # 优先 Graph（快）；失败时按 token scope 决定是否回退 IMAP，并给清晰错误
        if self._graph is not None:
            ok, msg = self._graph.mark_as_read(email_id, is_read)
            if ok:
                return ok, msg
            if self._token_manager and self._token_manager.has_scope("IMAP"):
                ok2, msg2 = self._imap.mark_as_read(email_id, folder, is_read)
                if ok2:
                    return ok2, msg2
                return False, self._explain_imap_fail(msg2)
            return False, self._explain_no_write_scope(msg)
        return self._imap.mark_as_read(email_id, folder, is_read)

    def delete_email(self, email_id: str, folder: str = "inbox") -> Tuple[bool, str]:
        if self._graph is not None:
            ok, msg = self._graph.delete_email(email_id)
            if ok:
                return ok, msg
            if self._token_manager and self._token_manager.has_scope("IMAP"):
                ok2, msg2 = self._imap.delete_email(email_id, folder)
                if ok2:
                    return ok2, msg2
                return False, self._explain_imap_fail(msg2)
            return False, self._explain_no_write_scope(msg)
        return self._imap.delete_email(email_id, folder)

    def send_email(
        self, to_addr: str, subject: str, body: str, cc_addr: Optional[str] = None,
    ) -> Tuple[bool, str]:
        # 优先 Graph（更稳定）；Thunderbird scope 没有 Mail.Send 时回退 SMTP+XOAUTH2
        if self._graph is not None and self._can_use_graph_for_writes():
            ok, msg = self._graph.send_email(to_addr, subject, body, cc_addr)
            if ok:
                return ok, msg
        ok, msg = self._imap.send_email(to_addr, subject, body, cc_addr)
        if not ok:
            return False, self._explain_imap_fail(msg)
        return ok, msg

    def send_email_with_attachments(
        self, to_addr: str, subject: str, body: str,
        attachments: Optional[list[str]] = None, cc_addr: Optional[str] = None,
    ) -> Tuple[bool, str]:
        if self._graph is not None and self._can_use_graph_for_writes():
            ok, msg = self._graph.send_email(to_addr, subject, body, cc_addr, attachments)
            if ok:
                return ok, msg
        ok, msg = self._imap.send_email(to_addr, subject, body, cc_addr, attachments)
        if not ok:
            return False, self._explain_imap_fail(msg)
        return ok, msg

    def get_attachments(self, email_id: str, folder: str = "inbox") -> Tuple[list[dict], str]:
        if self._graph is not None:
            atts, msg = self._graph.get_attachments(email_id)
            if atts or "失败" not in msg:
                return atts, msg
        return self._imap.get_attachments(email_id, folder)

    def check_aws_verification_emails(self, limit: int = 50) -> Tuple[bool, int]:
        """检查收件箱前 N 封邮件中是否包含 AWS / Amazon 验证邮件。"""
        keywords = ("aws", "amazon")
        try:
            emails, _ = self.fetch_emails("inbox", limit)
        except Exception:
            logger.exception("AWS 验证码检测异常")
            return False, 0
        count = sum(
            1 for e in emails
            if any(kw in (e.get("subject") or "").lower() for kw in keywords)
        )
        return count > 0, count
