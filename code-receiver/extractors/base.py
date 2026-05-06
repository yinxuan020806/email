# -*- coding: utf-8 -*-
"""提取器基类、SafeLinks unwrap、HTML 实体清洗。"""

from __future__ import annotations

import html as html_mod
import logging
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional
from urllib.parse import parse_qs, unquote, urlparse


logger = logging.getLogger(__name__)


@dataclass
class ExtractedResult:
    """单封邮件提取出的结果。"""

    code: Optional[str] = None
    link: Optional[str] = None
    sender: str = ""
    subject: str = ""
    received_at: str = ""
    matched_rule_id: Optional[int] = None
    body_preview: str = ""

    def has_payload(self) -> bool:
        return bool(self.code or self.link)


_HTML_SCRIPT_STYLE_RE = re.compile(
    r"<(script|style)[^>]*>[\s\S]*?</\1>", re.IGNORECASE
)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_ALL_WHITESPACE_RE = re.compile(r"\s+")


def strip_html_tags(text: str) -> str:
    """简单 HTML → 纯文本（不引入 BS4 重型依赖，足以覆盖 Cursor / OpenAI 邮件）。

    - 移除 <script>/<style> 整段内容
    - 移除所有标签
    - 折叠所有空白（含 \\n）成单空格 — 让正则能跨原 HTML 标签结构命中
    """
    if not text:
        return text
    text = _HTML_SCRIPT_STYLE_RE.sub(" ", text)
    text = _HTML_TAG_RE.sub(" ", text)
    text = html_mod.unescape(text)
    text = _ALL_WHITESPACE_RE.sub(" ", text)
    return text.strip()


def looks_like_html(text: str) -> bool:
    if not text:
        return False
    low = text.lower()
    return ("<html" in low or "<body" in low or "<!doctype html" in low
            or low.count("<div") > 2 or low.count("<p>") > 2)


class SafeLinks:
    """处理 Outlook / O365 SafeLinks 包装的链接。

    示例:
        https://nam11.safelinks.protection.outlook.com/?url=https%3A%2F%2Fauth.openai.com%2Flog-in%2F...&data=...

    安全约束：``unwrap`` 返回的 URL 必须以 ``http://`` 或 ``https://`` 开头；
    任何非 http(s) 协议（``javascript:`` / ``data:`` / ``file:`` / 空字符串等）
    一律返回原始包装 URL，避免 magic-link 被构造成可执行 payload 后透传到前端。
    """

    _SAFELINK_HOST = "safelinks.protection.outlook.com"
    _SAFELINK_PATTERN = re.compile(
        r"https?://[a-z0-9-]+\.safelinks\.protection\.outlook\.com/[^\s\"'>]+",
        re.IGNORECASE,
    )
    _HTTP_PREFIXES = ("http://", "https://")

    @classmethod
    def _is_http_url(cls, url: str) -> bool:
        if not url:
            return False
        return url.lower().startswith(cls._HTTP_PREFIXES)

    @classmethod
    def unwrap(cls, url: str) -> str:
        if not url:
            return url
        try:
            parsed = urlparse(url)
            if cls._SAFELINK_HOST not in (parsed.netloc or ""):
                return url
            qs = parse_qs(parsed.query)
            target = qs.get("url", [None])[0]
            if not target:
                return url
            unwrapped = unquote(target)
            if not cls._is_http_url(unwrapped):
                logger.warning(
                    "SafeLinks unwrap 拒绝非 http(s) 目标，回退原 URL；prefix=%r",
                    unwrapped[:24],
                )
                return url
            return unwrapped
        except (ValueError, TypeError):
            return url

    @classmethod
    def unwrap_all_in_text(cls, text: str) -> str:
        """把文本里所有 SafeLinks 包装的 URL 就地替换为原始 URL，便于后续正则匹配。"""
        if not text:
            return text
        if "safelinks.protection.outlook.com" not in text.lower():
            return text
        return cls._SAFELINK_PATTERN.sub(lambda m: cls.unwrap(m.group(0)), text)


# 单条 sender/subject 通配符的最大字符数
_MAX_PATTERN_LEN = 100
# 单条 code/link 正则的最大字符数（防 ReDoS：超长嵌套量词通常需要更长正则）
_MAX_REGEX_LEN = 200


@dataclass
class Extractor:
    """单条提取规则。"""

    category: str
    sender_patterns: List[re.Pattern] = field(default_factory=list)
    subject_patterns: List[re.Pattern] = field(default_factory=list)
    code_regex: Optional[re.Pattern] = None
    link_regex: Optional[re.Pattern] = None
    priority: int = 0
    rule_id: Optional[int] = None
    """rule_id 来自 DB 时非空；代码内置默认规则为 None。"""

    @classmethod
    def from_strings(
        cls,
        category: str,
        sender_pattern: str = "",
        subject_pattern: str = "",
        code_regex: str = "",
        link_regex: str = "",
        priority: int = 0,
        rule_id: Optional[int] = None,
    ) -> "Extractor":
        """从字符串模式构造，sender/subject 用通配符（``*``→``.*``）+ 大小写不敏感。

        防 ReDoS：``code_regex`` / ``link_regex`` 单条 > ``_MAX_REGEX_LEN`` 字符直接拒绝；
        ``sender_pattern`` / ``subject_pattern`` 拆分后每段 > ``_MAX_PATTERN_LEN`` 拒绝。
        管理员可通过 DB 写规则，限制能挡住"无限灰度回溯"型恶意正则。
        """

        def _split_compile_patterns(s: str) -> List[re.Pattern]:
            if not s:
                return []
            patterns: List[re.Pattern] = []
            for raw in s.split("|"):
                raw = raw.strip()
                if not raw:
                    continue
                if len(raw) > _MAX_PATTERN_LEN:
                    logger.warning(
                        "跳过过长发件人/主题模式（%d > %d 字符）",
                        len(raw), _MAX_PATTERN_LEN,
                    )
                    continue
                escaped = re.escape(raw).replace(r"\*", ".*")
                try:
                    patterns.append(re.compile(escaped, re.IGNORECASE))
                except re.error:
                    logger.warning("跳过非法发件人/主题模式: %r", raw)
            return patterns

        def _safe_compile(s: str) -> Optional[re.Pattern]:
            if not s:
                return None
            if len(s) > _MAX_REGEX_LEN:
                logger.warning(
                    "跳过过长正则（%d > %d 字符），防 ReDoS", len(s), _MAX_REGEX_LEN,
                )
                return None
            try:
                return re.compile(s, re.IGNORECASE | re.DOTALL)
            except re.error as exc:
                logger.warning("跳过非法正则 %r: %s", s, exc)
                return None

        return cls(
            category=category.lower(),
            sender_patterns=_split_compile_patterns(sender_pattern),
            subject_patterns=_split_compile_patterns(subject_pattern),
            code_regex=_safe_compile(code_regex),
            link_regex=_safe_compile(link_regex),
            priority=priority,
            rule_id=rule_id,
        )

    def match(self, mail: dict) -> bool:
        """发件人 + 主题双白名单匹配；任一组留空表示该维度不限制。"""
        sender = (mail.get("sender") or mail.get("from") or "").lower()
        subject = (mail.get("subject") or "").lower()
        if self.sender_patterns:
            if not any(p.search(sender) for p in self.sender_patterns):
                return False
        if self.subject_patterns:
            if not any(p.search(subject) for p in self.subject_patterns):
                return False
        return True

    def extract(self, mail: dict) -> ExtractedResult:
        """从 mail dict 提取 code / link。约定 mail 至少包含
        ``sender`` / ``subject`` / ``date`` / ``body`` 字段。
        """
        raw_body = mail.get("body") or mail.get("preview") or ""
        body_text = html_mod.unescape(raw_body)
        # SafeLinks unwrap 必须在正则匹配前完成，否则被包装的链接域名是
        # safelinks.protection.outlook.com，无法命中 cursor.com / openai.com 模式
        body_text = SafeLinks.unwrap_all_in_text(body_text)
        # OpenAI / 部分发件方只发 HTML 邮件，<div>123456</div> 这种
        # 验证码被标签包着，必须先 strip tag 才能让正则跨标签命中
        if looks_like_html(body_text):
            body_text = strip_html_tags(body_text)
        subject = mail.get("subject") or ""

        result = ExtractedResult(
            sender=mail.get("sender") or mail.get("from") or "",
            subject=subject,
            received_at=str(mail.get("date") or ""),
            matched_rule_id=self.rule_id,
            body_preview=body_text[:500],
        )

        # 验证码：优先 body 找（避免 subject 含 "code" 关键词把 body 开头的订单号
        # 误命中）；body 没找到再 fallback 到 subject — 适用于 OpenAI 中文模板
        # "你的 OpenAI 代码为 186862" 这种 subject 自身就含验证码的情况。
        if self.code_regex:
            m = self.code_regex.search(body_text)
            if not m and subject:
                m = self.code_regex.search(subject)
            if m:
                result.code = (m.group("code") if "code" in (m.groupdict() or {}) else m.group(0)).strip()

        # link 同样优先 body 找
        if self.link_regex:
            m = self.link_regex.search(body_text)
            if not m and subject:
                m = self.link_regex.search(subject)
            if m:
                raw_link = m.group("link") if "link" in (m.groupdict() or {}) else m.group(0)
                candidate = SafeLinks.unwrap(raw_link.strip())
                # 协议白名单：纵深防御。即使 DB 中的 link_regex 被站长写成
                # ``(?P<link>.+)`` 这样的宽松模式抓到 ``javascript:...`` / ``data:...``，
                # 也要在赋值前拦下，避免前端最终展示 / 用户点击触发 XSS。
                if SafeLinks._is_http_url(candidate):
                    result.link = candidate
                else:
                    logger.warning(
                        "拒绝非 http(s) link：rule_id=%s prefix=%r",
                        self.rule_id, candidate[:24],
                    )

        return result


def first_match(extractors: Iterable[Extractor], mails: Iterable[dict]) -> Optional[ExtractedResult]:
    """对一批邮件按时间倒序逐封尝试每个 extractor，返回首个成功结果。

    调用方负责把 mails 排好序（最近优先）。
    """
    for mail in mails:
        for ex in extractors:
            if not ex.match(mail):
                continue
            result = ex.extract(mail)
            if result.has_payload():
                return result
    return None
