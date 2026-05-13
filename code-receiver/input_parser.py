# -*- coding: utf-8 -*-
"""用户输入凭据解析（v8: 仅 ``email----token`` 双段格式）。

历史背景
--------
v7 之前接码端支持 5 种输入格式（裸邮箱 / IMAP 密码 / OAuth 等），其中
"仅邮箱"路径让任何人只要知道邮箱地址就能抓到验证码——只有站长侧的
``is_public`` 白名单做防护，但凭据本身不是秘密，相当于"密码=邮箱"。

v8 收紧成"双因子"：
- 站长在管理端为每个公开账号生成 6 位 ``access_token``（邮箱凭证）
- 前台必须输入 ``email----token`` 才能换验证码
- 站长可随时旋转 token，老链接立即失效，**无需**碰真实邮箱密码

本模块只负责把"用户输入字符串"拆成 ``(email, access_token)``；
所有 IMAP/OAuth/refresh_token 业务字段都已下线（byo 路径在 v6 就关了）。

支持的输入形态
--------------
- ``email----token``  规范形式，两段以 ``----`` 分隔
- ``email``           仅邮箱（v8 起一律 422 拒绝，但解析阶段宽松接受
                      让上层用 ``needs_token`` 字段判别后回包更友好的错误）

非规范形式（3 段及以上）一律按"前 2 段是 email/token，其余忽略"处理，
避免用户多复制了个换行被严格拒绝。
"""

from __future__ import annotations

import re
from dataclasses import dataclass


_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
# token：4 - 16 位，仅字符集中的字符（与 core.security.ACCESS_TOKEN_ALPHABET 对齐）。
# 这里做语法预校验是为了让"用户拼写错 / 多复制了空格"在解析阶段就被拒绝，
# 比走完限流→DB 查询→token 比对的全流程后再返回 401 体验好得多。
#
# 字符类直接复刻字符集字面量（不用 A-H 这种区间）—— 上次手写区间漏了 L，
# 让合法 token "Vb4xL8" 被错误拒绝；用字面量集合最不容易出错。
_TOKEN_RE = re.compile(
    r"^[ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789]{4,16}$"
)


@dataclass
class ParsedCredential:
    """解析后的凭据（绝不可序列化进日志）。"""

    email: str
    access_token: str = ""
    needs_token: bool = False
    """True 表示用户只输入了邮箱地址、还差凭证 → 上层应回 401 提示补 token。"""

    def __repr__(self) -> str:
        masked = "***" if self.access_token else ""
        return (
            f"ParsedCredential(email={self.email!r}, access_token={masked!r}, "
            f"needs_token={self.needs_token})"
        )


class InputParseError(ValueError):
    """输入格式不合法。"""


def parse_user_input(text: str) -> ParsedCredential:
    """解析单行用户输入；不合法的整体格式抛 ``InputParseError``。

    解析策略：
    - 空输入 → ``InputParseError``
    - 第 1 段必须是合法邮箱 → 否则 ``InputParseError``
    - 仅邮箱（无 ``----``）→ 返回 ``needs_token=True``，由 app 路由层
      回 401 提示用户补凭证（这里不抛错，保留更柔和的错误体验）
    - 含 ``----`` 但第 2 段不是合法 6 位凭证 → ``InputParseError``
      （token 字符集预校验，避免把 "abc 123" / 包含 ``$`` 这类一眼就错的输入
      送进 DB 比对）
    - 多余的 ``----`` 段（3 段及以上）一律忽略
    """
    if not text or not text.strip():
        raise InputParseError("输入为空")

    raw = text.strip()
    fields = [f.strip() for f in raw.split("----")]

    email = fields[0]
    if not _EMAIL_RE.match(email):
        raise InputParseError("第一段不是合法邮箱地址")

    if len(fields) == 1:
        # 只有邮箱：不抛错，标记为"缺凭证"让上层回一个明确提示
        return ParsedCredential(email=email, needs_token=True)

    token = fields[1]
    if not token:
        return ParsedCredential(email=email, needs_token=True)
    if not _TOKEN_RE.match(token):
        raise InputParseError("凭证错误")

    # 多余字段忽略：用户从分发链接粘贴时常带尾随空白或额外 ----
    return ParsedCredential(email=email, access_token=token)
