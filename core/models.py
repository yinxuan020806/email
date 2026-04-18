# -*- coding: utf-8 -*-
"""
数据模型定义 - 所有跨层传递的数据结构

替代原来的 raw tuple，提供类型安全的字段访问。
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Account:
    """邮箱账号模型，与 accounts 表一一对应。

    字段顺序与 SELECT * 的列顺序一致，方便从 DB tuple 迁移。
    """
    id: int
    email: str
    password: str
    group_name: str = '默认分组'
    status: str = '未检测'
    account_type: str = '普通'
    imap_server: Optional[str] = None
    imap_port: int = 993
    smtp_server: Optional[str] = None
    smtp_port: int = 465
    client_id: Optional[str] = None
    refresh_token: Optional[str] = None
    created_at: Optional[str] = None
    last_check: Optional[str] = None
    has_aws_code: int = 0
    remark: Optional[str] = None

    # ── 字段顺序，用于 __getitem__ 兼容桥 ──
    _FIELD_ORDER = (
        'id', 'email', 'password', 'group_name', 'status', 'account_type',
        'imap_server', 'imap_port', 'smtp_server', 'smtp_port',
        'client_id', 'refresh_token', 'created_at', 'last_check',
        'has_aws_code', 'remark',
    )

    def to_dict(self) -> dict:
        """JSON 序列化（用于 Web API 响应）。"""
        d = asdict(self)
        # 确保时间字段为字符串
        for key in ('created_at', 'last_check'):
            if d[key] is not None:
                d[key] = str(d[key])
        # bool 化 has_aws_code
        d['has_aws_code'] = bool(d['has_aws_code'])
        return d

    @classmethod
    def from_row(cls, row: tuple) -> Account:
        """从 DB 原始 tuple 构建 Account。

        集中处理所有 len(acc)>N 的防御逻辑，替代散落在 10+ 处的重复代码。
        """
        if row is None:
            raise ValueError("Cannot create Account from None row")
        # 填充到 16 个字段，缺失的用 None
        padded = tuple(row) + (None,) * max(0, 16 - len(row))
        return cls(
            id=padded[0],
            email=padded[1] or '',
            password=padded[2] or '',
            group_name=padded[3] or '默认分组',
            status=padded[4] or '未检测',
            account_type=padded[5] or '普通',
            imap_server=padded[6],
            imap_port=padded[7] if padded[7] is not None else 993,
            smtp_server=padded[8],
            smtp_port=padded[9] if padded[9] is not None else 465,
            client_id=padded[10],
            refresh_token=padded[11],
            created_at=str(padded[12]) if padded[12] else None,
            last_check=str(padded[13]) if padded[13] else None,
            has_aws_code=padded[14] if padded[14] is not None else 0,
            remark=padded[15],
        )

    # ── 临时兼容桥（步骤6中删除）──────────────────────────
    def __getitem__(self, index: int):
        """允许 acc[0]、acc[1] 等旧风格访问，保持向后兼容。"""
        if isinstance(index, int) and 0 <= index < len(self._FIELD_ORDER):
            return getattr(self, self._FIELD_ORDER[index])
        raise IndexError(f"Account index {index} out of range")

    def __len__(self) -> int:
        """支持 len(acc) > N 守卫。"""
        return 16


@dataclass
class ServerProfile:
    """邮件服务器连接配置。"""
    imap_host: str
    imap_port: int
    smtp_host: str
    smtp_port: int
    use_ssl: bool = True
