# -*- coding: utf-8 -*-
"""
启动时安全检查 - 提示而非中止。

仅做 POSIX 平台的目录与主密钥权限检测（Windows 因 chmod 是 no-op，跳过）。
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import List


logger = logging.getLogger(__name__)


def check_data_dir(data_dir: Path) -> List[str]:
    """返回一组警告消息（空列表表示一切正常）。"""
    warnings: List[str] = []

    if sys.platform.startswith("win"):
        return warnings

    if not data_dir.exists():
        return warnings

    try:
        st = data_dir.stat()
        mode = st.st_mode & 0o777
        if mode & 0o077:
            warnings.append(
                f"数据目录权限过宽 ({oct(mode)})，建议执行: chmod 700 {data_dir}"
            )
    except OSError as exc:
        logger.debug("无法读取 %s 的权限: %s", data_dir, exc)

    key_path = data_dir / ".master.key"
    if key_path.exists():
        try:
            st = key_path.stat()
            mode = st.st_mode & 0o777
            if mode & 0o077:
                warnings.append(
                    f"主密钥权限过宽 ({oct(mode)})，建议执行: chmod 600 {key_path}"
                )
        except OSError:
            pass

    db_path = data_dir / "emails.db"
    if db_path.exists():
        try:
            st = db_path.stat()
            mode = st.st_mode & 0o777
            if mode & 0o077:
                warnings.append(
                    f"数据库权限过宽 ({oct(mode)})，建议执行: chmod 600 {db_path}"
                )
        except OSError:
            pass

    if data_dir.exists() and key_path.exists() and db_path.exists():
        try:
            data_real = data_dir.resolve()
            key_real = key_path.resolve()
            if key_real.parent == data_real:
                warnings.append(
                    "主密钥与数据库位于同一目录；备份/迁移时请同时拷贝两者，"
                    "且建议把 .master.key 单独额外保管一份。"
                )
        except OSError:
            pass

    return warnings


def emit_warnings(data_dir: Path) -> None:
    """打印检查结果到日志和 stderr。"""
    for w in check_data_dir(data_dir):
        logger.warning(w)
        print(f"  [SECURITY] {w}", file=sys.stderr)
