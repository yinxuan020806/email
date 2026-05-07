# -*- coding: utf-8 -*-
"""
应用版本号解析（管理端 + 接码前台共享）。

优先级：
1. ``APP_VERSION`` 环境变量（部署期临时覆盖用）
2. ``__version__`` 常量 —— **代码内置语义化版本号**（默认走这条）
3. 字符串 ``"dev"`` —— 极端 fallback（理论上永远不会用到）

发版流程：直接修改 ``__version__`` 常量、git tag 一下、push 即可。
不再依赖 git short SHA / deploy.sh 注入 / 任何外部状态，前端右下角看到
的就是这个常量值，简洁直观。
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union


# ── 当前发版版本号 ───────────────────────────────────────────────
# 修改流程：
#   1. 这里 bump 版本号（语义化版本：MAJOR.MINOR.PATCH）
#   2. git commit -am "release: vX.Y.Z"
#   3. git tag vX.Y.Z
#   4. git push --tags
__version__: str = "1.0.1"
"""当前应用版本号（语义化）。bump 即发版。"""


_FALLBACK_VERSION = "dev"
_VERSION_MAX_LEN = 32

PathLike = Union[str, Path]


def resolve_app_version(repo_root: Optional[PathLike] = None) -> str:  # noqa: ARG001
    """按优先级解析当前应用版本号。

    Args:
        repo_root: 历史签名兼容参数（之前用于 git rev-parse 的 cwd），
                   现已不再使用 git，参数保留只为不破坏调用方。下一次
                   重构可移除。

    Returns:
        长度被截到 ``_VERSION_MAX_LEN`` 的版本字符串；永不返回空串或 None。
    """
    env_value = (os.getenv("APP_VERSION") or "").strip()
    if env_value:
        return env_value[:_VERSION_MAX_LEN]

    if __version__:
        return __version__[:_VERSION_MAX_LEN]

    return _FALLBACK_VERSION
