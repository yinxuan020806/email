# -*- coding: utf-8 -*-
"""
应用版本号解析（管理端 + 接码前台共享）。

优先级：
1. ``APP_VERSION`` 环境变量（容器部署 / deploy.sh 写到 .env）
2. ``git rev-parse --short=8 HEAD`` —— 本地从 git 仓库源码直接跑时自动读
3. 字符串 ``"dev"`` —— fallback，仅在前两者都拿不到时使用

容器场景（Dockerfile 不 COPY .git）：
- 步骤 1 由 docker-compose.yml 的 ``APP_VERSION: ${APP_VERSION:-dev}`` 注入
- ``deploy.sh`` 在宿主机写 ``.env``，把 git short SHA 透传到容器
- 失败 fallback 到 "dev" 时前端会 **不加 ``v`` 前缀**（防止显示 ``vdev`` 这种怪样子）
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Union


_FALLBACK_VERSION = "dev"
_VERSION_MAX_LEN = 32

PathLike = Union[str, Path]


def _try_git_short_sha(repo_root: Optional[PathLike] = None) -> Optional[str]:
    """尝试通过 git 拿当前 commit 的 short SHA（8 位）。

    任何异常都吞掉返回 None —— 没装 git / 不是 git 仓库 / git binary 不在 PATH /
    远程子模块解析失败都让 fallback 兜底，绝不让"读 git 失败"阻断启动。
    """
    if shutil.which("git") is None:
        return None
    cwd: Optional[str] = None
    if repo_root is not None:
        cwd = str(repo_root)
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short=8", "HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if result.returncode != 0:
        return None
    sha = (result.stdout or "").strip()
    # short SHA 必须是 [0-9a-f]，长度 <= 8；若 git 输出异常（含换行/空白）就丢弃
    if not sha or not all(c in "0123456789abcdef" for c in sha) or len(sha) > 8:
        return None
    return sha


def resolve_app_version(repo_root: Optional[PathLike] = None) -> str:
    """按优先级解析当前应用版本号。

    Args:
        repo_root: 可选的 git 仓库根目录（``str`` 或 ``Path`` 都接受）。
                   None 则在当前进程 cwd 上跑 git。web_app.py /
                   code-receiver/app.py 启动时 cwd 不一定是仓库根，
                   传入 ``Path(__file__).resolve().parent`` 这类路径更稳。

    Returns:
        长度被截到 ``_VERSION_MAX_LEN`` 的版本字符串；永不返回空串或 None。
    """
    env_value = (os.getenv("APP_VERSION") or "").strip()
    if env_value:
        return env_value[:_VERSION_MAX_LEN]

    git_sha = _try_git_short_sha(repo_root=repo_root)
    if git_sha:
        return git_sha

    return _FALLBACK_VERSION
