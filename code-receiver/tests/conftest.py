# -*- coding: utf-8 -*-
"""Pytest 配置：把 code-receiver/ 与 ../email/ 注入 sys.path。"""

from __future__ import annotations

import os
import sys


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# code-receiver 在 email/ 下作为子目录，向上一级即是 email 项目根
EMAIL_PROJECT = os.path.normpath(os.path.join(ROOT, ".."))

for path in (ROOT, EMAIL_PROJECT):
    if path not in sys.path:
        sys.path.insert(0, path)
