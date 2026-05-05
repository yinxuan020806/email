# -*- coding: utf-8 -*-
"""验证码 / Magic-Link 提取器。

每个提取器对应一个分类（cursor / openai / ...），由 ``base.Extractor`` 描述。
``registry.get_extractors(category)`` 返回该分类下所有提取器（含 DB 中
``extractor_rules`` 表的动态规则与代码内置默认规则的合并）。
"""

from extractors.base import (  # noqa: F401
    ExtractedResult,
    Extractor,
    SafeLinks,
)
from extractors.registry import get_extractors  # noqa: F401
