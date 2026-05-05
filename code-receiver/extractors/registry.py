# -*- coding: utf-8 -*-
"""提取器注册表：合并代码内置默认规则 + DB 中 extractor_rules 的动态规则。"""

from __future__ import annotations

import logging
from typing import Callable, Dict, List, Optional

from extractors.base import Extractor
from extractors import cursor as _cursor
from extractors import openai_chatgpt as _openai


logger = logging.getLogger(__name__)


# 内置默认规则，按 category 索引
_BUILTIN: Dict[str, Callable[[], List[Extractor]]] = {
    "cursor": _cursor.default_rules,
    "openai": _openai.default_rules,
}


def get_extractors(
    category: str,
    db_rules_loader: Optional[Callable[[str], List[dict]]] = None,
) -> List[Extractor]:
    """返回该分类下所有提取器，按 priority 降序。

    Args:
        category: 'cursor' / 'openai' / ...
        db_rules_loader: 可选回调，传入 category 返回 DB 中的 ``extractor_rules`` 行
            （见 ``DatabaseManager.list_extractor_rules``）。None 表示只用内置规则。
    """
    cat = (category or "").lower()
    rules: List[Extractor] = []

    builtin_factory = _BUILTIN.get(cat)
    if builtin_factory:
        try:
            rules.extend(builtin_factory())
        except Exception:
            logger.exception("加载内置规则失败 cat=%s", cat)

    if db_rules_loader:
        try:
            for row in db_rules_loader(cat):
                try:
                    rules.append(
                        Extractor.from_strings(
                            category=row.get("category", cat),
                            sender_pattern=row.get("sender_pattern", ""),
                            subject_pattern=row.get("subject_pattern", ""),
                            code_regex=row.get("code_regex", ""),
                            link_regex=row.get("link_regex", ""),
                            priority=int(row.get("priority", 0)),
                            rule_id=row.get("id"),
                        )
                    )
                except Exception:
                    logger.exception("加载 DB 规则失败 row=%s", row)
        except Exception:
            logger.exception("调用 db_rules_loader 失败 cat=%s", cat)

    rules.sort(key=lambda r: r.priority, reverse=True)
    return rules
