# -*- coding: utf-8 -*-
"""Code Receiver — Cursor / OpenAI 验证码接码前台。

与 ../email/ 共用 data/emails.db 与 .master.key，但仅以受限只读 + 受限写
（仅 code_query_log 与 query_count 自增）方式访问，不持有 accounts / users 写权限。
"""
