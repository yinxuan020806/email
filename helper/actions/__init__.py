"""Helper 业务 action 子包。

每个 action 都是 ``(params, log) -> dict`` 的纯函数；由
``helper.handlers.install_default_handlers`` 在 client 启动时统一注册。
"""
