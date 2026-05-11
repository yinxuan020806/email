"""Email Helper — 邮箱管家本地客户端

通过 HTTP 长轮询连接到 Web 面板服务器（FastAPI + uvicorn），接收远程派发
的任务（自动打开 Outlook 邮箱 / 自动 OAuth 拿 refresh_token / 自动改密 /
自动绑定辅助邮箱），并在用户电脑上真的启动浏览器执行。

设计目标
--------
- 单文件 .exe 发行（PyInstaller 打包）；卸载干净不留垃圾
- URL 协议拉起：浏览器点「🚀 启动助手」后通过 ``emailhelper://`` 协议
  自动把 token 注入 helper 客户端，零拷贴
- 开机自启 + 系统托盘，托盘菜单显示连接状态
"""

__version__ = "0.1.3"
