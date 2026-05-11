# Email Helper

邮箱管家的本地客户端，让 Web 面板能在你的电脑上自动操作 Outlook 邮箱浏览器。

## 功能

| Action                    | 说明                                  | Stage |
| ------------------------- | ------------------------------------- | ----- |
| `echo` / `ping` / `version` | 连通性测试                            | 1     |
| `open_mailbox`            | 启动浏览器、自动登录 Outlook 并保持   | 2     |
| `get_ms_token`            | 完成 MS OAuth2 → 拿 refresh_token     | 2     |
| `change_email_password`   | 自动修改 Outlook 密码                 | 2     |
| `bind_recovery_email`     | 自动绑定辅助邮箱                      | 2     |

> **Stage 1** 当前已完成：完整长轮询架构 + 客户端 + Web 面板 UI。  
> **Stage 2** 待移植：DrissionPage 浏览器自动化（约 3000 行代码）。

## 安装（用户视角）

1. 用 `xiaoxuan` 账号登录 Web 面板
2. 点侧边栏 **「📬 邮箱助手」**
3. 点 **「📥 下载」** 拿到 `EmailHelper.exe` + `install.ps1` + `uninstall.ps1`
4. 把三个文件放同一目录，右键 `install.ps1` → "用 PowerShell 运行"
5. 系统托盘出现 Email Helper 图标
6. 回 Web 面板点 **「🚀 启动助手」** 完成首次绑定

完全用 HKCU 注册表，无需管理员权限。

### 如果第 4 步被 ExecutionPolicy 拒绝

Windows 10/11 默认 PowerShell ExecutionPolicy 是 `Restricted`，会直接拒绝运行
.ps1 脚本。两种解决方案，任选其一：

**方案 A：临时绕过（推荐 — 不改全局策略）**

直接在 PowerShell 里跑：

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

**方案 B：永久放开（仅当前用户）**

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# 之后右键 install.ps1 → "用 PowerShell 运行" 才会生效
```

`RemoteSigned` 只允许本地脚本运行，从网络下载的脚本必须签名 — 安全性
相对 `Bypass` 更高。

## 卸载

右键 `uninstall.ps1` → 用 PowerShell 运行。会清理：

- `%LOCALAPPDATA%\EmailHelper` 安装目录
- `%APPDATA%\EmailHelper` 配置目录（`-KeepConfig` 可保留）
- 开机自启注册表项
- `emailhelper://` URL 协议注册

## 开发者：从源码运行

```powershell
cd D:\1\0-email\email
# 装依赖
pip install -r helper\requirements.txt
# 运行（debug 模式 + 不加载托盘，便于看日志）
python helper\main.py --no-tray --debug --token <从面板拿到的 token> --server http://127.0.0.1:8000
```

## 开发者：打包成 .exe

```powershell
cd D:\1\0-email\email
powershell -ExecutionPolicy Bypass -File helper\build.ps1
# 增量构建跑得快；首次或换依赖时加 -Clean
powershell -ExecutionPolicy Bypass -File helper\build.ps1 -Clean
```

产物：

- `helper\dist\EmailHelper.exe`
- 同时拷贝到 `static\helper\EmailHelper.exe`（Web 面板下载按钮直接给用户）

## 文件结构

```
helper/
├── __init__.py            版本号
├── main.py                CLI 入口（含 --silent / --install-protocol 等）
├── config.py              %APPDATA%/EmailHelper/config.json 读写
├── client.py              HTTP 长轮询客户端 + 任务执行
├── handlers.py            action 分发表
├── protocol.py            emailhelper:// URL 协议注册
├── autostart.py           开机自启
├── tray.py                pystray 系统托盘
├── actions/
│   ├── __init__.py
│   └── mailbox.py         邮箱相关 action（Stage 1 = stub）
├── install.ps1            用户安装脚本
├── uninstall.ps1          用户卸载脚本
├── build.ps1              开发者打包脚本
├── requirements.txt
└── README.md
```

## 通信协议（HTTP 长轮询）

Helper 启动后：

1. `POST /api/helper/register` 提交 token → 拿 `helper_id`
2. 循环 `GET /api/helper/poll-task?helper_id=...` 阻塞最多 25s 等任务
3. 收到任务后异步执行，期间通过 `POST /api/helper/task-log` 推日志
4. 完成后 `POST /api/helper/task-result` 报结果
5. 后台线程每 20s 发一次 `POST /api/helper/heartbeat`

服务端可同时只处理一个用户对应的一个在线 helper。同一 token 重连会顶替旧
session。

## 为什么不用 WebSocket

uvicorn 原生支持 WS，但要保证多 worker / Cloudflare / Nginx 反代下连接稳
定，HTTP 长轮询是更鲁棒的选择。延迟 300ms-1s，业务场景完全可接受。

## 安全

- `emailhelper://` URL 协议拉起后，token 通过 query string 落到 `config.json`
  （`%APPDATA%/EmailHelper/`）。 该文件仅当前用户可读。
- helper 与服务端通信用 token 鉴权，token 30 天不用自动失效。
- 只有 `xiaoxuan` 用户能在 Web 面板生成 / 撤销 token，普通用户拿不到入口
  也拿不到 token。
