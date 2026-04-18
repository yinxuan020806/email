# 邮箱管家 Web

> 批量邮箱账号管理工具的 Web 版本。支持 Outlook OAuth2 与通用 IMAP/SMTP，提供导入、检测、收发邮件、批量操作等能力。

---

## 特性

- **纯 Web 架构** — FastAPI + 单页前端，无需安装桌面客户端
- **加密存储** — 账号密码、refresh_token 全部 Fernet 加密；主密钥独立保管
- **多账号管理** — 分组、备注、批量检测、批量发信
- **多协议** — Microsoft Graph API、Outlook REST API、IMAP/SMTP
- **AWS 验证码识别** — 自动标记收到 Amazon/AWS 邮件的账号
- **可选 Token 鉴权** — 局域网开放时启用 `EMAIL_WEB_TOKEN`
- **HTTPS 支持** — 通过环境变量挂载证书；附带自签证书生成脚本
- **中英双语** — 前端实时切换 zh/en
- **测试覆盖** — 42 个 pytest 测试覆盖核心逻辑（DB / 加密 / API / 路由）

---

## 目录结构

```
email/
├── core/
│   ├── email_client.py       # 统一 Facade
│   ├── imap_client.py        # IMAP / SMTP 实现
│   ├── graph_client.py       # Microsoft Graph / Outlook REST 实现
│   ├── oauth_token.py        # OAuth access_token 管理
│   ├── oauth2_helper.py      # OAuth 授权码换取 refresh_token
│   ├── folder_map.py         # 文件夹名映射
│   ├── mail_parser.py        # RFC 822 解析辅助
│   ├── server_config.py      # 邮件服务器配置注册表
│   ├── security.py           # Fernet 加解密
│   └── models.py             # 类型化数据模型
├── database/
│   └── db_manager.py         # SQLite 持久化、版本化迁移、WAL
├── static/                   # 前端资源
│   ├── index.html
│   ├── app.css
│   ├── app.js
│   └── i18n.js
├── scripts/
│   └── gen_cert.py           # 自签 TLS 证书生成
├── tests/                    # pytest 测试
│   ├── test_security.py
│   ├── test_db.py
│   ├── test_email_client.py
│   └── test_web_app.py
├── data/                     # 运行时数据 (gitignored)
│   ├── emails.db             # SQLite 数据库
│   └── .master.key           # 主密钥（首次启动自动生成）
├── web_app.py                # FastAPI 入口
├── requirements.txt
└── requirements-dev.txt
```

---

## 安装与启动

```powershell
# 1. 创建虚拟环境
python -m venv .venv
.\.venv\Scripts\activate

# 2. 安装依赖
pip install -r requirements.txt

# 3. 启动 (默认 127.0.0.1:8000，仅本地)
python web_app.py
```

浏览器访问 <http://localhost:8000>。

---

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `EMAIL_WEB_HOST` | `127.0.0.1` | 监听地址 |
| `EMAIL_WEB_PORT` | `8000` | 监听端口 |
| `EMAIL_WEB_TOKEN` | _空_ | 设置后所有 `/api/*` 需要 `Authorization: Bearer <token>` |
| `EMAIL_WEB_CORS` | _空_ | 逗号分隔的额外允许跨域来源；默认仅同源 |
| `EMAIL_WEB_LOG_LEVEL` | `INFO` | 日志级别 |
| `EMAIL_WEB_SSL_KEY` | _空_ | TLS 私钥路径（PEM） |
| `EMAIL_WEB_SSL_CERT` | _空_ | TLS 证书路径（PEM） |
| `EMAIL_OAUTH_CLIENT_ID` | Thunderbird ID | 自托管 Azure 应用时填入自己的 client_id |
| `EMAIL_OAUTH_REDIRECT_URI` | `https://localhost` | OAuth 授权回调地址 |

---

## HTTPS 部署

开放到内网/公网时**必须**启用 TLS，避免 token 与账号密码被嗅探。

```powershell
# 1. 生成自签证书（绑定 localhost、127.0.0.1，可加 --hosts 192.168.x.y）
python scripts/gen_cert.py --hosts 192.168.1.100,mail.local

# 2. 设置环境变量启动
$env:EMAIL_WEB_HOST     = "0.0.0.0"
$env:EMAIL_WEB_TOKEN    = "Use-A-Long-Random-String"
$env:EMAIL_WEB_SSL_KEY  = "data/server.key"
$env:EMAIL_WEB_SSL_CERT = "data/server.crt"
python web_app.py
```

如使用 nginx / caddy 反向代理，则后端只绑 `127.0.0.1` 不挂证书即可。

---

## 容器化部署

仓库已附带 `Dockerfile` + `docker-compose.yml`。

```bash
# 1. 编辑 docker-compose.yml 取消 EMAIL_WEB_TOKEN 注释并填入随机字符串
# 2. 启动
docker compose up -d

# 数据将持久化到当前目录的 data/，注意定期备份 data/.master.key + data/emails.db
```

镜像基于 `python:3.12-slim`，非 root（uid=10001）运行，自带 healthcheck。

> 📘 **腾讯云 + 宝塔 + 无备案域名**的完整图文部署教程见 [`docs/deploy-tencent-baota.md`](docs/deploy-tencent-baota.md)，包含 Cloudflare Tunnel 内网穿透、自动备份、安全加固、故障排查等。
>
> 🔁 **日常更新（git push → 一键部署）**速查：[`docs/redeploy-quickstart.md`](docs/redeploy-quickstart.md)。
>
> 📋 **某次实际部署后的交接摘要**（架构、路径、Tunnel、权限坑、重部署命令模板）见 [`docs/redeploy-handover.md`](docs/redeploy-handover.md)。

---

## 云上免费部署对比

> ⚠️ **不能直接部署到 Cloudflare Workers/Pages**：项目依赖 SQLite 文件系统、IMAP/SMTP TCP socket、`cryptography` C 扩展，三者在 Workers 沙箱里都不可用。

| 平台 | 适合度 | 备注 |
| --- | --- | --- |
| **Render Web Service (Free)** | ⭐⭐⭐⭐⭐ | 一键 Docker 部署，自带 HTTPS，免费 750h/月；15 分钟无请求会休眠 |
| **Fly.io (Free Allowance)** | ⭐⭐⭐⭐⭐ | 3 台 256MB VM 永久免费，支持持久卷 (`fly volumes`) |
| **Railway**                 | ⭐⭐⭐⭐  | 试用 $5 额度，部署简单，付费后稳定 |
| **Hugging Face Spaces (Docker)** | ⭐⭐⭐ | 永久免费，但 Space 名公开可见，不太私密 |
| **Oracle Cloud Always Free VM** | ⭐⭐⭐⭐⭐ | 4 vCPU + 24GB RAM 永久免费，自由度最高，需要会基础 SSH 运维 |
| **Cloudflare Tunnel + 本地** | ⭐⭐⭐⭐  | 服务跑本机，Tunnel 提供反代/HTTPS，无需暴露公网端口 |
| **Cloudflare Workers/Pages** | ❌      | 架构不兼容（无文件系统 / 无原生 socket / 无 C 扩展） |

**Fly.io 部署示例**（最便宜的方案之一）：

```bash
# 安装 flyctl 后
fly launch --no-deploy           # 生成 fly.toml
fly volumes create data --size 1
fly secrets set EMAIL_WEB_TOKEN=$(openssl rand -hex 32)
fly deploy
```

记得在 `fly.toml` 里挂载 volume：

```toml
[[mounts]]
  source = "data"
  destination = "/data"
```

---

## 安全说明

1. **主密钥** `data/.master.key` 仅本机有效；备份/换机务必连同 `emails.db` 一起迁移，否则旧密文不可解。
2. 数据库与主密钥都已加入 `.gitignore`；切勿提交到代码仓库。
3. 邮件正文渲染使用 `<iframe sandbox>` 隔离，HTML 邮件无法访问主页面 DOM、cookie、token。
4. 默认绑定 `127.0.0.1`，外部网络无法访问；开放到内网请同时设置 Token 与 TLS。
5. 所有用户输入在前端均以 `textContent` 写入 DOM，杜绝拼接 XSS。
6. **OAuth client_id**：内置 Thunderbird 公开 ID 仅供个人本地使用。商用建议在 [Azure Portal](https://portal.azure.com) 注册自己的应用，通过 `EMAIL_OAUTH_CLIENT_ID` 与 `EMAIL_OAUTH_REDIRECT_URI` 覆盖。

---

## 账号导入格式

每行一个账号，使用 `----` 分隔字段：

```
普通邮箱:
example@gmail.com----password123

OAuth2 (Outlook):
me@outlook.com----password----<client_id>----<refresh_token>
```

也支持 `$$` 作为账号分隔符，便于一行多账号。

---

## 旧库迁移

从 v1（明文密码）升级到 v2 时，`DatabaseManager` 会自动检测 `PRAGMA user_version`，把所有明文 password / refresh_token 加密升级为 v2 格式。该过程仅执行一次。

---

## 开发与测试

```powershell
# 安装开发依赖
pip install -r requirements-dev.txt

# 运行测试套件（约 4 秒，42 个用例）
python -m pytest tests -q

# 仅跑指定测试
python -m pytest tests/test_db.py -v
```

测试覆盖：
- `test_security.py` — Fernet 加解密、密钥持久化、密文幂等
- `test_db.py` — CRUD、孤儿分组、rowcount 准确性、settings 白名单
- `test_email_client.py` — Facade 路由判断、文件夹映射
- `test_web_app.py` — 端点鉴权、参数校验、bug 回归

代码约定：
- Python ≥ 3.10
- 不直接拼 SQL，参数全部 placeholder
- 异常捕获必须指定具体异常 + `logger.exception`
- 所有 settings 写入需在 `ALLOWED_SETTING_KEYS` 白名单中
- 涉及加密字段读写必须经过 `SecretBox`
