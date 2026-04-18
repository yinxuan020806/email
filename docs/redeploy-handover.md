# 部署会话交接说明（便于重新部署）

> 本文档根据一次实际部署过程整理，用于**换机重装、迁移、或半年后自己重做**时对照。  
> **不要**把真实 Token、Tunnel 安装命令、数据库备份包提交到公开仓库。

---

## 1. 整体架构（本次最终形态）

```
用户浏览器
  → HTTPS（Cloudflare 边缘证书）
  → Cloudflare Tunnel（cloudflared，出站连接，无需服务器开放 80/443）
  → 腾讯云轻量 127.0.0.1:8000
  → Docker 容器 email-web（FastAPI + 静态前端 + SQLite 数据卷）
```

- **公网入口域名（示例）**：`https://mail.<你的域名>`（本次为 `mail.evuzdnd.cn`）。
- **服务器无需备案即可 HTTPS**：流量经 Cloudflare，不依赖国内 ICP 备案的 80/443。
- **宝塔面板**：仅用于上传文件、终端、计划任务；应用本身不依赖 Nginx 站点。

---

## 2. 环境与路径（请按实际填写）

| 项目 | 本次会话中的值 / 说明 |
| --- | --- |
| 云厂商 | 腾讯云轻量应用服务器 |
| 公网 IP（示例） | `106.53.4.248`（仅作记录，生产可配合 Tunnel 隐藏） |
| 系统 | OpenCloudOS 9（RHEL 系，yum/dnf） |
| 面板 | 宝塔 Linux 面板 |
| 项目根目录 | `/www/wwwroot/email` |
| 持久化数据目录（宿主机） | `/www/wwwroot/email/data`（挂载到容器内 `/data`） |
| 上传的临时包（若用过） | `/www/wwwroot/email-deploy.zip`（可删，仅部署用） |
| Docker Compose 文件 | `/www/wwwroot/email/docker-compose.yml` |

---

## 3. Docker 与 Compose 要点

- **镜像构建**：仓库自带 `Dockerfile` + `docker-compose.yml`。
- **端口**：`127.0.0.1:8000:8000`（只监听本机，由 Tunnel 访问，勿把 8000 直接暴露公网）。
- **环境变量**：
  - `EMAIL_WEB_HOST=0.0.0.0`、`EMAIL_WEB_PORT=8000`
  - `EMAIL_WEB_TOKEN`：**强随机字符串**（`openssl rand -hex 32`），设置后所有 `/api/*` 需 `Authorization: Bearer <token>`。
  - `EMAIL_DATA_DIR`：容器内默认 `/data`，与卷 `./data:/data` 对应。
- **国内构建加速（可选）**：在 `Dockerfile` 里为 `pip install` 增加清华源，例如：
  - `RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt`
- **权限坑（重要）**：容器内进程用户为 **uid 10001**。若宿主机 `data/` 为 root 且 `chmod 700`，容器会无法写入 `.master.key`。修复：
  - `chown -R 10001:10001 /www/wwwroot/email/data`

---

## 4. Cloudflare Tunnel（Zero Trust → Connectors）

- **控制台路径（2026 年 UI）**：Cloudflare Dashboard → Zero Trust / Cloudflare One → **Networks → Connectors**（旧文档里的 “Tunnels” 可能重定向到此）。
- **本次 Tunnel 名称**：`email-web`（可自行命名）。
- **连接器**：**Cloudflared**；服务器系统类型选 **Red Hat**（OpenCloudOS/RHEL 系用 yum 仓库安装 `cloudflared`）。
- **安装方式概要**：
  1. 添加官方 repo：`curl -fsSl https://pkg.cloudflare.com/cloudflared.repo | sudo tee /etc/yum.repos.d/cloudflared.repo`
  2. `sudo yum install -y cloudflared`
  3. 在 Tunnel 配置页复制 **`sudo cloudflared service install <token>`**（**token 极敏感**，勿泄露）。
  4. `systemctl status cloudflared` 应为 **active**，日志中可见 Registered tunnel connection。
- **路由（Published application）**：
  - **Subdomain**：`mail`（或你自定义）
  - **Domain**：在 Cloudflare 托管的域名（本次 `evuzdnd.cn`）
  - **Path**：留空表示全路径（若填 `^/blog` 则只匹配以 `/blog` 为前缀的路径，容易误配）
  - **Service Type**：**HTTP**（后端为 `http://127.0.0.1:8000`，勿选 HTTPS 除非本机有证书）
  - **URL**：`127.0.0.1:8000`

---

## 5. 安全与运维清单

### 5.1 必须做

- [ ] **轮换 `EMAIL_WEB_TOKEN`**：部署过程若出现在聊天/截图中，应在服务器上重新生成并 `docker compose up -d`。
- [ ] **备份**：定期备份 **`data/.master.key` + `data/emails.db`**（两者必须成对；缺任一无法解密）。
- [ ] **腾讯云防火墙**：至少放行 SSH + 宝塔端口；**不必**为应用单独开放 8000（经 Tunnel 访问）。

### 5.2 建议做

- [ ] 宝塔：**强密码**、必要时开启面板 SSL、缩小面板暴露面。
- [ ] SSH：密钥登录、改端口、`fail2ban` 防爆破（按你环境执行）。
- [ ] 再次确认 Cloudflare Tunnel 的 **service install token** 未泄露；泄露则应在 Cloudflare 侧轮换/重建 Tunnel。

---

## 6. 重新部署时可复用的命令模板（在服务器上执行）

```bash
# 进入项目
cd /www/wwwroot/email

# 生成新 Token 并写入 compose（按你编辑器方式改也行）
NEW=$(openssl rand -hex 32)
sed -i "s|EMAIL_WEB_TOKEN: \".*\"|EMAIL_WEB_TOKEN: \"$NEW\"|" docker-compose.yml
echo "请保存新 Token: $NEW"

# 数据目录权限（首次或换机后）
mkdir -p data
chown -R 10001:10001 data

# 构建并启动
docker compose up -d --build

# 本机健康检查
curl -s http://127.0.0.1:8000/api/health
```

---

## 7. 备份脚本与计划任务（推荐内容）

以下逻辑与《腾讯云宝塔详细部署教程》一致，可在 **`/root/backup-email.sh`** 保存并 `chmod +x`，再用 `crontab -e` 每天执行。

要点：

- 用 `docker compose exec` 对 SQLite 做 **`.backup`**，避免直接拷贝 WAL 时损坏。
- 打包 **`.master.key`** 与备份出来的 `emails.db`（或 `.bak`）。
- 日志：`/var/log/backup-email.log`（路径可改）。

（具体脚本正文以 `docs/deploy-tencent-baota.md` 第 8 节为准，避免此处与仓库双份维护不一致。）

---

## 8. 本次会话中遇到的问题（复现时少走弯路）

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 容器不断重启，`Permission denied` 写 `.master.key` | 宿主机 `data/` 属主与容器 uid 不一致 | `chown -R 10001:10001 data` |
| 外网打不开宝塔 `:8888` | 腾讯云轻量**防火墙**未放行 8888 | 控制台防火墙放行 TCP 8888 |
| Cloudflare 页面找不到旧版 “Tunnels” 路径 | UI 改版 | 使用 **Networks → Connectors** |
| 宝塔网页终端里 Playwright `fill` 不生效 | xterm 依赖真实 `input` 事件 | 用逐字输入或粘贴到「计划任务/文件」执行 |

---

## 9. 文档与仓库内其他说明

- 通用教程（含 Tunnel、备份、FAQ）：[`docs/deploy-tencent-baota.md`](deploy-tencent-baota.md)
- 主 README 容器化小节：[`README.md`](../README.md)

---

## 10. 敏感信息存放建议（不要写进 git）

单独保存在密码管理器或加密笔记中：

- 当前 **`EMAIL_WEB_TOKEN`**（轮换后的值）
- Cloudflare **`cloudflared service install`** 完整命令或 token
- 宝塔面板地址、用户名、密码（若使用）
- SSH 端口与密钥说明

---

*文档生成目的：便于「关闭对话后」仍能独立重做部署；若你后续固定了域名/IP，可自行在副本中替换占位符。*
