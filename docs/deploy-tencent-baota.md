# 邮箱管家 Web - 腾讯云宝塔详细部署教程

> 适用环境:**腾讯云轻量应用服务器(国内节点) + 宝塔面板 + 域名未备案**
>
> 部署架构:`用户 → Cloudflare(HTTPS+CDN) → Tunnel 加密隧道 → 服务器 Docker 容器`
>
> 总耗时:约 1 小时(其中等域名 NS 切换 15~30 分钟)
>
> 完成后:免备案、自动 HTTPS、服务器零开放端口、自带 5 秒盾防爬

---

## 目录

- [0. 部署前准备清单](#0-部署前准备清单)
- [1. 服务器与宝塔基础环境](#1-服务器与宝塔基础环境)
- [2. 防火墙规则配置](#2-防火墙规则配置)
- [3. 上传项目代码](#3-上传项目代码)
- [4. 配置项目](#4-配置项目)
- [5. 启动 Docker 容器](#5-启动-docker-容器)
- [6. 域名托管到 Cloudflare](#6-域名托管到-cloudflare)
- [7. 配置 Cloudflare Tunnel](#7-配置-cloudflare-tunnel)
- [8. 自动备份配置](#8-自动备份配置必做)
- [9. 安全加固](#9-安全加固)
- [10. 日常运维命令](#10-日常运维命令)
- [11. 故障排查 FAQ](#11-故障排查-faq)
- [12. 部署完成检查清单](#12-部署完成检查清单)

---

## 0. 部署前准备清单

开始之前先确认你已经有以下东西:

| 项目 | 说明 | 备注 |
| --- | --- | --- |
| 腾讯云轻量应用服务器 | 2C2G / 4C4G 都够用 | 国内节点 OK,香港节点连国外邮件更快 |
| SSH 客户端 | Windows: PowerShell / Tabby / WindTerm | 用来连服务器 |
| 一个域名 | 任意注册商,**不需要备案** | 例如 `example.com` |
| Cloudflare 账号 | 免费 plan 即可 | [cloudflare.com](https://cloudflare.com) 注册 |
| 项目代码 | 你的 git 仓库地址 或 zip 包 | |

**关键提醒**:这个项目存的是**你所有邮箱的明文密码 + OAuth refresh_token**,加密主密钥仅本机有效。所以备份必须严肃对待,本教程第 8 节会详细讲。

---

## 1. 服务器与宝塔基础环境

### 1.1 重置系统(可选,推荐 Ubuntu)

腾讯云轻量控制台 → 你的实例 → **重装系统** → 选 **Ubuntu 22.04 LTS**(宝塔兼容性最好)。

> 已经在用其他系统也行(Debian / CentOS / TencentOS),宝塔都支持。

### 1.2 SSH 连接服务器

Windows PowerShell 直接:

```powershell
ssh root@你的服务器公网IP
# 输入腾讯云控制台设置的密码
```

首次连接会询问 `Are you sure you want to continue connecting`,输入 `yes`。

### 1.3 安装宝塔面板

进入服务器后,贴以下命令(Ubuntu/Debian):

```bash
wget -O install.sh https://download.bt.cn/install/install-ubuntu_6.0.sh && bash install.sh ed8484bec
```

> CentOS/TencentOS 的安装命令在 [bt.cn](https://bt.cn) 官网首页,自己复制。

安装结束后会输出类似:

```
==================================================================
【宝塔面板】已成功安装
外网面板地址: https://你的IP:8888/xxxxxxxx
内网面板地址: https://内网IP:8888/xxxxxxxx
username: ABcd1234
password: xyz...
==================================================================
```

**立刻把这三行抄下来**,关闭 SSH 后找不到密码会很麻烦(虽然有 `bt default` 命令能找回)。

### 1.4 登录宝塔做基础设置

浏览器打开 `https://你的IP:8888/xxxxxxxx`(浏览器会警告自签证书,继续访问即可):

1. 输入用户名和密码
2. 进入后弹出**绑定宝塔账号**页面 → 可以选【试用】跳过
3. 弹出推荐安装套件 → **全部不要装**(我们用 Docker,不要装 LNMP)
4. 进入主界面后,左下角【面板设置】:
   - 修改**面板用户**(默认 `admin` 太容易被扫,改成自定义)
   - 修改**面板密码**(强密码)
   - **绑定面板手机/邮箱**(便于找回)

### 1.5 安装 Docker 管理器

宝塔左侧菜单 → 【软件商店】→ 搜索 `Docker`:

- 安装 **Docker 管理器**(版本 2.x 或更高即可)
- 安装时间约 1~2 分钟

### 1.6 安装 Git

继续在【软件商店】搜索 `Git` 安装,或 SSH 里直接:

```bash
apt update && apt install -y git curl wget
```

### 1.7 验证基础环境

SSH 里执行:

```bash
docker --version          # 应该输出 Docker version 2x.x
docker compose version    # 应该输出 Docker Compose version v2.x
git --version             # 应该输出 git version 2.x
```

三个都有版本号就 OK。

---

## 2. 防火墙规则配置

> ⚠️ 腾讯云有**两层防火墙**:云端防火墙(控制台)+ 系统防火墙(宝塔/ufw)。漏配任一层都会导致连不上。

### 2.1 腾讯云控制台防火墙

腾讯云控制台 → 轻量应用服务器 → 你的实例 → **防火墙** 标签页:

**只保留以下两条规则,其他全删**:

| 应用类型 | 协议 | 端口 | 策略 | 备注 |
| --- | --- | --- | --- | --- |
| 自定义 | TCP | 22 | 允许 | SSH |
| 自定义 | TCP | 8888 | 允许 | 宝塔面板 |

**特别强调**:不要开 80、443、8000。Cloudflare Tunnel 是出站连接,不需要任何入站端口。

### 2.2 宝塔系统防火墙

宝塔左侧菜单 → 【安全】:

- 端口规则与腾讯云控制台保持一致(只放 22 + 8888)
- SSH 端口建议**改成非 22**(比如 22122),防爆破

修改 SSH 端口的方法:

```bash
sed -i 's/^#Port 22/Port 22122/' /etc/ssh/sshd_config
systemctl restart sshd
```

然后**腾讯云控制台和宝塔安全里同步**:加 22122 → 测试新端口能登 → 关掉 22。

> 改 SSH 端口前,先用新窗口测试新端口能登录,再关掉旧端口,否则可能把自己锁在外面。

### 2.3 安装 fail2ban 防爆破

```bash
apt install -y fail2ban
systemctl enable --now fail2ban
fail2ban-client status                   # 应该看到 sshd 被监控
```

---

## 3. 上传项目代码

### 方式 A:Git 克隆(推荐)

```bash
cd /www/wwwroot
git clone <你的仓库地址> email
cd email
ls -la
```

应该能看到 `web_app.py`、`Dockerfile`、`docker-compose.yml`、`core/`、`database/`、`static/` 等。

### 方式 B:本地上传(没有 git 仓库时)

1. 本地把项目根目录(`email/`)打包成 zip
2. 宝塔【文件】→ 进入 `/www/wwwroot/`
3. 点【上传】选择 zip → 等上传完成
4. 右键 zip → **解压**
5. 解压完的目录如果叫 `email-main` 之类的,**重命名成 `email`**

### 验证代码结构

```bash
cd /www/wwwroot/email
ls
# 应该看到:
# Dockerfile  README.md  core  database  docker-compose.yml  requirements.txt  scripts  static  tests  web_app.py
```

---

## 4. 配置项目

### 4.1 生成 API Token(必做)

```bash
openssl rand -hex 32
```

输出类似:`8f3a92c1b4e7f9d2a6c1b4e7f9d2a6c18f3a92c1b4e7f9d2a6c1b4e7f9d2a6c1`

**把这串字符复制下来**,后面要写到配置文件里,也要在登录网页时输入。

### 4.2 修改 docker-compose.yml

宝塔【文件】→ `/www/wwwroot/email/docker-compose.yml`,**双击编辑**,改成:

```yaml
services:
  email-web:
    build: .
    image: email-web:latest
    container_name: email-web
    restart: unless-stopped
    ports:
      - "127.0.0.1:8000:8000"
    volumes:
      - ./data:/data
    environment:
      EMAIL_WEB_HOST: 0.0.0.0
      EMAIL_WEB_PORT: 8000
      EMAIL_WEB_LOG_LEVEL: INFO
      EMAIL_WEB_TOKEN: "把第 4.1 步生成的 token 粘贴到这里(保留双引号)"
```

**关键点**:
- `ports` 必须是 `127.0.0.1:8000:8000`(只绑本机)而不是 `8000:8000`
- `EMAIL_WEB_TOKEN` 必须填,留空相当于裸奔
- 双引号不要丢

保存退出。

### 4.3 (可选)国内构建加速

国内服务器拉 PyPI 包慢,可以在 `Dockerfile` 里改用清华镜像:

宝塔【文件】→ `/www/wwwroot/email/Dockerfile`,在 `RUN pip install -r requirements.txt` **上面**加一行:

```dockerfile
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
```

构建时间能从 5~10 分钟降到 1~2 分钟。

### 4.4 创建数据目录

```bash
cd /www/wwwroot/email
mkdir -p data
chmod 700 data
ls -la data
```

`chmod 700` 让数据目录只有所有者可读写,保护主密钥。

---

## 5. 启动 Docker 容器

### 5.1 命令行启动

```bash
cd /www/wwwroot/email
docker compose up -d --build
```

`--build` 会触发首次构建,**第一次会比较慢**(2~10 分钟,取决于网络和是否加了清华源)。

构建完成后,看启动日志:

```bash
docker compose logs -f --tail=100
```

正常输出应该有:

```
email-web  | INFO:     Started server process [1]
email-web  | INFO:     Waiting for application startup.
email-web  | INFO:     Application startup complete.
email-web  | INFO:     Uvicorn running on http://0.0.0.0:8000
```

按 `Ctrl+C` 退出日志查看(不会停容器)。

### 5.2 健康检查

```bash
curl http://127.0.0.1:8000/api/health
```

应该返回类似:

```json
{"status":"ok","version":"2.0.0"}
```

### 5.3 在宝塔可视化查看

宝塔左侧 → 【Docker】→ 【容器】,应该能看到 `email-web`,状态绿色 `Up`。

点容器名进去可以看:
- 实时日志
- 资源占用(CPU/内存)
- 进入容器终端
- 重启 / 停止

---

## 6. 域名托管到 Cloudflare

### 6.1 注册 Cloudflare 账号

[cloudflare.com](https://cloudflare.com) → Sign Up → 邮箱 + 密码注册 → 邮箱验证。

### 6.2 添加域名

1. 登录后右上角【+ Add a site / Add a domain】
2. 输入你的**根域名**(如 `example.com`,不要带 `www.` 或 `mail.`)
3. 选 **Free 计划** → Continue
4. Cloudflare 会自动扫描你域名的现有 DNS 记录

### 6.3 修改域名 NS 服务器

Cloudflare 会显示 2 个 NS 服务器,例如:

```
alice.ns.cloudflare.com
bob.ns.cloudflare.com
```

**记下这两个**,然后去你买域名的地方修改:

| 注册商 | 修改路径 |
| --- | --- |
| 阿里云万网 | 域名控制台 → 管理 → DNS 修改 → 修改 DNS 服务器 |
| 腾讯云 DNSPod | DNS 解析 → 我的域名 → 修改 DNS 服务器 |
| Namesilo | Domain Manager → 点域名 → NameServers |
| GoDaddy | My Products → DNS → Nameservers → Change |
| Cloudflare 上买的 | 已经默认是 Cloudflare 的 NS,跳过这步 |

把原来的 NS(通常是注册商自己的)替换成 Cloudflare 给的两个,保存。

### 6.4 等待生效

NS 切换全球生效需要 **5 分钟到 24 小时**(实际通常 15~30 分钟)。

Cloudflare 会自动检测,生效后:
- Cloudflare 控制台域名状态变成绿色 **Active**
- 给你绑定的邮箱发邮件通知

可以同时在本地命令行检测:

```bash
# Windows PowerShell
nslookup -type=ns 你的域名.com
# 看到的 NS 是 Cloudflare 的就是生效了
```

> ⚠️ **NS 切换没生效之前,不要进行第 7 步**,否则 Tunnel DNS 路由会创建失败。

---

## 7. 配置 Cloudflare Tunnel

### 7.1 服务器安装 cloudflared

SSH 进服务器:

```bash
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o /tmp/cf.deb
dpkg -i /tmp/cf.deb && rm /tmp/cf.deb
cloudflared --version
```

应该输出版本号,例如 `cloudflared version 2024.x.x`。

**国内服务器拉 GitHub 慢/失败时**:

方法 1:本地下载后上传

```
本地浏览器打开:
https://github.com/cloudflare/cloudflared/releases/latest

下载文件:cloudflared-linux-amd64.deb

宝塔【文件】→ /tmp/ → 上传

SSH:
dpkg -i /tmp/cloudflared-linux-amd64.deb
```

方法 2:用国内代理镜像

```bash
curl -L https://ghproxy.com/https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o /tmp/cf.deb
dpkg -i /tmp/cf.deb
```

### 7.2 在 Cloudflare 网页创建 Tunnel(全程可视化)

打开 [https://one.dash.cloudflare.com](https://one.dash.cloudflare.com) → 选你的账号(首次进入要确认 Zero Trust 团队名,随便填)。

**步骤详解**:

1. 左侧菜单:**Networks → Tunnels**(旧版可能在 Access → Tunnels)
2. 点【**+ Create a tunnel**】
3. 选 **Cloudflared** → Next
4. **Tunnel name**:填 `email-web` → Save tunnel
5. **Choose your environment**:选 `Debian` → 选 `64-bit`
6. 下面会显示一段安装命令,类似:

   ```bash
   sudo cloudflared service install eyJhIjoiYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5In0=
   ```

7. **复制整段命令**,SSH 到服务器粘贴执行
8. 几秒后,Cloudflare 网页底部 **Connectors** 区域会出现一个绿色的 `Connected` 连接器
9. 点【**Next**】
10. **Public Hostnames** 配置(关键):
    - **Subdomain**:`mail`
    - **Domain**:从下拉里选你的域名
    - **Path**:留空
    - **Service - Type**:`HTTP`
    - **Service - URL**:`127.0.0.1:8000`
11. (可选)展开 **Additional application settings → TLS**:
    - `No TLS Verify` 勾上(因为后端是 HTTP)
    - `HTTP Host Header` 填 `127.0.0.1:8000`
12. 点【**Save tunnel**】

### 7.3 验证 Tunnel

SSH:

```bash
systemctl status cloudflared
# 应该是 active (running)

cloudflared tunnel list
# 应该看到 email-web 这条记录
```

浏览器打开 `https://mail.你的域名.com`:
- ✅ 看到登录页 → 部署成功
- 输入第 4.1 步的 Token → 进入主界面

### 7.4 第一次进入应用

1. 登录后会自动初始化数据库和主密钥
2. SSH 验证:

   ```bash
   ls -la /www/wwwroot/email/data/
   # 应该看到 .master.key 和 emails.db
   ```

3. **立刻去做第 8 节的备份配置**,在添加任何账号之前

---

## 8. 自动备份配置(必做!)

### 8.1 为什么必须备份

| 文件 | 作用 | 丢失后果 |
| --- | --- | --- |
| `data/.master.key` | 主加密密钥 | 数据库里所有邮箱密码 / OAuth token **永久无法解密** |
| `data/emails.db` | SQLite 数据库 | 所有账号、分组、设置丢失 |

**这两个文件必须配对备份**,只备份其中一个等于没备份。

### 8.2 创建备份脚本

```bash
mkdir -p /www/backup/email-app

cat > /root/backup-email.sh <<'SCRIPT'
#!/bin/bash
set -e

DATE=$(date +%Y%m%d-%H%M%S)
APP_DIR=/www/wwwroot/email
BACKUP_DIR=/www/backup/email-app
RETAIN_DAYS=14

cd "$APP_DIR"

# SQLite 在线备份(避免 WAL 模式下复制损坏)
docker compose exec -T email-web sh -c \
    "sqlite3 /data/emails.db '.backup /data/emails.db.bak'" 2>/dev/null || \
    cp ./data/emails.db ./data/emails.db.bak

# 打包加密(密码自定义)
tar czf "$BACKUP_DIR/email-$DATE.tar.gz" \
    -C ./data .master.key emails.db.bak 2>/dev/null

# 清理旧备份
find "$BACKUP_DIR" -name 'email-*.tar.gz' -mtime +$RETAIN_DAYS -delete

# 删除临时备份
rm -f ./data/emails.db.bak

echo "[$(date '+%F %T')] backup ok: email-$DATE.tar.gz"
SCRIPT

chmod +x /root/backup-email.sh

# 立刻跑一次测试
/root/backup-email.sh
ls -la /www/backup/email-app/
```

应该看到一个 `email-20XX...tar.gz` 文件,几 KB 到几十 KB。

### 8.3 配置宝塔计划任务

宝塔左侧 → 【**计划任务**】→ 添加任务:

| 字段 | 值 |
| --- | --- |
| 任务类型 | Shell 脚本 |
| 任务名称 | `邮箱管家-数据备份` |
| 执行周期 | 每天 / 04:00 |
| 脚本内容 | `/root/backup-email.sh` |
| 日志记录 | 开 |

点【添加】后,回到任务列表点【**执行**】手动测试一次,日志应该显示 `backup ok`。

### 8.4 异地备份(强烈推荐)

只备份在本机,服务器一炸全没了。配上**云存储异地备份**:

宝塔左侧 → 【计划任务】→ 添加任务:

| 字段 | 值 |
| --- | --- |
| 任务类型 | **备份目录** |
| 任务名称 | `邮箱管家-异地备份` |
| 执行周期 | 每天 / 05:00 |
| 备份目录 | `/www/backup/email-app` |
| 备份到 | **腾讯云 COS** / 七牛云 / 阿里云 OSS / OneDrive(任选) |
| 保留份数 | 30 |

> 腾讯云 COS 要先在【软件商店】装【腾讯云 COS】插件并填 SecretId/Key。每月几毛钱。

### 8.5 备份恢复演练(最少做一次)

**真实灾难前必须演练过恢复流程**,否则备份等于安慰剂。

模拟恢复(在新机器或新目录测试):

```bash
mkdir -p /tmp/recovery && cd /tmp/recovery
tar xzf /www/backup/email-app/email-XXXXX.tar.gz
ls -la
# 应该看到 .master.key 和 emails.db.bak
mv emails.db.bak emails.db
# 把这两个文件放到新机器的 data/ 目录,启动容器即可恢复
```

---

## 9. 安全加固

部署完成后,逐项过一遍:

- [ ] **腾讯云控制台防火墙**:只留 22(或自定义 SSH 端口)+ 8888
- [ ] **宝塔安全**:与控制台一致
- [ ] **宝塔面板用户名**:不是 `admin`
- [ ] **宝塔面板密码**:强密码(≥16 位混合)
- [ ] **宝塔面板 SSL**:开启(面板设置 → 面板 SSL)
- [ ] **宝塔面板入口**:已修改(默认 8888 + `/safe-key` 都改掉)
- [ ] **SSH 端口**:已改非 22
- [ ] **SSH 禁用密码登录**:用 Key 登录(可选但强烈推荐)
- [ ] **fail2ban**:已启用
- [ ] **EMAIL_WEB_TOKEN**:已设置且非弱密码
- [ ] **data/ 目录权限**:`chmod 700`
- [ ] **每日备份**:已配置 + 已手动验证 + 已上云

进阶(可选):
- 把宝塔面板访问也走 Cloudflare Tunnel(再开一个 `panel.xxx.com` 的 ingress 指向 `127.0.0.1:8888`),然后**完全关掉腾讯云防火墙的 8888**,只留 22。这样服务器除了 SSH **零开放端口**

---

## 10. 日常运维命令

### 10.1 速查表

| 操作 | 命令 |
| --- | --- |
| 看应用日志 | `cd /www/wwwroot/email && docker compose logs -f --tail=200` |
| 重启应用 | `cd /www/wwwroot/email && docker compose restart` |
| 停止应用 | `cd /www/wwwroot/email && docker compose stop` |
| 启动应用 | `cd /www/wwwroot/email && docker compose start` |
| 进入容器 | `docker exec -it email-web sh` |
| 看资源占用 | `docker stats email-web` |
| 看 Tunnel 状态 | `systemctl status cloudflared` |
| 看 Tunnel 日志 | `journalctl -u cloudflared -f --tail=100` |
| 重启 Tunnel | `systemctl restart cloudflared` |
| 手动备份 | `/root/backup-email.sh` |
| 看备份列表 | `ls -lh /www/backup/email-app/` |

### 10.2 升级新版本

```bash
cd /www/wwwroot/email

# 先备份(以防新版本数据库迁移失败)
/root/backup-email.sh

# 拉最新代码
git pull

# 重新构建并启动
docker compose up -d --build

# 看日志确认启动成功
docker compose logs -f --tail=100
```

### 10.3 修改环境变量(例如换 Token)

```bash
cd /www/wwwroot/email
vim docker-compose.yml          # 改 EMAIL_WEB_TOKEN
docker compose up -d            # 自动重建容器(数据保留)
```

### 10.4 修改 Tunnel 路由

不需要改服务器,**直接在 Cloudflare 网页改**:

Zero Trust → Networks → Tunnels → email-web → **Public Hostname** 标签 → 编辑 / 添加新条目。

---

## 11. 故障排查 FAQ

### Q1:浏览器打开域名报 502 / 521 / 1033

依次排查:

```bash
# A. 容器在跑吗?
docker ps | grep email-web

# B. 本地通吗?
curl http://127.0.0.1:8000/api/health

# C. Tunnel 连上了吗?
systemctl status cloudflared
# 应该显示 active (running) + Connection registered

# D. DNS 解析对吗?
nslookup mail.你的域名.com
# 应该返回 Cloudflare 的 IP(104.x.x.x 之类)
```

90% 的 502 是容器没跑或 Tunnel 没启动。

### Q2:`docker compose up` 卡在 `Building...` 几分钟没动静

国内拉 PyPI 包超时。解决:

宝塔【文件】→ `/www/wwwroot/email/Dockerfile`,在 `RUN pip install -r requirements.txt` 上面加:

```dockerfile
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
```

然后:

```bash
cd /www/wwwroot/email
docker compose build --no-cache
docker compose up -d
```

### Q3:cloudflared 安装报 `dpkg: error: package architecture (amd64) does not match system (arm64)`

腾讯云轻量个别套餐是 ARM 架构。改下载 ARM 版:

```bash
uname -m
# 如果输出 aarch64,用下面这个
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64.deb -o /tmp/cf.deb
dpkg -i /tmp/cf.deb
```

### Q4:Cloudflare Tunnel 网页一直显示 `No connections`

```bash
# 看具体报错
journalctl -u cloudflared -n 50

# 重启
systemctl restart cloudflared

# 实在不行重新跑 install 命令(网页 Tunnel 配置页右上角能再次复制)
```

### Q5:国内访问 Cloudflare 域名很慢/经常超时

Cloudflare 国内访问质量看运气。解决方案:

1. **付费**:Cloudflare 升级 9.9 美元/月的 **Argo Smart Routing**,延迟立降 30~50%
2. **优选 IP**:用 [CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest) 找你本地最优 Cloudflare IP,在 hosts 文件固定
3. **换通道**:不走 Cloudflare,改用 frp / ngrok / 自建 wireguard 反代回家
4. **彻底解决**:服务器换香港/海外节点 + 备案改不需要

### Q6:邮件账号检测一直 timeout

国内服务器连 Outlook/Gmail 偶尔慢,这是网络结构问题不是代码问题。

- 重试几次通常能成
- 严重时考虑给容器加代理:在 `docker-compose.yml` 里加

  ```yaml
      environment:
        HTTPS_PROXY: "http://你的代理:端口"
        HTTP_PROXY: "http://你的代理:端口"
        NO_PROXY: "127.0.0.1,localhost"
  ```

### Q7:忘了 `EMAIL_WEB_TOKEN`

```bash
grep EMAIL_WEB_TOKEN /www/wwwroot/email/docker-compose.yml
```

或直接改新的:

```bash
NEW_TOKEN=$(openssl rand -hex 32)
sed -i "s|EMAIL_WEB_TOKEN:.*|EMAIL_WEB_TOKEN: \"$NEW_TOKEN\"|" /www/wwwroot/email/docker-compose.yml
cd /www/wwwroot/email && docker compose up -d
echo "新 Token: $NEW_TOKEN"
```

### Q8:`.master.key` 被误删了

**立刻**从最近的备份恢复:

```bash
cd /www/wwwroot/email
docker compose stop

# 找最近的备份
ls -lt /www/backup/email-app/ | head

# 解压恢复(注意备份了哪些文件)
tar xzf /www/backup/email-app/email-XXXXX.tar.gz -C /tmp/restore/
cp /tmp/restore/.master.key /www/wwwroot/email/data/

docker compose start
```

如果**没备份**:数据库里所有加密字段(密码、refresh_token)永久无法解密,只能清库重新添加账号。

### Q9:升级版本后启动失败

```bash
cd /www/wwwroot/email
docker compose logs --tail=200      # 看具体错误

# 如果是数据库迁移问题,回滚:
docker compose down
git log --oneline -10               # 找上一个能跑的提交
git checkout <commit-hash>
# 恢复备份
tar xzf /www/backup/email-app/email-上次成功的备份.tar.gz -C ./data/
docker compose up -d --build
```

### Q10:磁盘空间满了

```bash
df -h                               # 看哪个分区满了
docker system df                    # 看 Docker 占用
docker system prune -a              # 清理未使用的镜像/容器(谨慎,会删停止的容器)
du -sh /www/backup/*                # 看备份占用
```

---

## 12. 部署完成检查清单

部署完成后,逐项打勾确认:

### 应用层
- [ ] `docker ps` 看到 `email-web` 容器在跑且状态健康
- [ ] `curl http://127.0.0.1:8000/api/health` 返回 200
- [ ] 浏览器访问 `https://mail.你的域名.com` 看到登录页
- [ ] 输入 Token 能登录进主界面
- [ ] 测试导入一个邮箱账号成功
- [ ] 测试收取邮件成功

### Tunnel 层
- [ ] `systemctl status cloudflared` 显示 active
- [ ] Cloudflare 网页 Tunnels 页面显示绿色 Connected
- [ ] Public Hostname 配置无误

### 安全层
- [ ] 腾讯云控制台防火墙只留 SSH + 8888
- [ ] 宝塔安全规则一致
- [ ] 宝塔面板用户名 ≠ admin
- [ ] 宝塔面板有强密码
- [ ] SSH 改了非默认端口
- [ ] fail2ban 已启用

### 备份层
- [ ] `/root/backup-email.sh` 已存在且可执行
- [ ] 手动跑过一次,在 `/www/backup/email-app/` 看到备份文件
- [ ] 宝塔计划任务已添加(每天 4:00)
- [ ] 异地备份已配置(云存储)
- [ ] 演练过恢复流程

### 数据层
- [ ] `/www/wwwroot/email/data/.master.key` 存在
- [ ] `/www/wwwroot/email/data/emails.db` 存在
- [ ] `data/` 目录权限 700

---

## 附录:架构图与端口/域名规划

```
┌─────────────────┐
│  用户浏览器       │
└────────┬────────┘
         │ HTTPS (443)
         ↓
┌─────────────────────────┐
│ Cloudflare 边缘节点       │
│ - 自动 HTTPS              │
│ - DDoS 防护               │
│ - 5 秒盾                  │
└────────┬────────────────┘
         │ Cloudflare Tunnel
         │ (出站 TCP,无入站端口)
         ↓
┌──────────────────────────┐
│ 腾讯云轻量 (国内/香港)     │
│ ┌──────────────────────┐ │
│ │ cloudflared (systemd)│ │
│ │     ↓ 127.0.0.1:8000 │ │
│ │ ┌──────────────────┐ │ │
│ │ │ Docker:email-web │ │ │
│ │ │  FastAPI + SQLite│ │ │
│ │ │  /data 持久化     │ │ │
│ │ └──────────────────┘ │ │
│ └──────────────────────┘ │
│ 仅开放: 22 (SSH) + 8888  │
└──────────────────────────┘
         ↓ 出站
┌─────────────────────────┐
│ Outlook / Gmail / IMAP  │
└─────────────────────────┘
```

| 端口 | 用途 | 暴露范围 |
| --- | --- | --- |
| 22 (或自定义) | SSH | 公网(限你的 IP 更安全) |
| 8888 | 宝塔面板 | 公网(进阶可走 Tunnel) |
| 8000 | 应用 | **仅 127.0.0.1**,不对外 |

| 域名 | 解析到 | 用途 |
| --- | --- | --- |
| `mail.你的域名.com` | Cloudflare(橙色云) | 应用入口 |
| `panel.你的域名.com`(可选) | Cloudflare Tunnel | 宝塔面板入口 |

---

**部署有问题?** 优先看第 11 节 FAQ;还不行就看 `docker compose logs` 和 `journalctl -u cloudflared` 的具体报错信息。
