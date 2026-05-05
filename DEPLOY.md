# 部署 & 访问指南

> 本文档讲清楚两件事：
> 1. **从代码提交到服务器跑起来**（Linux VPS / 本地 / 内网 三种场景）
> 2. **服务跑起来之后怎么进入页面看效果**（含外网访问、HTTPS、反代、排错）

---

## 一、目录结构与端口

```
<repo-root>/                    ← git clone 出来的目录，docker compose 在此层执行
├── docker-compose.yml          ← 联合启动两个服务（email-web + code-receiver）
├── Dockerfile                  ← 管理端 Dockerfile
├── .dockerignore               ← 关键：阻止 master.key / *.db / __pycache__ 进镜像
├── DEPLOY.md                   ← 本文件
├── README.md
├── web_app.py                  ← 管理端入口（端口 8000）
├── core/  database/  static/   ← 管理端源码
├── data/                       ← 持久化主密钥 + SQLite（必须 chown 给 uid=10001）
│   ├── .master.key
│   └── emails.db
└── code-receiver/              ← 接码前台子模块（端口 8001）
    ├── Dockerfile
    ├── entrypoint.sh           ← 等待 master.key 就位
    ├── app.py
    └── ...
```

| 端口 | 服务 | 用途 | 谁能访问 |
|---|---|---|---|
| **8000** | 管理端 (xiaoxuan 等管理员登录) | 邮箱管理、设置 is_public、改提取规则 | 仅站长，建议反代到独立子域名 + 强密码 |
| **8001** | 接码前台 | 终端用户输入邮箱拿验证码 | 公开（匿名 + 限流） |

---

## 二、首次部署（Linux VPS / 服务器）

### 2.1 把代码弄到服务器

**方式 A：git push → ssh pull（推荐）**

```powershell
# 本地（仓库根目录）
cd D:\1\0-email\email
git add .
git commit -m "feat: code-receiver MVP + schema v5"
git push origin main
```

```bash
# 服务器侧
ssh user@your-server.com
cd /opt/email          # 或您原本 git clone 出来的目录（即 email repo 根）
git pull
```

> 如果服务器上还没 clone 过：`git clone https://github.com/<owner>/email.git /opt/email`

**方式 B：rsync 直接上传（调试期）**

```bash
rsync -avz --exclude='.git' --exclude='**/__pycache__' --exclude='data/' \
  D:/1/0-email/email/ user@your-server.com:/opt/email/
```

### 2.2 准备 data/ 目录权限

容器内进程是 `uid=10001`，宿主目录必须可读写：

```bash
cd /opt/email          # 仓库根（与 docker-compose.yml 同级）
mkdir -p data
sudo chown -R 10001:10001 data
```

> 这一步**必须**做，否则容器启动后写不进 `data/.master.key`，前后两个容器都会反复重启。

### 2.3 启动两个服务

```bash
docker compose up -d --build
```

**首次启动顺序**（自动）：

1. `email-web` 镜像 build 完，容器启动
2. 容器内 `DatabaseManager()` 初始化 → 生成 `data/.master.key` + `data/emails.db`
3. healthcheck `/api/health` 通过（约 10-15s）
4. **此时** `code-receiver` 才被 docker compose 拉起（因为 `depends_on: condition: service_healthy`）
5. 接码前台容器内 `entrypoint.sh` 再次确认 master.key 存在 → 启动 uvicorn
6. 接码前台 healthcheck `/healthz` 通过

### 2.4 查看启动状态

```bash
docker compose ps                  # 两行都应该 "healthy"
docker compose logs -f email-web   # 看管理端日志
docker compose logs -f code-receiver
```

如果有问题：

```bash
docker compose logs --tail=200 code-receiver
docker exec -it code-receiver sh   # 进容器排查
```

---

## 三、首次初始化（必做一次）

### 3.1 在管理端注册 `xiaoxuan` 账号

打开浏览器：`http://你的服务器:8000`（或反代后的域名）

第一次访问会跳到 `/register`，填用户名 `xiaoxuan` + 密码注册。

> ⚠️ 注册完后强烈建议关闭注册（防陌生人抢资源）：在 `docker-compose.yml` 的 email-web environment 里取消注释 `EMAIL_WEB_DISABLE_REGISTER: "1"` 然后 `docker compose up -d`。

### 3.2 导入邮箱（如果还没有）

登录后在管理端按 `----` 分隔批量粘贴格式导入您的 257 个 outlook.com 邮箱。

### 3.3 一键开放公开查询

进 SQLite 执行一条 SQL（`xiaoxuan` 名下所有 cursor / cursor+gpt 分组的账号都设为公开）：

```bash
docker exec -it email-web sqlite3 /data/emails.db <<EOF
UPDATE accounts SET is_public = 1
 WHERE owner_id = (SELECT id FROM users WHERE username = 'xiaoxuan')
   AND (lower(group_name) LIKE '%cursor%' OR lower(group_name) LIKE '%gpt%');
SELECT changes() AS updated_rows;
EOF
```

预期输出：`updated_rows: 211`（您管理端截图里的 cursor 206 + cursor+gpt 5）。

---

## 四、查看页面（多种访问方式）

### 4.1 内网 / 局域网访问（最简单）

`docker-compose.yml` 默认把端口绑定到 `127.0.0.1`，**只有服务器本机能访问**。要让局域网也能访问，改成 `0.0.0.0:8001:8001`：

```yaml
ports:
  - "0.0.0.0:8001:8001"
```

```bash
docker compose up -d
```

然后局域网内访问 `http://服务器局域网IP:8001`，应该看到这个页面：

```
+------------------------------+
|     ✉ 邮件查看器              |
+------------------------------+
| [邮箱----密码 / Gmail-...] [搜索] |
| ○ Cursor   ● ChatGPT/OpenAI  |
+------------------------------+
|         （暂无邮件）          |
+------------------------------+
```

### 4.2 公网访问 — Cloudflare Tunnel（**推荐**：免开放公网端口、自动 HTTPS）

不用改服务器防火墙，最简单：

```bash
# 服务器上安装 cloudflared
curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared.deb

# 登录 + 创建 tunnel
cloudflared tunnel login
cloudflared tunnel create code-receiver
cloudflared tunnel route dns code-receiver code.yourdomain.com

# 配置 ~/.cloudflared/config.yml
cat > ~/.cloudflared/config.yml <<EOF
tunnel: code-receiver
credentials-file: /home/user/.cloudflared/<tunnel-id>.json
ingress:
  - hostname: code.yourdomain.com
    service: http://127.0.0.1:8001
  - hostname: admin.yourdomain.com
    service: http://127.0.0.1:8000
  - service: http_status:404
EOF

# 跑 tunnel
sudo cloudflared service install
```

完成后：

- 终端用户 → `https://code.yourdomain.com`（接码前台）
- 站长 → `https://admin.yourdomain.com`（管理端）
- 自动 HTTPS、自动续证、不用开公网端口

> ⚠️ 用反代必须打开 `CRX_TRUST_PROXY: "1"`，否则限流会把所有流量算成同一个反代 IP。

### 4.3 公网访问 — nginx 反代

```nginx
server {
    listen 443 ssl http2;
    server_name code.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/code.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/code.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

同样要在 `docker-compose.yml` 设 `CRX_TRUST_PROXY: "1"`。

### 4.4 公网访问 — Caddy（最省事，自动 HTTPS）

```caddyfile
code.yourdomain.com {
    reverse_proxy 127.0.0.1:8001
}

admin.yourdomain.com {
    reverse_proxy 127.0.0.1:8000
}
```

`caddy reload` 即可。

---

## 五、第一次冒烟测试（确认能接码）

### 5.1 浏览器访问

打开 `http://server-ip:8001` 或您的反代域名。

### 5.2 输入测试

输入您管理端里 `cursor` 分组下任意一个 outlook.com 邮箱地址（**不带密码也行**），选 Cursor 或 ChatGPT，点搜索。

### 5.3 预期结果

| 情况 | 响应 |
|---|---|
| 该邮箱有最近的 Cursor 验证邮件 | 200 + 显示 6 位 OTP（可一键复制）或 Magic-Link |
| 该邮箱没近邮件 | 200 + "暂无邮件 / 未匹配到该分类的邮件" |
| 邮箱未设 `is_public=1` 或不属于 xiaoxuan | 404 + "未公开 / 不存在 / 未授权此分类" |
| 1 分钟内同 IP 查 5 次 | 429 + "IP 1 分钟内已达 5 次上限" |
| 邮箱凭据失效 | 401 + "邮箱凭据无效或已过期"（连续 3 次封 IP 1 小时） |

### 5.4 命令行验证（不用浏览器）

```bash
# healthz
curl -s http://server-ip:8001/healthz | jq
# {"ok":true,"owner":"xiaoxuan","db":true,"rules":true}

# 模拟一次查询
curl -s -X POST http://server-ip:8001/api/lookup \
  -H "Content-Type: application/json" \
  -d '{"input":"some-email@outlook.com","category":"cursor"}' | jq
```

---

## 六、日常维护

### 6.1 升级代码

```bash
cd /opt/email
git pull
docker compose up -d --build
```

`--build` 会用新代码重建镜像；`docker compose up -d` 会保留现有 `data/` 卷里的所有数据。

### 6.2 备份

最重要两个文件：

```bash
# 每天 cron 备份一次
0 3 * * * tar czf /backup/email-$(date +\%F).tar.gz \
  /opt/email/data/.master.key \
  /opt/email/data/emails.db
```

> ⚠️ `master.key` 与 `emails.db` **必须一起备份**。两者分离时密文不可解密。

### 6.3 看接码查询日志

```bash
docker exec -it email-web sqlite3 /data/emails.db <<EOF
SELECT ts, category, source, success, error_kind, latency_ms
FROM code_query_log
ORDER BY id DESC LIMIT 20;
EOF
```

注意：IP 与 email 都是 SHA-256 哈希，原值不入库。

### 6.4 清理旧日志

容器自动 30 天清理一次。手动清空：

```bash
docker exec -it email-web sqlite3 /data/emails.db \
  "DELETE FROM code_query_log WHERE ts < datetime('now','-30 days');"
```

---

## 七、常见问题

### Q1：`docker compose up` 后 code-receiver 一直在 restarting？

```bash
docker compose logs --tail=50 code-receiver
```

最常见原因：

1. **`data/` 权限不对** → `cd /opt/email && sudo chown -R 10001:10001 data && docker compose up -d`
2. **管理端没起来** → `docker compose ps` 看 email-web 是不是 healthy；不 healthy 就先 `docker compose logs email-web`
3. **xiaoxuan 还没注册** → 这不是启动问题，进页面注册即可（但前台业务会一直返 404）

### Q2：浏览器输了邮箱地址但一直 404？

```sql
-- 在管理端 SQLite 里查这个邮箱的状态
SELECT id, email, group_name, is_public, allowed_categories
FROM accounts a JOIN users u ON u.id = a.owner_id
WHERE u.username='xiaoxuan' AND a.email='your-email@outlook.com';
```

- `is_public=0` → 没设公开，回到 §3.3 跑 SQL
- `group_name='默认分组'` 且 `allowed_categories=''` → 推断不出分类，要么改 group 要么显式 `allowed_categories='cursor,openai'`

### Q3：能拿到邮件但提取不出验证码？

把您手头**真实的一封 Cursor / ChatGPT 邮件**（发件人 + 主题 + 正文片段）发我，我会基于实物校准 `extractors/cursor.py` 或 `openai_chatgpt.py` 的正则。也可以临时通过 `extractor_rules` 表加规则（无需重启）：

```sql
INSERT INTO extractor_rules (category, sender_pattern, subject_pattern, code_regex, link_regex, priority, enabled, remark)
VALUES ('cursor', '*@cursor.com|*@cursor.sh', 'Cursor*|Verify*', '(?<!\d)(?P<code>\d{6})(?!\d)', '(?P<link>https?://[^\s\"''>]+)', 200, 1, '紧急规则');
```

新规则生效有 30 秒缓存延迟。

### Q4：怎么禁掉某个滥用 IP？

当前没做 IP 黑名单（出现需求再加）。短期手段：

```bash
# 临时封 1 小时
sudo iptables -A INPUT -s 1.2.3.4 -p tcp --dport 8001 -j DROP
```

### Q5：忘了 xiaoxuan 密码？

```bash
docker exec -it email-web sqlite3 /data/emails.db
sqlite> .quit  -- 先退出，用 Python 重置
docker exec -it email-web python -c "
from core.auth import hash_password
from database.db_manager import DatabaseManager
db = DatabaseManager()
db.update_user_password(db.get_user_by_username('xiaoxuan')['id'], hash_password('NewPasswordHere'))
print('OK')"
```

---

## 八、上线检查清单

- [ ] 服务器 `data/` 已 `chown 10001:10001`
- [ ] `docker compose ps` 两行都是 `healthy`
- [ ] `xiaoxuan` 已在管理端注册
- [ ] 管理端的 cursor / cursor+gpt 邮箱已批量 SET `is_public=1`
- [ ] HTTPS（Cloudflare Tunnel / Caddy / nginx）已生效
- [ ] 反代时 `CRX_TRUST_PROXY=1` 已设
- [ ] `EMAIL_WEB_DISABLE_REGISTER=1` 已开（防止陌生人注册）
- [ ] 备份脚本已加入 cron
- [ ] 限流阈值按预期 QPS 调整（默认 5/min, 30/hour）
- [ ] 浏览器实测：输入邮箱 → 点搜索 → 拿到验证码或 magic-link

完成上述全部即可上线。
