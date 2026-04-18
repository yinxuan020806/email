# 日常重新部署速查（git push → 一键更新）

> 本文档假设**首次部署已经完成**（参考 [`deploy-tencent-baota.md`](deploy-tencent-baota.md)），  
> 现在我们只关心"代码改完之后怎么把新版本上线"。

---

## TL;DR — 三步上线

```bash
# 1) 本机：提交并推送代码
git add -A && git commit -m "feat: ..." && git push

# 2) SSH 到服务器
ssh root@<你的服务器>

# 3) 一条命令搞定：拉代码 → 重建容器 → 健康检查
cd /www/wwwroot/email && bash scripts/deploy.sh
```

`scripts/deploy.sh` 会按顺序做：

1. `git pull --ff-only`（拉最新）
2. 如有必要 `chown -R 10001:10001 data`（修正容器用户对持久卷的权限）
3. `docker compose up -d --build`（重新构建并启动）
4. 轮询 `http://127.0.0.1:8000/api/health` 直到返回 200，否则非零退出
5. 输出当前容器状态

健康检查失败时退出码非 0，方便后续接入 cron / CI。

---

## 让 AI 帮你部署（最省事）

需要给到的最小信息：

| 信息 | 示例 | 备注 |
| --- | --- | --- |
| 服务器地址 | `ssh root@1.2.3.4 -p 22122` | 端口若改过务必告诉我 |
| 登录方式 | 密码 / 私钥 | 私钥粘贴时用一次性的，事后撤回 |
| GitHub 仓库 | `git@github.com:user/email.git` | 私有仓库需在服务器配 deploy key |

> ⚠️ **凭据安全**：把密码/私钥贴到聊天里有泄露风险。建议  
> ① 部署完立刻在服务器上 `passwd` 改密码或撤回临时密钥；  
> ② 或者只在宝塔后台开个临时 SSH IP 白名单；  
> ③ 公私钥永远不要提交到仓库，`.gitignore` 已默认忽略 `.env`。

我（AI）会按以下顺序操作：

1. SSH 上去 `cd /www/wwwroot/email && git pull && bash scripts/deploy.sh`
2. 如果是第一次接管，会先确认 `git remote -v` 已经指向 GitHub
3. 部署后会主动跑 `docker compose ps` + `curl /api/health` 给你确认

---

## 常用变体

| 场景 | 命令 |
| --- | --- |
| 改了 `requirements.txt`，强制不用缓存 | `bash scripts/deploy.sh --no-cache` |
| 只想重启容器（没改代码） | `bash scripts/deploy.sh --restart-only` |
| 仅查看实时日志 | `cd /www/wwwroot/email && docker compose logs -f --tail=200` |
| 回滚到上一个版本 | `git log --oneline -10` 找 hash → `git checkout <hash> && bash scripts/deploy.sh` |
| 改 token / 端口 | 直接改 `docker-compose.yml` → `docker compose up -d`（无需 pull） |

---

## 服务器侧首次"接入 git"流程

> 已经按旧教程把代码 zip 上传到服务器、还没用过 git 的话，按这一步把它转成 git 仓库。  
> **整个过程不会动 `data/` 和你已经填好的 `docker-compose.yml`**。

```bash
cd /www/wwwroot/email

# 1) 备份现有的 compose 与 data（保险起见）
cp docker-compose.yml /root/docker-compose.yml.bak.$(date +%s)
tar czf /root/email-data-backup-$(date +%Y%m%d).tgz data/

# 2) 初始化 git 并拉远端
git init
git remote add origin git@github.com:<user>/<repo>.git    # 或 https://github.com/.../.git
git fetch origin

# 3) 强制对齐到远端 main 分支（保留 data/ 因为已 .gitignore）
#    docker-compose.yml 在仓库里有版本——下面会用本地备份覆盖回 token 配置
git checkout -f -B main origin/main

# 4) 用备份恢复你的真实 token（仓库里那份只是模板）
cp /root/docker-compose.yml.bak.* docker-compose.yml

# 5) 跑一次部署
bash scripts/deploy.sh
```

之后每次更新就只剩 `git pull && bash scripts/deploy.sh`（或直接 `bash scripts/deploy.sh`，脚本内部会先 pull）。

---

## 进阶：完全自动化（GitHub Actions）

> 不强求；按需开启。

如果未来想做到 push 之后服务器自动拉，可以加 `.github/workflows/deploy.yml`：

```yaml
name: deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: SSH 部署
        uses: appleboy/ssh-action@v1.0.3
        with:
          host: ${{ secrets.SSH_HOST }}
          username: ${{ secrets.SSH_USER }}
          key: ${{ secrets.SSH_KEY }}
          port: ${{ secrets.SSH_PORT }}
          script: cd /www/wwwroot/email && bash scripts/deploy.sh
```

需要在 GitHub 仓库 → Settings → Secrets 里配 4 个 secrets。  
**国内服务器 + GitHub Actions 偶尔会因网络抖动失败，建议保留手动 `bash scripts/deploy.sh` 作为兜底。**

---

## 故障速查

| 现象 | 处理 |
| --- | --- |
| 部署后健康检查 timeout | `docker compose logs --tail=200` 看具体报错 |
| 容器反复重启，日志写 `Permission denied` `.master.key` | `chown -R 10001:10001 /www/wwwroot/email/data` |
| `git pull` 报 `Your local changes would be overwritten` | 服务器上意外编辑了仓库文件；用 `git stash` 或 `git checkout --` 还原 |
| pip 装包慢/超时 | 在 `Dockerfile` 加 `RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple` |
| 浏览器打开域名 502 | `systemctl status cloudflared` 看 Tunnel；详见 [deploy-tencent-baota.md §11](deploy-tencent-baota.md) |

---

## 相关文档

- 完整图文教程（首次部署）：[`deploy-tencent-baota.md`](deploy-tencent-baota.md)
- 一次部署后的环境交接说明：[`redeploy-handover.md`](redeploy-handover.md)
- 主 README：[`../README.md`](../README.md)
