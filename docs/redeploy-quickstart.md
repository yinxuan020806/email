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

## 服务器侧首次"接入 git"流程（一次性）

仓库里已经准备好了自动化脚本 `scripts/server-bootstrap.sh`，它会：

1. 生成专用 deploy key（仅对这一个仓库可读）
2. 配置 SSH 走 `ssh.github.com:443` 端口（绕开国内 22 端口被墙）
3. 暂停打印公钥，提示你把它加到 GitHub Deploy Keys
4. 自动备份 `docker-compose.yml` 与 `data/`
5. `git init` + remote + 强制对齐到 `origin/main`
6. 用备份恢复你的真实 `docker-compose.yml`（不会丢现有 token / 端口配置）
7. 调用 `scripts/deploy.sh` 完成首次构建 + 健康检查

**鸡生蛋问题**：还没 git clone 怎么拿到这个脚本？两种办法：

**办法一（推荐，不依赖网络）**：在宝塔终端贴下面这段「自包含 here-doc」，会把 bootstrap 脚本写到 `/tmp/` 并执行：

```bash
# 见 docs/redeploy-quickstart.md → "服务器一次性 bootstrap" 章节，
# 或直接让 AI 帮你贴
```

**办法二（私有仓库 + 一次性 PAT）**：

```bash
# 用一次性 GitHub Personal Access Token（仅 repo:read 权限即可）下载脚本
TOKEN='ghp_xxxxxxxxxxxxxxxxxxxxxxxx'
curl -fsSL -H "Authorization: token $TOKEN" \
    https://raw.githubusercontent.com/yinxuan020806/email/main/scripts/server-bootstrap.sh \
    -o /tmp/email-bootstrap.sh
bash /tmp/email-bootstrap.sh
# 跑完后撤销 PAT
```

跑完之后：
- `scripts/server-bootstrap.sh` 这一脚本就再也用不上
- 日常更新只剩：`cd /www/wwwroot/email && bash scripts/deploy.sh`

---

## 进阶：完全自动化（GitHub Actions）

仓库已经包含 [`.github/workflows/deploy.yml`](../.github/workflows/deploy.yml)，  
配完 4 个 secrets 即可实现 **push → 服务器自动部署**。

详细步骤见 → [`docs/github-actions-setup.md`](github-actions-setup.md)

> **国内服务器 + GitHub Actions 偶尔会因网络抖动失败**，手动 `bash scripts/deploy.sh` 永远是兜底。两种方式可以并存。

---

## 故障速查

| 现象 | 处理 |
| --- | --- |
| 部署后健康检查 timeout | `docker compose logs --tail=200` 看具体报错 |
| 容器反复重启，日志写 `Permission denied` `.master.key` | `chown -R 10001:10001 /www/wwwroot/email/data` |
| `git pull` 报 `Your local changes would be overwritten by docker-compose.yml` | 已自动处理：`deploy.sh` 会把它标记为 `skip-worktree`。手动也可：`git update-index --skip-worktree docker-compose.yml` |
| `git pull` 报其它文件冲突 | 服务器上意外编辑了仓库文件；用 `git stash` 或 `git checkout --` 还原 |
| pip 装包慢/超时 | 在 `Dockerfile` 加 `RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple` |
| 浏览器打开域名 502 | `systemctl status cloudflared` 看 Tunnel；详见 [deploy-tencent-baota.md §11](deploy-tencent-baota.md) |

> **关于 `docker-compose.yml`**：服务器上的版本通常含真实 token / 端口，与仓库里的模板不同。  
> `deploy.sh` 第一次跑会自动 `git update-index --skip-worktree docker-compose.yml`，  
> 之后 `git pull` 不会动这个文件，你的本地配置会被永久保留。  
> 如要从仓库同步新版本：`git update-index --no-skip-worktree docker-compose.yml && git checkout -- docker-compose.yml`，再手动改回 token。

---

## 相关文档

- 完整图文教程（首次部署）：[`deploy-tencent-baota.md`](deploy-tencent-baota.md)
- 一次部署后的环境交接说明：[`redeploy-handover.md`](redeploy-handover.md)
- 主 README：[`../README.md`](../README.md)
