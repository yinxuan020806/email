# GitHub Actions 自动部署 — 一次性配置

> 配完之后：**`git push` → GitHub 自动 SSH 到服务器跑 `scripts/deploy.sh`**。  
> 不再需要任何手动操作。

仓库里已经写好 [`.github/workflows/deploy.yml`](../.github/workflows/deploy.yml)，  
你只需要在 GitHub 配 4 个 Secrets，再在服务器配一个登录用 SSH key。

---

## Step 1 — 在服务器生成 GitHub Actions 专用 SSH 私钥

> 跟 `scripts/server-bootstrap.sh` 生成的 deploy key **不是同一个**。  
> 那个是「服务器→GitHub」拉代码用的；这个是「GitHub→服务器」推命令用的。

在服务器（宝塔终端 / SSH）跑：

```bash
# 1) 生成 GitHub Actions 用的密钥（无密码）
ssh-keygen -t ed25519 -N '' -C 'github-actions@email-deploy' -f /root/.ssh/gha_deploy

# 2) 把公钥追加到 authorized_keys（让 GH Actions 能登进来）
cat /root/.ssh/gha_deploy.pub >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# 3) 打印私钥（待会贴到 GitHub Secrets，贴完务必把私钥从聊天/文件里删掉）
echo
echo "===== 复制下面这一整段（含 BEGIN/END 行）到 GitHub Secret SSH_KEY ====="
cat /root/.ssh/gha_deploy
echo "================================================================"
```

> ⚠️ **最小权限做法**（推荐）：编辑 `/root/.ssh/authorized_keys`，在新加的那一行**最前面**加约束：
>
> ```
> command="cd /www/wwwroot/email && bash scripts/deploy.sh ${SSH_ORIGINAL_COMMAND:-}",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA...
> ```
>
> 这样这个 key 只能跑 `deploy.sh`，即使泄露也无法做别的。但如果觉得麻烦，省略也行（普通 SSH key 一样能用）。

---

## Step 2 — 在 GitHub 配 4 个 Secrets

打开 https://github.com/yinxuan020806/email/settings/secrets/actions 点 **New repository secret**，依次添加：

| Secret 名 | 值 | 示例 |
| --- | --- | --- |
| `SSH_HOST` | 服务器公网 IP 或域名 | `106.53.4.248` 或 `mail.evuzdnd.cn` |
| `SSH_USER` | 登录用户名 | `root` |
| `SSH_PORT` | SSH 端口 | `22`（如果改过填实际端口，如 `22122`） |
| `SSH_KEY` | Step 1 打印出的**私钥**整段 | `-----BEGIN OPENSSH PRIVATE KEY-----` 开头那段 |

---

## Step 3 — 触发一次部署验证

```bash
# 在本地（d:\1\0-email\email）
git commit --allow-empty -m "ci: trigger first deploy"
git push
```

打开 https://github.com/yinxuan020806/email/actions 看 workflow：

- 绿色 ✓ → 大功告成，以后只要 `git push` 就会自动部署
- 红色 ✗ → 点进去看 log，常见原因：
  - `Permission denied (publickey)` → Step 1 的公钥没加到 `authorized_keys`
  - `Connection timed out` → SSH 端口被防火墙挡了，或 `SSH_HOST` / `SSH_PORT` 填错
  - `bash: scripts/deploy.sh: No such file` → 服务器还没跑 `server-bootstrap.sh`，先跑那个
  - `Permission denied (publickey,password)` → `SSH_KEY` 多/少了首尾的换行，重新复制一次

---

## 网络注意事项

- GitHub Actions runner 在欧美。**国内服务器**首次连接可能因网络抖动失败，可以重跑（Actions 页面右上角 Re-run）。
- 如果你嫌 GitHub Actions 慢/不稳，也可以**保留手动模式**：随时还能在宝塔终端跑 `cd /www/wwwroot/email && bash scripts/deploy.sh`，两种方式互不冲突。

---

## 安全 checklist

- [ ] `/root/.ssh/gha_deploy`（私钥）已**仅本机**留存，没发到聊天/截图/外部
- [ ] `SSH_KEY` Secret 在 GitHub 上**只能写不能读**（GitHub Secret 的特性，不会暴露给 PR/fork）
- [ ] 如果未来不再用，把 `authorized_keys` 里那一行删掉即撤销访问
- [ ] 关掉公开仓库 Actions 来自 fork 的 PR 自动跑（默认就是关的）

---

## 触发选项

| 触发方式 | 何时 |
| --- | --- |
| `git push` 到 main | 自动触发 |
| GitHub Actions 页 → Run workflow | 手动重跑（不带代码改动） |
| Run workflow → 勾 "no_cache" | 改了 `requirements.txt` 时强制不使用缓存重建 |

---

## 仅文档/截图改动不会触发

`deploy.yml` 里的 `paths-ignore` 已经过滤掉以下路径，避免无意义的部署：

- `docs/**`
- `README.md`
- `*.png`

如要触发：手动 Run workflow，或者改一个代码文件。
