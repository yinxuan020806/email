#!/usr/bin/env bash
# 邮箱管家 Web · 服务器一次性接管脚本
#
# 把已经手工部署的 /www/wwwroot/email 转成 git 工作区，
# 之后任何更新都只需要 `bash scripts/deploy.sh`。
#
# 使用前提：
#   - 你已经按 docs/deploy-tencent-baota.md 完成首次部署
#   - 现在站在 root（或对 /www/wwwroot/email 有写权限的用户）
#
# 流程：
#   1. 生成专用 deploy key（仅用于这一个仓库）
#   2. 配置 SSH 走 ssh.github.com:443，绕开国内 22 端口被墙
#   3. 暂停等你把公钥加到 GitHub → Settings → Deploy keys
#   4. 备份现有 docker-compose.yml 与 data/
#   5. git init + remote + 强制对齐到 origin/main
#   6. 用备份恢复 docker-compose.yml（保留你已配好的环境变量）
#   7. 调用 scripts/deploy.sh 完成首次构建 + 健康检查
#
# 跑完之后这个脚本就再也用不上了。日常更新只需要：
#   cd /www/wwwroot/email && bash scripts/deploy.sh

set -euo pipefail

REPO_SSH="${REPO_SSH:-git@github-email:yinxuan020806/email.git}"
SSH_HOST_ALIAS="${SSH_HOST_ALIAS:-github-email}"
APP_DIR="${APP_DIR:-/www/wwwroot/email}"
KEY_PATH="${KEY_PATH:-/root/.ssh/email_deploy}"
BAK_DIR="${BAK_DIR:-/root}"

# ── 颜色 ────────────────────────────────────────
if [[ -t 1 ]]; then
    R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[34m'; N=$'\033[0m'
else
    R=""; G=""; Y=""; B=""; N=""
fi
info() { echo "${B}[INFO ]${N} $*"; }
ok()   { echo "${G}[ OK  ]${N} $*"; }
warn() { echo "${Y}[WARN ]${N} $*"; }
err()  { echo "${R}[ERROR]${N} $*" >&2; }

# ── 0. 前置检查 ─────────────────────────────────
[[ "$EUID" == "0" ]] || warn "建议用 root 跑（当前 uid=$EUID），否则可能写不了 /root/.ssh"
command -v git    >/dev/null || { err "缺少 git，请先 apt install -y git"; exit 1; }
command -v ssh    >/dev/null || { err "缺少 ssh"; exit 1; }
command -v docker >/dev/null || { err "缺少 docker"; exit 1; }
docker compose version >/dev/null 2>&1 || { err "缺少 docker compose v2"; exit 1; }
[[ -d "$APP_DIR" ]] || { err "项目目录不存在：$APP_DIR"; exit 1; }

# ── 1. 生成专用 deploy key ──────────────────────
mkdir -p "$(dirname "$KEY_PATH")" && chmod 700 "$(dirname "$KEY_PATH")"
if [[ -f "$KEY_PATH" ]]; then
    info "复用已有密钥：$KEY_PATH"
else
    info "生成新的 deploy key：$KEY_PATH"
    ssh-keygen -t ed25519 -N '' -C 'email-deploy@server' -f "$KEY_PATH"
fi

# ── 2. 写 SSH config（走 443 端口避开国内被墙） ──
SSH_CFG=/root/.ssh/config
touch "$SSH_CFG" && chmod 600 "$SSH_CFG"
if ! grep -q "^Host $SSH_HOST_ALIAS$" "$SSH_CFG"; then
    info "追加 Host $SSH_HOST_ALIAS 到 $SSH_CFG"
    cat >> "$SSH_CFG" <<EOF

Host $SSH_HOST_ALIAS
    HostName ssh.github.com
    Port 443
    User git
    IdentityFile $KEY_PATH
    IdentitiesOnly yes
EOF
else
    info "SSH config 已存在 Host $SSH_HOST_ALIAS，不重复写入"
fi

# ── 3. 显示公钥 + 等用户加到 GitHub ──────────────
PUBKEY_LINE=$(cat "$KEY_PATH.pub")
echo
echo "${Y}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo "${Y}请把下面这一整行（含开头 ssh-ed25519 与结尾注释）复制：${N}"
echo
echo "$PUBKEY_LINE"
echo
echo "${Y}然后打开浏览器，新开标签页：${N}"
echo "    https://github.com/yinxuan020806/email/settings/keys/new"
echo
echo "${Y}填写：${N}"
echo "    Title:               tencent-server"
echo "    Key:                 粘贴上面那一行"
echo "    Allow write access:  ${R}不要勾${N}（只读，更安全）"
echo "    点 Add key"
echo "${Y}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo

read -r -p "已经在 GitHub 加好 Deploy Key？回车继续，Ctrl+C 中止： " _

# ── 4. 测试 SSH 通道 ────────────────────────────
info "测试 SSH 到 GitHub（首次会询问 host key，自动接受）"
SSH_OUT=$(ssh -T -o StrictHostKeyChecking=accept-new "$SSH_HOST_ALIAS" 2>&1 || true)
echo "$SSH_OUT"
if echo "$SSH_OUT" | grep -q "successfully authenticated"; then
    ok "SSH 通道正常"
else
    err "SSH 认证未通过。检查 deploy key 是否加对、HostKey 是否对，再重新跑本脚本。"
    exit 2
fi

# ── 5. 备份现有 compose + data ──────────────────
cd "$APP_DIR"
TS=$(date +%Y%m%d-%H%M%S)
COMPOSE_BAK="$BAK_DIR/docker-compose.yml.bak.$TS"
DATA_BAK="$BAK_DIR/email-data-backup-$TS.tgz"
cp docker-compose.yml "$COMPOSE_BAK"
ok  "备份 compose → $COMPOSE_BAK"
if [[ -d data ]]; then
    tar czf "$DATA_BAK" data/ 2>/dev/null && ok "备份 data → $DATA_BAK ($(du -h "$DATA_BAK" | cut -f1))"
fi

# ── 6. 把目录转成 git 工作区 ────────────────────
if [[ -d .git ]]; then
    info "目录已是 git 仓库，跳过 init"
    if git remote get-url origin >/dev/null 2>&1; then
        CURRENT_REMOTE=$(git remote get-url origin)
        if [[ "$CURRENT_REMOTE" != "$REPO_SSH" ]]; then
            info "更新 origin: $CURRENT_REMOTE → $REPO_SSH"
            git remote set-url origin "$REPO_SSH"
        fi
    else
        git remote add origin "$REPO_SSH"
    fi
else
    info "git init + 添加 origin"
    git init -b main >/dev/null
    git remote add origin "$REPO_SSH"
fi

info "git fetch origin"
git fetch origin

info "强制对齐到 origin/main（data/ 已 .gitignore，不会动）"
git checkout -f -B main origin/main

# ── 7. 还原 compose（保留现网真实环境变量） ─────
info "用备份恢复 docker-compose.yml（保留你的真实 token / 端口配置）"
cp "$COMPOSE_BAK" docker-compose.yml
if ! diff -q <(git show HEAD:docker-compose.yml) docker-compose.yml >/dev/null 2>&1; then
    warn "你的 compose 与仓库版本有差异（这是预期的，本地敏感配置已保留）："
    diff <(git show HEAD:docker-compose.yml) docker-compose.yml || true
fi

# ── 8. 跑 deploy.sh ─────────────────────────────
chmod +x scripts/deploy.sh scripts/server-bootstrap.sh 2>/dev/null || true
info "调用 scripts/deploy.sh 完成首次构建 + 健康检查"
echo
bash scripts/deploy.sh

echo
ok "服务器接管完成！以后只需："
echo "    cd $APP_DIR && bash scripts/deploy.sh"
echo
echo "回滚：cd $APP_DIR && git log --oneline -10 && git checkout <hash> && bash scripts/deploy.sh"
