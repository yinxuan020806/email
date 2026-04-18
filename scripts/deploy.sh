#!/usr/bin/env bash
# 邮箱管家 Web 一键重新部署脚本
#
# 用途：服务器拉到最新代码 → 重新构建容器 → 健康检查
# 用法：
#   1. 首次或日常更新：bash scripts/deploy.sh
#   2. 强制不使用缓存重建：bash scripts/deploy.sh --no-cache
#   3. 仅重启容器（不拉代码、不重建）：bash scripts/deploy.sh --restart-only
#
# 假设服务器已经按照 docs/deploy-tencent-baota.md 完成首次部署，并且：
#   - 项目目录是 /www/wwwroot/email
#   - data/ 目录里已有 .master.key + emails.db（保留不动）
#   - docker-compose.yml 已配好端口与环境变量（保留不动）
#
# 退出码：0=成功；非 0=失败。CI/cron 可以据此判断。

set -euo pipefail

# ── 可配置项（也可通过环境变量覆盖） ─────────────────
APP_DIR="${APP_DIR:-/www/wwwroot/email}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8000/api/health}"
HEALTH_RETRIES="${HEALTH_RETRIES:-30}"      # 健康检查最多尝试次数（每次 sleep 1s）
COMPOSE="${COMPOSE:-docker compose}"        # 老版本可改成 'docker-compose'
DATA_UID="${DATA_UID:-10001}"               # Dockerfile 里的非 root 用户 uid

# ── 颜色输出 ──────────────────────────────────────
if [[ -t 1 ]]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_RESET=""
fi
info()  { echo "${C_BLUE}[INFO ]${C_RESET} $*"; }
ok()    { echo "${C_GREEN}[ OK  ]${C_RESET} $*"; }
warn()  { echo "${C_YELLOW}[WARN ]${C_RESET} $*"; }
err()   { echo "${C_RED}[ERROR]${C_RESET} $*" >&2; }

# ── 解析参数 ──────────────────────────────────────
NO_CACHE=""
RESTART_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --no-cache) NO_CACHE="--no-cache" ;;
        --restart-only) RESTART_ONLY=1 ;;
        -h|--help)
            sed -n '2,17p' "$0"; exit 0 ;;
        *) err "未知参数: $arg"; exit 2 ;;
    esac
done

# ── 0. 前置检查 ────────────────────────────────────
[[ -d "$APP_DIR" ]] || { err "项目目录不存在: $APP_DIR"; exit 1; }
cd "$APP_DIR"

[[ -f docker-compose.yml ]] || { err "缺少 docker-compose.yml"; exit 1; }
[[ -f Dockerfile        ]] || { err "缺少 Dockerfile"; exit 1; }
$COMPOSE version >/dev/null 2>&1 || { err "$COMPOSE 不可用，请先安装 Docker Compose"; exit 1; }

START_TS=$(date +%s)
info "开始部署：$APP_DIR"

# ── 1. 仅重启分支 ──────────────────────────────────
if [[ "$RESTART_ONLY" == "1" ]]; then
    info "仅重启容器（跳过 git pull / 构建）"
    $COMPOSE restart
    ok "容器已重启"
else
    # ── 2. 拉取最新代码 ─────────────────────────────
    if [[ -d .git ]]; then
        info "git pull --ff-only ..."
        # 防止本地修改阻塞 pull：仅展示，不强制
        if ! git diff --quiet || ! git diff --cached --quiet; then
            warn "工作区有未提交修改，请先确认后再运行；仅展示差异，不会 reset。"
            git status --short || true
        fi
        BEFORE=$(git rev-parse HEAD)
        git pull --ff-only
        AFTER=$(git rev-parse HEAD)
        if [[ "$BEFORE" == "$AFTER" ]]; then
            info "代码已是最新（$AFTER），无需重建。如要强制重建：bash scripts/deploy.sh --no-cache"
        else
            info "代码已更新：$BEFORE → $AFTER"
            git --no-pager log --oneline "$BEFORE..$AFTER" | head -20 || true
        fi
    else
        warn "$APP_DIR 不是 git 仓库，跳过 git pull（请按 docs/deploy-tencent-baota.md 配置 git remote）"
    fi

    # ── 3. 修复 data/ 目录权限（容器以 uid=10001 运行） ─
    if [[ -d data ]]; then
        # 仅 root 才能 chown，普通用户跳过
        if [[ "$EUID" == "0" ]]; then
            CURRENT_OWNER=$(stat -c '%u' data 2>/dev/null || echo "")
            if [[ "$CURRENT_OWNER" != "$DATA_UID" ]]; then
                info "修正 data/ 属主为 $DATA_UID:$DATA_UID"
                chown -R "$DATA_UID":"$DATA_UID" data
            fi
        fi
    else
        info "首次部署：创建 data/"
        mkdir -p data
        [[ "$EUID" == "0" ]] && chown -R "$DATA_UID":"$DATA_UID" data
    fi

    # ── 4. 构建并启动 ──────────────────────────────
    info "$COMPOSE up -d --build $NO_CACHE"
    if [[ -n "$NO_CACHE" ]]; then
        $COMPOSE build --no-cache
        $COMPOSE up -d
    else
        $COMPOSE up -d --build
    fi
fi

# ── 5. 健康检查 ────────────────────────────────────
info "等待容器就绪 → 健康检查 $HEALTH_URL"
ATTEMPT=0
HTTP_CODE=""
while (( ATTEMPT < HEALTH_RETRIES )); do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$HEALTH_URL" || echo "000")
    [[ "$HTTP_CODE" == "200" ]] && break
    ATTEMPT=$((ATTEMPT + 1))
    sleep 1
done

if [[ "$HTTP_CODE" != "200" ]]; then
    err "健康检查失败（$HEALTH_URL 返回 $HTTP_CODE，重试 $HEALTH_RETRIES 次）"
    err "查看容器日志：$COMPOSE logs --tail=200"
    $COMPOSE ps || true
    exit 3
fi

# ── 6. 完成 ────────────────────────────────────────
ELAPSED=$(( $(date +%s) - START_TS ))
ok  "部署成功！耗时 ${ELAPSED}s"
info "容器状态："
$COMPOSE ps
info "如需查看日志：$COMPOSE logs -f --tail=100"
