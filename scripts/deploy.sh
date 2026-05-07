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
HEALTH_URL_CRX="${HEALTH_URL_CRX:-http://127.0.0.1:8001/healthz}"
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
        # ── 2a. docker-compose.yml 本地改动隔离 ──
        # 服务器上 docker-compose.yml 常被改（填真实 token / 端口）。
        # 旧策略只靠 git update-index --skip-worktree 标记，但首次部署 / 标记
        # 被取消时一旦仓库改动了 docker-compose.yml，git pull --ff-only 会被
        # "Your local changes ... would be overwritten" 拦下导致整次部署失败。
        #
        # 新策略（更稳）：pull 前若 dirty 就备份并重置，pull 完再用备份覆盖回去——
        # 这样无论仓库改没改 compose、本地改了多少，pull 都不会冲突；用户的
        # 真实 token / 端口完整保留。代价是仓库新增的 compose 字段（如本次的
        # CRX_TRUST_PROXY）不会自动出现，但下面 3.5 的"自动注入"hook 会补齐。
        COMPOSE_RESTORE_FROM=""
        if [[ -f docker-compose.yml ]] && git ls-files --error-unmatch docker-compose.yml >/dev/null 2>&1; then
            # 先临时取消 skip-worktree，让后续 checkout / 状态查询能正常工作
            CURRENT_FLAGS=$(git ls-files -v docker-compose.yml | head -c 1)
            COMPOSE_HAD_SKIP=0
            if [[ "$CURRENT_FLAGS" == "S" ]]; then
                COMPOSE_HAD_SKIP=1
                git update-index --no-skip-worktree docker-compose.yml
            fi
            # 检测是否 dirty（git diff 在 skip-worktree 下永远返回 unchanged，必须先取消标记）
            if ! git diff --quiet -- docker-compose.yml; then
                COMPOSE_RESTORE_FROM="docker-compose.yml.local-$(date +%Y%m%d_%H%M%S)"
                info "docker-compose.yml 有本地改动 → 备份到 $COMPOSE_RESTORE_FROM 后重置以让 pull 顺利"
                cp docker-compose.yml "$COMPOSE_RESTORE_FROM"
                git checkout HEAD -- docker-compose.yml
            fi
            # 重新设上 skip-worktree（如果之前有）+ 首次部署也要标记上
            git update-index --skip-worktree docker-compose.yml
            if [[ "$COMPOSE_HAD_SKIP" != "1" ]]; then
                info "标记 docker-compose.yml 为 skip-worktree（保留本地真实配置）"
            fi
        fi

        info "git pull --ff-only ..."
        if ! git diff --quiet || ! git diff --cached --quiet; then
            warn "工作区还有未提交修改（除 docker-compose.yml 已备份外）；展示差异，不会 reset。"
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

        # ── 2b. 恢复本地 docker-compose.yml 改动（如果有） ──
        if [[ -n "$COMPOSE_RESTORE_FROM" && -f "$COMPOSE_RESTORE_FROM" ]]; then
            info "恢复 docker-compose.yml 本地改动（覆盖回 git 跟踪文件）"
            cp "$COMPOSE_RESTORE_FROM" docker-compose.yml
            # 备份保留 7 天后清理（dot 备份不影响 git，因 skip-worktree 已设）
            find . -maxdepth 1 -name 'docker-compose.yml.local-*' -mtime +7 -delete 2>/dev/null || true
            ok "已恢复本地 docker-compose.yml；备份保留在 $COMPOSE_RESTORE_FROM"
        fi
    else
        warn "$APP_DIR 不是 git 仓库，跳过 git pull（请按 docs/deploy-tencent-baota.md 配置 git remote）"
    fi

    # ── 2c. 清理旧的 APP_VERSION 行 ──
    # 历史版本曾把 git short SHA 注入到 .env，让前端右下角显示成 git hash。
    # 现已改为「``core/version.py::__version__`` 语义化常量」由代码自管，
    # docker-compose.yml 也改成 ``${APP_VERSION:-}`` 空 fallback，让代码常量
    # 胜出。这里把旧 .env 里残留的 APP_VERSION 行清掉，避免覆盖代码版本号。
    if [[ -f .env ]] && grep -q '^APP_VERSION=' .env; then
        info "清理 .env 中残留的 APP_VERSION 行（让代码版本常量生效）"
        grep -v '^APP_VERSION=' .env > .env.tmp.$$ || true
        mv .env.tmp.$$ .env
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

    # ── 3.5 关键升级 hook：确保 docker-compose.yml 已启用 CRX_TRUST_PROXY ─
    # docker-compose.yml 因 skip-worktree 不会被 git pull 覆盖；首次升级到新版后
    # 必须把 CRX_TRUST_PROXY: "1" 注入到旧 compose 文件，否则限流仍按反代 IP 算，
    # 全网用户共享同一个限流桶（30 次/小时一把就用完）。
    if [[ -f docker-compose.yml ]]; then
        if grep -qE '^\s*CRX_TRUST_PROXY\s*:\s*"?1"?\s*$' docker-compose.yml; then
            info "docker-compose.yml 已启用 CRX_TRUST_PROXY=1（限流按真实客户端 IP 计）"
        else
            # 把已注释或缺失的配置统一替换/追加为活跃配置
            BACKUP="docker-compose.yml.bak.$(date +%Y%m%d_%H%M%S)"
            cp docker-compose.yml "$BACKUP"
            info "升级 hook：备份旧 compose → $BACKUP"
            if grep -qE '^\s*#\s*CRX_TRUST_PROXY\s*:' docker-compose.yml; then
                # 已有注释行 → 取消注释
                # 用 sed 行内替换：保留缩进，把 "# CRX_TRUST_PROXY:" 变成 "CRX_TRUST_PROXY:"
                sed -i -E 's@^([[:space:]]*)#[[:space:]]*CRX_TRUST_PROXY[[:space:]]*:[[:space:]]*.*$@\1CRX_TRUST_PROXY: "1"@' docker-compose.yml
                ok "升级 hook：取消注释 CRX_TRUST_PROXY: \"1\""
            elif grep -qE '^\s*CODE_OWNER_USERNAME\s*:' docker-compose.yml; then
                # 没注释行 → 在 CODE_OWNER_USERNAME 之后插入一行（沿用相同缩进）
                sed -i -E '/^([[:space:]]*)CODE_OWNER_USERNAME[[:space:]]*:.*$/{
                    s@@&\n\1CRX_TRUST_PROXY: "1"@
                }' docker-compose.yml
                ok "升级 hook：在 CODE_OWNER_USERNAME 后插入 CRX_TRUST_PROXY: \"1\""
            else
                warn "docker-compose.yml 里既没找到现成的 CRX_TRUST_PROXY 也没找到 CODE_OWNER_USERNAME，"
                warn "  请手动在 code-receiver.environment 段加上：CRX_TRUST_PROXY: \"1\""
                warn "  否则限流会把所有公网用户算成同一个反代 IP，严重影响可用性。"
            fi
            # 验证修改后语法是否还能 docker compose config 通过
            if ! $COMPOSE config >/dev/null 2>&1; then
                err "升级 hook：注入后 docker-compose.yml 语法异常 — 已回滚"
                cp "$BACKUP" docker-compose.yml
                exit 1
            fi
            ok "升级 hook：CRX_TRUST_PROXY=1 已写入 docker-compose.yml"
        fi
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
ok  "管理端 healthy ($HEALTH_URL)"

# ── 5b. 接码前台健康检查（双服务部署时启用；失败仅 warn 不阻断） ──
if grep -q '^[[:space:]]*code-receiver:' docker-compose.yml 2>/dev/null; then
    info "等待接码前台就绪 → $HEALTH_URL_CRX"
    ATTEMPT=0
    CRX_CODE=""
    while (( ATTEMPT < HEALTH_RETRIES )); do
        CRX_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$HEALTH_URL_CRX" || echo "000")
        [[ "$CRX_CODE" == "200" ]] && break
        ATTEMPT=$((ATTEMPT + 1))
        sleep 1
    done
    if [[ "$CRX_CODE" == "200" ]]; then
        ok  "接码前台 healthy ($HEALTH_URL_CRX)"
    else
        warn "接码前台未就绪 (HTTP $CRX_CODE)；管理端已部署成功，但 code-receiver 异常"
        warn "查看接码前台日志：$COMPOSE logs --tail=100 code-receiver"
    fi
fi

# ── 6. 完成 ────────────────────────────────────────
ELAPSED=$(( $(date +%s) - START_TS ))
ok  "部署成功！耗时 ${ELAPSED}s"
info "容器状态："
$COMPOSE ps
info "如需查看日志：$COMPOSE logs -f --tail=100"
