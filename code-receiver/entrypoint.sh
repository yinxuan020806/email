#!/bin/sh
# 接码前台启动前等待 master.key 就位（由管理端 email-web 首次启动时生成）。
# 没有这一步时如果两个容器一起 up，code-receiver 会因 master.key 不存在
# 而 RuntimeError 退出，依赖 restart 兜底，体验差。
set -e

KEY="${EMAIL_DATA_DIR:-/data}/.master.key"
TIMEOUT="${MASTER_KEY_WAIT_TIMEOUT:-60}"

i=0
while [ ! -f "$KEY" ]; do
  if [ "$i" -ge "$TIMEOUT" ]; then
    echo "ERROR: master.key not found after ${TIMEOUT}s at $KEY" >&2
    echo "请先在管理端 (email-web) 完成首次启动以生成 master.key" >&2
    exit 1
  fi
  if [ $((i % 5)) = 0 ]; then
    echo "Waiting for master.key at $KEY... (${i}/${TIMEOUT}s)"
  fi
  sleep 1
  i=$((i + 1))
done

echo "master.key ready, launching: $*"
exec "$@"
