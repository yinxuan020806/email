FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# build context = 仓库根（即 email 项目根目录）。
# 先装依赖以利用 Docker 层缓存（依赖列表变化频率远低于代码）。
COPY requirements.txt /app/email/requirements.txt
COPY code-receiver/requirements.txt /app/code-receiver/requirements.txt
RUN pip install --no-cache-dir -r /app/email/requirements.txt \
 && pip install --no-cache-dir -r /app/code-receiver/requirements.txt

# 显式 COPY 管理端各源码子目录到 /app/email（避免把 code-receiver 重复拷一份进去）
COPY core /app/email/core
COPY database /app/email/database
COPY static /app/email/static
COPY scripts /app/email/scripts
COPY web_app.py /app/email/web_app.py

# 接码前台自身
COPY code-receiver /app/code-receiver

# 共享 .master.key + emails.db 的目录
VOLUME ["/data"]
ENV EMAIL_DATA_DIR=/data \
    CRX_HOST=0.0.0.0 \
    CRX_PORT=8001 \
    CODE_OWNER_USERNAME=xiaoxuan

WORKDIR /app/code-receiver

# 等待 master.key 就位的 entrypoint，避免与管理端竞态启动
COPY code-receiver/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 非 root 用户
RUN groupadd -r app && useradd -r -g app -u 10001 app \
 && mkdir -p /data && chown -R app:app /data /app /entrypoint.sh
USER 10001:10001

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,sys; \
                 r=urllib.request.urlopen('http://127.0.0.1:8001/healthz',timeout=3); \
                 sys.exit(0 if r.status==200 else 1)"

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "app.py"]
