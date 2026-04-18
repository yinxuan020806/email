FROM python:3.12-slim AS base

# 国内镜像可换 PIP_INDEX_URL；公网默认即可
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    EMAIL_DATA_DIR=/data \
    EMAIL_WEB_HOST=0.0.0.0 \
    EMAIL_WEB_PORT=8000

WORKDIR /app

# 先装依赖以利用 Docker 层缓存
COPY requirements.txt ./
RUN pip install -r requirements.txt

# 拷贝源代码
COPY core ./core
COPY database ./database
COPY static ./static
COPY scripts ./scripts
COPY web_app.py ./

# 数据目录（密钥 + SQLite + 可选证书）应由宿主机挂载
RUN mkdir -p /data
VOLUME ["/data"]

# 非 root 用户运行
RUN useradd --create-home --uid 10001 app \
    && chown -R app:app /data /app
USER app

EXPOSE 8000

# 容器健康检查
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=3); sys.exit(0 if r.status==200 else 1)"

CMD ["python", "web_app.py"]
