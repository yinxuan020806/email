FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
    PIP_TRUSTED_HOST=pypi.tuna.tsinghua.edu.cn \
    PIP_DEFAULT_TIMEOUT=120

# build context = 仓库根（即 email 项目根目录）。
# 容器内布局必须跟 git 仓库布局一致：
#   /app/email/                ← 仓库根（管理端代码）
#   /app/email/core/           ← 管理端模块
#   /app/email/code-receiver/  ← 接码前台子目录（app.py 在这）
# 这样 app.py 里的 os.path.join(HERE, "..") 在容器内 = /app/email，
# sys.path 加进去就能正确 import core / database 等模块。
WORKDIR /app/email

# 先装依赖以利用 Docker 层缓存（依赖列表变化频率远低于代码）
COPY requirements.txt requirements.txt
COPY code-receiver/requirements.txt code-receiver/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir -r code-receiver/requirements.txt

# 管理端源码（与 email/Dockerfile 保持一致的目录命名）
COPY core core
COPY database database
COPY static static
COPY scripts scripts
COPY web_app.py web_app.py

# 接码前台自身（包含 entrypoint.sh / app.py / extractors/ 等）
COPY code-receiver code-receiver

# entrypoint 单独再放一份到根，避免被 USER 切换后无权访问；
# chmod +x 保证可执行（虽然 .gitattributes 已强制 LF，多保一道）
COPY code-receiver/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 共享 .master.key + emails.db 的目录
VOLUME ["/data"]
ENV EMAIL_DATA_DIR=/data \
    CRX_HOST=0.0.0.0 \
    CRX_PORT=8001 \
    CODE_OWNER_USERNAME=xiaoxuan

# 进程工作目录切到 code-receiver/，这样 CMD ["python", "app.py"] 能直接定位
WORKDIR /app/email/code-receiver

# 非 root 用户运行
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
