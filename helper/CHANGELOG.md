# Email Helper Changelog

## 0.1.3 - 2026-05-11

> 第四轮深度优化：从「值得用」到「敢上生产」。聚焦 P0/P1 测试覆盖、并发
> 安全、token 收紧、运维一致性。Helper EXE 协议层未动（client/handlers/
> protocol 0 改），0.1.0+ EXE 继续可用。

### 测试：pytest 单测覆盖（72 个用例）

之前 helper 功能完全没有 pytest 覆盖，只能靠手工 `_smoke_e2e.py`；本版补齐：

- `tests/test_helper_token.py`（13 用例）：provision / validate / TTL /
  touch / revoke / revoke_all / list / purge_expired / 跨用户隔离 /
  MAX_TOKENS_PER_USER
- `tests/test_helper_registry.py`（27 用例）：parse_version / _version_ok /
  HelperSession alive/outbox/drain / register/unregister/replace /
  get_online per owner / dispatch 完整链路（含 offline / 版本守门 / 连通性
  豁免 / 超时 / 并发上限）/ cancel_task（含跨 owner 隔离 + outbox drain）/
  subscribe_logs LRU / broadcast_log 按 owner 隔离
- `tests/test_helper_routes.py`（18 用例）：xiaoxuan 鉴权 / 未登录 401 /
  provision token / list 脱敏 / MAX_TOKENS_PER_USER / revoke / status 含
  version_ok / dispatch action 白名单 + params 大小 / stale_account_id /
  批量 SSE / 批量拒 change_password / cancel-task / audit_log 写入

CI 跑 pytest 现在能拦住 helper 模块大部分回归。

### 服务端：同 owner 并发任务上限 = 3

旧实现：用户狂点 4 行按钮 → 4 个 dispatch 同时往 helper outbox 塞 → helper
4 个 task 线程同时跑 → 抢 chromium 资源 + Outlook 风控被触发。

新实现：`MAX_CONCURRENT_TASKS_PER_OWNER = 3`，业务 action（非 echo/ping/version）
派发前先查同 owner 的 `_pending` 数；满了返回 `too_many_concurrent: True`
让前端显示明确文案而不是排队等死。

### 服务端：cancel_task 从 outbox drain

旧实现：cancel 只让 dispatch 立刻返回，但 task 已派到 helper 的 outbox 里仍
会被 helper 取走执行。

新实现：cancel 时先把 helper outbox 里**还没被 poll 走**的同 task_id 任务
drain 掉（彻底取消）；helper 已经在跑的任务无法中断（HTTP 长轮询限制），但
绝大多数排队任务能秒杀。

`_pending` 字典从 `task_id -> queue` 改成 `task_id -> (queue, owner_id)`，
顺手支持了"cancel 跨 owner 隔离"（owner B 不能 cancel owner A 的 task）。

### 服务端：token TTL 30 天 → 7 天 + 总数上限

安全审视后收紧：

- `DEFAULT_TTL_SECONDS = 7 * 24 * 3600`（之前 30 天）—— `emailhelper://`
  URL 协议有被浏览器历史 / 扩展截获的可能；30 天的重放窗口太宽
- `MAX_TOKENS_PER_USER = 32`：单用户未撤销 token 上限。超出 `provision_token`
  抛 ValueError，路由层转 400 引导用户去清理。防误循环 / 接口刷爆 helper.db

### 服务端：批量审计聚合

旧实现：批量 200 个账号 → 写 200 条 `helper_batch_<action>` audit 记录，把
audit_log 表撑爆。

新实现：
- 入口写 1 条 `helper_batch_<action>_start`（target=accounts=N）
- 仅**失败**的账号单独写一条（便于排查）
- 完成写 1 条 `helper_batch_<action>_done` 含 success/fail/total/aborted

正常情况下 N=200 全成功 → 只写 2 条；全部失败 → 写 N+2 条。两端都合理。

### 服务端：多 worker 警告

`HelperRegistry` 是进程内单例，多 worker 部署会让 register 与 dispatch 落
不同 worker → 找不到 session。`web_app.main()` 检测 `EMAIL_WEB_WORKERS > 1`
时强 stderr 警告。README 同步补出说明。

### 客户端：shutdown 日志诚实化

`HelperClient.shutdown()` 旧版无条件打 `[OFFLINE] 已停止`，即便 join 超时
后线程仍在退出。新版区分两种情况：
- join 完成 → `已停止`
- join 超时 → `已请求停止（join 超时 3s 后线程仍在退出：loop=true hb=false，
  依赖进程退出兜底）`

便于运维定位"进程为什么没立刻退"。

### 前端：上下线 toast 30s 防抖

网络抖动会让 helper 在 60s 心跳窗口内反复 offline↔online，原本每次翻转都
弹 toast 导致 2 分钟内闪 4-6 次。新版同方向 30s 内不重复 toast。

### 前端：批量绑定辅助邮箱按钮

之前批量按钮只有 🔓 / 🔑，缺 🔗。后端 `_BATCH_ALLOWED_ACTIONS` 早就允许
`bind_recovery_email`，前端补出入口。

### 文档：PowerShell ExecutionPolicy 提示

`helper/README.md` 和主 `README.md` 都加上：

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

避免新用户右键 .ps1 被 Win10/11 默认 Restricted 拒绝时一脸懵。

### ⚠ 升级提醒

- **Web 端**：版本 0.1.2 → 0.1.3；前端新增「批量绑辅助 / toast 防抖」
- **Helper EXE**：本版**不破协议层**（client/handlers/protocol 0 改），
  0.1.0+ EXE 可继续使用；但建议重编以拿到「shutdown 诚实化日志」
- **数据库**：schema 未变；老 helper.db 的 TTL 改成 7 天后，30 天未用的旧
  token 会被 purge_expired 物理删除（首次 cleanup 任务跑时）

## 0.1.2 - 2026-05-11

> 第三轮深入优化：从「能跑」到「值得用」。聚焦审计、批量、安全防御与日志体验。
> Helper EXE 协议层未动（client/handlers/protocol/actions 0 改），0.1.0 EXE 继续可用。

### 服务端：审计日志全量覆盖

每个 helper 端点完成时写入一条 `audit_log` 记录，包含：
- `action`：`helper_provision_token` / `helper_revoke` / `helper_mailbox_open` /
  `helper_mailbox_get_token` / `helper_mailbox_change_password` /
  `helper_mailbox_bind_recovery` / `helper_dispatch_<action>` /
  `helper_batch_<action>`
- `target`：操作目标邮箱地址 / token 后 8 位 / `*all*`
- `success`：操作是否成功
- `detail`：`task_id=...,err=...,offline=...,cancelled=...,upgrade_required>=...`
- `ip` / `user_agent`：从请求头解析

xiaoxuan 可以在「⚙ 设置 → 审计日志」直接看到自己的全部 helper 操作历史，
出问题时随时能溯源「哪个 task 失败了 / 什么原因 / 哪个 IP 发起的」。

`echo` / `ping` / `version` 等连通性测试豁免审计（避免刷屏）。

### 服务端：批量 helper 操作（新增）

旧实现：账号表里每行有 4 个 helper 按钮，但只能一个一个点。

新实现：表格顶部 actionBar 增加 2 个 owner-only 批量按钮：
- 🔓 **批量登录**：对选中的 N 个账号串行调 `open_mailbox`
- 🔑 **批量取 Token**：对选中的 N 个账号串行调 `get_ms_token`，成功自动落库

新增接口 `POST /api/helper/batch/mailbox`：
- SSE 流式：每完成一个就推一条 `progress` 事件，最后一条 `done`
- 串行而非并发：本地 Helper 只有一个 Chromium 池，并发会让 Outlook 风控更猛
- 失败 / stale_account_id / needs_helper_upgrade 都在 progress 里逐条上报
- 自动写 audit_log 每条 `helper_batch_<action>`
- 不支持 `change_email_password`（一次性给所有账号设同一密码无意义且危险）

前端进度 Modal：实时进度条 + 滚动日志 + 成功/失败计数。

### 服务端：dispatch action 白名单（防御）

`POST /api/helper/dispatch` 是开放接口，可以接受任意 `action` 字符串。
旧实现没有限制，前端误传 / 攻击者构造的奇怪 action 也能进 helper outbox
队列 + 消耗任务超时名额（每次 dispatch 阻塞一个线程池 worker）。

新实现：
- 仅允许 `_DISPATCH_ALLOWED_ACTIONS`：`echo` / `ping` / `version` + 4 个邮箱
  业务 action
- `params` 字段数 > 32 直接拒（防大对象塞 outbox）
- 业务接口（`mailbox/*`）走专门路由不受此限

### 服务端：HelperRegistry 兼容性整理

- `dispatch` 新加 `min_helper_version` 参数（Stage 2 个别 action 可以单独要求
  更高版本）
- `MIN_HELPER_VERSION` 与 `ALWAYS_ALLOWED_ACTIONS` 导出到 `__all__`

### 前端：helper 上线/下线 toast 提示

旧行为：用户在主表格视图，本地 helper 被关掉 / 突然失联，UI 上没任何
提示（要切到 Help 页才能看到状态变红）。

新行为：
- xiaoxuan 登录后立即启动 helper status 轮询（不只在 Help 页）
- 主表格视图轮询周期放宽到 15s（省 RTT），Help 页 1.5-5s
- 状态翻转时弹 toast：
  - 上线：`🟢 邮箱 Helper 已上线`（success）
  - 下线：`🔴 邮箱 Helper 已掉线，请检查本地客户端`（warning）
- 首次加载时不弹（避免每次进 Help 页都弹一次）

### 前端：Help 页常驻 SSE 日志

旧行为：实时日志只在「Helper 任务 Modal」展开期间订阅，关闭就丢；用户
看不到之前的派单历史。

新行为：
- Help 视图新增第 5 个卡片「📜 实时日志」（占满最后一行）
- 进 Help 页就建立 SSE 订阅，离开页面关闭
- 自动加时间戳 `[HH:MM:SS]` 前缀
- 最多保留 500 行（超过自动从顶部清，避免内存涨爆）
- 自带「清空」按钮

### 文档

- `helper/CHANGELOG.md`：新增 0.1.2 条目
- 主仓库 `README.md`：新增「📬 邮箱助手 Helper（站长专属）」专章

### ⚠ 升级提醒

- **Web 端**：版本号 0.1.1 → 0.1.2；前端展示新增「实时日志卡 / 批量按钮 /
  上下线 toast / audit 入口」
- **Helper EXE**：本版**不破协议层**（client/handlers/protocol/actions 0 改），
  0.1.0 EXE 可继续使用
- **数据库**：`emails.db` schema 未变（audit_log 表已存在）；`helper.db`
  schema 未变

## 0.1.1 - 2026-05-11

> 借鉴 cursor-manager helper 0.1.1 ~ 0.1.11 的多轮迭代经验，做了一轮深度优化。
> Stage 1 协议层完全未动（client.py / handlers.py / protocol.py 0 改），
> 0.1.0 EXE **可继续使用，无需重编**；版本号同步只为前端 badge 一致性。

### 服务端：dispatch 链路实时日志桥接（参考 0.1.2）

旧实现：用户在 Web 面板点「自动登录」后看着 Modal 卡几十秒没反馈，直到 helper
推回 task-log 才有日志。

新实现：`HelperRegistry.dispatch()` 内部在派单前/超时/取消/完成 4 个关键节点
**自己广播 SSE 日志**，不依赖 helper 客户端推：

- 派单前推一条 `🛰 已派发任务到本地 Helper：action=... task_id=...`
- 任务超时推 `⏱ 任务 ... 超时（120s 内未收到 Helper 回报）`
- 任务取消推 `🛑 任务 ... 已被用户取消`
- 任务完成推 `✅ 任务 ... 完成` 或 `❌ 任务 ... 失败：...`

实现细节：
- `core/helper_registry.py` 新增 `_broadcast()` 私有方法 + `broadcast_log()` 公开 API
- 通过 `_log_sink` 机制（默认实现 = `subscribe_logs` SSE 桶）单向广播
- Helper 自己 task-log 推上来的日志仍正常工作，与 server broadcast 不冲突

### 服务端：Helper 版本一致性守门（参考 0.1.8）

旧实现：任何版本的 helper 都能跑任何 action；老 EXE 缺少 Stage 2 新加的 action
时会得到一个模糊的 `Helper 不支持 action: xxx` 错误。

新实现：
- 新增 `MIN_HELPER_VERSION = "0.1.0"` 常量 + `_version_ok()` semver 解析
- `dispatch()` 在派单前检查 `sess.version`；过低返回 `{success: False,
  needs_helper_upgrade: True, current_version, min_version}`
- 连通性测试 action（`echo` / `ping` / `version`）豁免版本检查
- `GET /api/helper/status` 新增 `min_helper_version` 与 `version_ok` 字段
- 前端识别 `needs_helper_upgrade` flag 自动弹 confirm 引导用户去「📥 下载」

### 服务端：stale_account_id 一致响应（参考 0.1.10）

旧实现：当 `account_id` 对应的账号已被删（其他客户端删过 / 数据库迁移失败等），
helper API 返回死文案 `账号不存在: id=42`，用户必须手动刷新页面。

新实现：
- `_resolve_account_credentials()` 在账号不存在时返回 `{success: False,
  code: "stale_account_id", stale_account_id: <id>}`
- 前端 `helperResponseGuard()` 拦截器识别 `code === 'stale_account_id'` 后
  自动 `loadAccounts()` 刷新表格 + toast 提示
- 与参考项目 cursor-manager 0.1.10 的修复行为一致

### 服务端：任务取消 API（新增）

旧实现：用户点了「自动改密」之后只能干等到超时（300s）才能放弃。

新实现：
- `HelperRegistry.cancel_task(owner_id, task_id)`：往 result_queue 塞 `_cancelled`
  消息让阻塞的 dispatch 立即返回（success=False, cancelled=True）
- 新增 `POST /api/helper/cancel-task`
- 前端 Modal 在派单后从 SSE 日志解析出 task_id，自动显示「🛑 取消任务」按钮
- 限制：HTTP 长轮询模型不能中断已派到 helper 的任务，helper 那边任务仍会
  跑完；但 web 用户立刻拿到 cancelled 响应，UI 解锁

### 前端：实时已运行时长 + 取消按钮

- Helper 任务 Modal 头部新增 `⏱ 0s` 实时计数器（500ms 刷新）
- 任务派发成功后自动显示「🛑 取消任务」按钮
- 任务结束 / 用户关闭 Modal 时自动清理 setInterval 与 EventSource

### 工程化

- `helper/EmailHelper.spec`：PyInstaller 单文件打包配置（带 `console=False` /
  `upx=True` / 自动收集 certifi data files）
- `helper/_smoke_e2e.py`：端到端冒烟测试脚本（6 步：provision → register →
  status → dispatch echo/ping/version → mailbox stub → revoke）。带自动登录
  辅助，支持 `python helper/_smoke_e2e.py http://host:port` 一行跑通
- `helper/build.ps1`：已在 0.1.0 实现，本版不动；spec 文件存在时优先用 spec

### Stage 2 准备工作

下面这些字段已经在协议里预留好，Stage 2 直接用即可：
- `dispatch.min_helper_version` 参数：Stage 2 新 action 可以指定 `0.2.0` 强制升级
- helper_routes `mailbox/*` 接受 `account_id` 优先于明文 `email + password`
- `helper.actions.mailbox` 4 个 action 入参签名已对齐 cursor-manager 0.1.11

### ⚠ 升级提醒

- **Web 端**：版本号同步升到 0.1.1；前端会在 Help 视图显示 helper 版本与
  最低版本，过低时给一条黄色警告条
- **Helper EXE**：**本版不破协议层**（`client.py` / `handlers.py` / `protocol.py`
  / `actions/*` 0 改），0.1.0 EXE 可继续使用
- **数据库**：`helper.db` schema 未变；首次启动会自动 `CREATE TABLE IF NOT EXISTS`

## 0.1.0 - 2026-05-11

首个可用版本（Stage 1 MVP）。

### 通信协议：HTTP 长轮询

走 **HTTP 长轮询**（不是 WebSocket）。原因：
- FastAPI + uvicorn 虽然原生支持 WebSocket，但多 worker + Cloudflare / Nginx
  反代场景下 idle timeout 难以管控
- HTTP 长轮询完全不依赖 ASGI 实现，所有部署方式都能跑
- 实际延迟与 WebSocket 几乎一致（300ms-1s 派发）
- 客户端依赖更少（仅需 `requests`）

具体端点见 `core/helper_routes.py` / `core/helper_registry.py`。

### Helper 客户端

- HTTP 长轮询客户端（`requests.Session`）+ 自动重连 + 指数退避
- 心跳：每 20s POST `/api/helper/heartbeat`
- 长轮询：阻塞 25s 取任务，最多一次拉 16 条批
- 任务执行线程独立 + 日志缓冲 500ms 批量回传
- 3 个内置 action：`echo` / `ping` / `version`（连通性测试）
- 4 个 stub action：`open_mailbox` / `get_ms_token` / `change_email_password` /
  `bind_recovery_email`（接口已定义，Stage 2 移植浏览器自动化后启用）
- 系统托盘 UI（pystray + Pillow），三色圆点（绿/黄/红）随状态切换
- `emailhelper://` URL 协议注册（HKCU，无需管理员）
- 开机自启注册（HKCU Run 项）
- 一键安装 / 卸载 PowerShell 脚本
- PyInstaller 单文件打包脚本

### 服务器侧

- 新增 `core/helper_registry.py`：连接池 + outbox queue + 任务派发 +
  SSE 日志广播桶
- 新增 `core/helper_routes.py`：13 个 HTTP 端点，分两类：
  - 给 Web 面板（带 cookie + xiaoxuan 鉴权）：provision-token / status /
    tokens / revoke / dispatch / download-info / logs(SSE) +
    mailbox/{open,get-token,change-password,bind-recovery}
  - 给 Helper 客户端（无 cookie，用 token / helper_id 鉴权）：register /
    poll-task / task-result / task-log / heartbeat
- 新增 `database/helper_token.py`：独立 helper.db + helper_tokens 表（含
  owner_id 多用户隔离）
- xiaoxuan 限制：复用现有 `CODE_OWNER_USERNAME` 机制（`require_owner` 依赖 +
  前端 `.owner-only` 隐显）

### Web 面板

- 侧边栏「📬 邮箱助手」入口（仅 xiaoxuan 可见）
- Help 视图 4 个卡片：状态 / 邮箱操作 / Token 列表 / 下载安装
- 邮箱操作 4 个功能格子：`🔓 自动登录` / `🔑 获取 Token` / `🔒 修改密码` /
  `🔗 绑定辅助邮箱`
- 主账号表「操作」列每行新增 4 个 owner-only 图标按钮（🔓 🔑 🔒 🔗），
  点击直接派任务
- 任务执行 Modal 带 SSE 实时日志流
- 删除原「手动授权」入口与 `/api/oauth2/*` 后端接口
