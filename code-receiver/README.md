# Code Receiver — Cursor / OpenAI 接码前台

> 邮箱管家仓库（`email/`）的子模块。
> 与管理端 `web_app.py` 共用同一份 SQLite + Fernet 主密钥，仅作为终端用户的极简接码前台。

---

## 功能

- 单页极简 UI：一个搜索框 + Cursor / ChatGPT 两个分类切换
- 多种凭据格式：仅邮箱 / `邮箱----密码` / `邮箱----密码----组` / Outlook OAuth2 4 段或 3 段
- 内置 Cursor / OpenAI 两套提取规则（6 位 OTP + Magic-Link，Outlook SafeLinks 自动 unwrap）
- 管理员可在 `extractor_rules` 表里热加规则（如 Anthropic、Google）
- 完全匿名 + 多维度限流 + 凭据失败锁定 + 凭据不落库

---

## 与管理端的关系

| 模块 | 管理端 (`email/`) | 接码前台 (`code-receiver/`) |
| --- | --- | --- |
| 端口 | 8000 | 8001 |
| 用户 | 注册/登录的多用户 | 完全匿名 |
| 数据库 | 写入 accounts/users/sessions/... | **只读**公开账号；只写 `query_count` 自增 + `code_query_log` |
| 共享 | `data/.master.key` + `data/emails.db` | 同一份 |
| 配置接码业务 | UI 上把账号设为 `is_public=1`、添加提取规则 | 不能写 |

> 当前版本的"接码业务配置"目前只通过 SQL 直接写。**有两种风格，按需选用**：
>
> **方式 A：靠分组名自动推断（推荐，零额外配置）**
>
> 截至本版本，前台已经能从管理端的 `group_name` 自动推断该账号属于哪个分类：
>
> | group_name 含 | 自动允许的 category |
> | --- | --- |
> | `cursor` | `cursor` |
> | `gpt` / `openai` / `chatgpt` | `openai` |
> | `cursor+gpt` | 两者都允许 |
> | `默认分组` 或其他 | 不允许（防止误公开） |
>
> 所以您只需要把已经放在对应分组里的账号一键设为公开：
> ```sql
> -- 把 xiaoxuan 名下所有 group_name 含 cursor / gpt 的账号设为公开
> UPDATE accounts SET is_public = 1
>  WHERE owner_id = (SELECT id FROM users WHERE username = 'xiaoxuan')
>    AND (lower(group_name) LIKE '%cursor%' OR lower(group_name) LIKE '%gpt%');
> ```
>
> **方式 B：显式 `allowed_categories` 精细控制（高级覆盖）**
>
> 当 `allowed_categories` 非空时，**忽略 group_name 推断**，只按字段值判定：
> ```sql
> -- 仅允许 cursor 分类（即使分组名是 cursor+gpt）
> UPDATE accounts SET is_public = 1, allowed_categories = 'cursor'
>  WHERE id = 123;
>
> -- 允许所有分类（站长完全信任的池子）
> UPDATE accounts SET is_public = 1, allowed_categories = '*'
>  WHERE id = 124;
> ```
>
> 后续可在管理端 UI 上加可视化开关（schema 已就位）。

---

## 数据库 schema 改动（v4 → v5）

`email/database/db_manager.py` 已升级到 v5，对老数据库做**增量在线升级**（不动旧数据）：

- `accounts` 表新增三列：
  - `is_public INTEGER DEFAULT 0` — 是否允许前台仅凭邮箱地址查询
  - `allowed_categories TEXT DEFAULT ''` — 允许的分类逗号分隔（空=允许所有）
  - `query_count INTEGER DEFAULT 0` — 被前台查询累计次数
- 新表 `extractor_rules`：管理员可热加的提取规则（按 category）
- 新表 `code_query_log`：前台查询日志（IP / 邮箱**仅存 SHA-256 哈希**，原文不入库）

---

## 安全约束

1. **凭据生命周期**：用户输入的密码 / refresh_token 仅在请求函数局部变量内存活，响应返回前由 `_wipe()` 主动置空；**绝不写入数据库或日志**
2. **日志脱敏**：`code_query_log` 只存 IP/邮箱的 SHA-256 哈希；`logger` 不打印密码
3. **限流**（默认值，可通过环境变量调）：
   - IP：1 分钟 5 次 / 1 小时 30 次
   - 邮箱：1 小时 10 次（无视 IP）
   - 凭据失败：3 次 → 封 IP 1 小时
4. **HTTP 安全头**：`X-Content-Type-Options`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`、`Content-Security-Policy: default-src 'self'`、`Permissions-Policy`
5. **代理信任**：默认不信任 `X-Forwarded-For`（避免伪造 IP 绕过限流）；反代场景必须显式 `CRX_TRUST_PROXY=1`
6. **账号读取范围**：仅 `username = ${CODE_OWNER_USERNAME}` 这一个用户名下的、且 `is_public=1` 的账号会被前台读取；其他用户不受影响
7. **写权限隔离**：前台只通过 `db_proxy.CodeReceiverDB` 操作 DB，仅暴露 4 类方法（读公开账号 / 读规则 / 自增 query_count / 写日志），其他全部 AttributeError
8. **HTTPS 必装**：明文凭据传输必须走 HTTPS，建议 nginx / Caddy / Cloudflare Tunnel 反代

---

## 启动

### 1. 本地开发（与管理端同时跑）

```powershell
# 1. 先启动管理端（在仓库根目录）
cd <repo-root>
python web_app.py    # 监听 8000

# 2. 再启动接码前台（另一个终端）
cd <repo-root>\code-receiver
pip install -r requirements.txt
$env:CODE_OWNER_USERNAME = "xiaoxuan"
python app.py
# 默认 http://127.0.0.1:8001
```

### 2. Docker（联合启动两个服务，推荐）

在仓库根目录执行：

```bash
docker compose up -d --build
# 管理端 → http://127.0.0.1:8000
# 接码前台 → http://127.0.0.1:8001
```

详细的服务器部署（含 git 推 / pull、Cloudflare Tunnel、首次初始化、排错）见仓库根的 [`DEPLOY.md`](../DEPLOY.md)。

### 3. 反代到公网（必须）

明文凭据传输必须走 HTTPS。推荐 Cloudflare Tunnel / Caddy / nginx，把 8001 反代上去，并开启 `CRX_TRUST_PROXY=1`。

---

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `CODE_OWNER_USERNAME` | `xiaoxuan` | 接码业务的站长用户名（仅这个用户的 `is_public=1` 账号被前台查到） |
| `CRX_HOST` | `127.0.0.1` | 监听地址 |
| `CRX_PORT` | `8001` | 监听端口 |
| `CRX_LOG_LEVEL` | `INFO` | 日志级别 |
| `CRX_TRUST_PROXY` | _空_ | `1` 时信任 `X-Forwarded-For`（反代场景必须） |
| `CRX_RATE_IP_PER_MIN` | `5` | IP 1 分钟限流阈值 |
| `CRX_RATE_IP_PER_HOUR` | `30` | IP 1 小时限流阈值 |
| `CRX_RATE_EMAIL_PER_HOUR` | `10` | 邮箱 1 小时限流阈值 |
| `EMAIL_DATA_DIR` | 自动 | 数据目录，与管理端共享；默认指向 `../data` |

---

## 测试

```powershell
cd <repo-root>\code-receiver
pip install pytest
python -m pytest tests -v
```

包含：

- `tests/test_input_parser.py` — 5 种输入格式 + 边界
- `tests/test_extractors.py` — Cursor / OpenAI 默认规则 + SafeLinks unwrap

---

## 提取规则的扩展

提取规则有两个来源，运行时合并（DB 规则优先级与代码规则混排，按 `priority DESC` 排序）：

1. **代码内置默认规则**：`extractors/cursor.py` 与 `extractors/openai_chatgpt.py`
2. **DB 中的 `extractor_rules` 表**（可由管理员热改）：

```sql
-- 新增 Anthropic / Claude 的接码规则示例：
INSERT INTO extractor_rules
  (category, sender_pattern, subject_pattern, code_regex, link_regex, priority, enabled, remark)
VALUES (
  'anthropic',
  '*@anthropic.com|*@claude.ai',
  'Verify*|Sign in*|verification*',
  '(?<!\d)(?P<code>\d{6})(?!\d)',
  '(?P<link>https?://(?:[a-z0-9-]+\.)?(?:anthropic\.com|claude\.ai)/[^\s"''>]+)',
  100,
  1,
  '默认 Anthropic 规则'
);
```

新增分类后需要在 `app.py:ALLOWED_CATEGORIES` 和前端 `index.html` 同步加 chip。

---

## 已知约束

- `data/.master.key` 必须与管理端共享（同一份 Fernet key），否则解密 `is_public` 账号的 IMAP 密码会失败
- Gmail 个人账号正在逐步禁用应用专用密码，部分账号必须走 OAuth；这意味着前台对 Gmail 的支持会随 Google 政策退化（影响管理端同样存在）
- 限流是本进程内存 + DB 计数；多副本部署需把内存锁迁到 Redis
- 当前没有验证码图形 / Turnstile 校验；如未来出现脚本爆破再补
