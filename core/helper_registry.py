"""
Helper 连接池 & 任务派发（HTTP 长轮询模型，FastAPI 适配）
==========================================================

为什么不用 WebSocket
--------------------
本项目用 uvicorn 跑 FastAPI，虽然 uvicorn 原生支持 WebSocket，但要保证多
worker / 反代部署下连接稳定（Cloudflare、Nginx 都有 idle timeout），
HTTP 长轮询是更鲁棒、运维友好的选择。

- ``Server → Helper``：``GET /api/helper/poll-task`` 阻塞 ~25s 等任务
- ``Helper → Server``：``POST /api/helper/task-result`` / ``task-log`` /
  ``heartbeat``（普通短请求）

延迟可控（300ms-1s 派发）；任何 WSGI/ASGI 部署都兼容；无需任何特殊配置。

设计要点
--------
- ``HelperSession.outbox``：服务端要发给 helper 的消息塞进这个 ``queue.Queue``，
  长轮询路由阻塞读取。
- ``HelperSession.last_seen``：每次 poll-task / heartbeat 都更新；
  超过 ``HEARTBEAT_DEAD_AFTER`` 没动静的 session 被认为掉线。
- ``dispatch(action, params, timeout)``：同步接口（put 任务到 outbox，
  等 result queue 拿结果）。FastAPI 路由调用时**必须**包到 ``run_in_threadpool``
  里，避免阻塞 asyncio event loop。
"""
from __future__ import annotations

import logging
import queue
import secrets
import threading
import time
from typing import Any, Callable, Optional

from database import helper_token as _tk

logger = logging.getLogger(__name__)


# 默认任务超时 120 秒。Outlook 浏览器登录可能慢，调用方可以传更大值。
DEFAULT_TASK_TIMEOUT = 120

# 心跳：服务端 60 秒没收到任何消息就认为掉线。
# 客户端默认 25 秒一次长轮询 + 20 秒一次 heartbeat，留两倍冗余。
HEARTBEAT_DEAD_AFTER = 60

# 长轮询单次最长阻塞时长（秒）。客户端在每次返回后立刻发起下一次。
POLL_BLOCK_SECONDS = 25

# 单 helper 的 outbox 队列上限：满了说明客户端长期不取，直接踢掉避免内存涨爆。
OUTBOX_MAX = 256

# 单用户对同一 helper 的并发任务上限。
#
# 设计动机：用户狂点表格 4 行的 🔓 按钮会同时调 4 次 dispatch，4 个 task 同时
# 塞 helper outbox → helper 4 个 task 线程同时跑 chromium → 抢资源 + Outlook
# 风控被触发的概率激增。上限 3 = 留 1 个连通性测试 (echo/ping) 不被业务任务
# 挤爆，同时让用户的业务并发被限制。
MAX_CONCURRENT_TASKS_PER_OWNER = 3

# Helper 客户端最低支持版本：低于此版本的 helper 不允许 dispatch 业务 action。
# 0.2.0 之前的 helper EXE 里 `helper/actions/mailbox.py` 是 stub，调用业务
# action 会立即返回"Stage 1 未实现"占位文案。Stage 2 上线后 server 端
# 要把老 EXE 拦住引导用户重新下载，否则用户面对的是 stub 提示一脸懵。
MIN_HELPER_VERSION = "0.2.0"

# 只有这几个 action 不需要 helper 升级（连通性测试）。其它业务 action 都受版本守门
ALWAYS_ALLOWED_ACTIONS = frozenset({"echo", "ping", "version"})


def _parse_version(v: str) -> tuple[int, int, int]:
    """简单 semver 解析：``"0.1.10"`` → ``(0, 1, 10)``；非法格式回退 ``(0, 0, 0)``"""
    if not v:
        return (0, 0, 0)
    parts = (v or "").strip().lstrip("v").split(".")
    out = [0, 0, 0]
    for i in range(min(3, len(parts))):
        try:
            out[i] = int(parts[i].split("-")[0])  # 0.1.0-dev → 0.1.0
        except (ValueError, TypeError):
            out[i] = 0
    return (out[0], out[1], out[2])


def _version_ok(client_version: str, min_version: str = MIN_HELPER_VERSION) -> bool:
    """``client_version`` >= ``min_version`` 返回 True；
    缺失版本一律按 0.0.0 处理（拒绝）。"""
    return _parse_version(client_version) >= _parse_version(min_version)


class HelperSession:
    """一条已注册的 Helper 会话（无长连接，靠定期 poll 保活）。"""

    __slots__ = (
        "helper_id", "token", "owner_id", "version", "platform",
        "registered_at", "last_seen", "_alive",
        "outbox",
    )

    def __init__(
        self,
        helper_id: str,
        token: str,
        owner_id: int,
        version: str,
        platform: str,
    ):
        self.helper_id = helper_id
        self.token = token
        self.owner_id = int(owner_id or 0)
        self.version = version or ""
        self.platform = platform or ""
        now = time.time()
        self.registered_at = now
        self.last_seen = now
        self._alive = True
        self.outbox: queue.Queue = queue.Queue(maxsize=OUTBOX_MAX)

    @property
    def alive(self) -> bool:
        if not self._alive:
            return False
        if time.time() - self.last_seen > HEARTBEAT_DEAD_AFTER:
            return False
        return True

    def mark_dead(self) -> None:
        self._alive = False
        # 给可能还在阻塞 poll 的请求一个"空唤醒"，让它快速返回
        try:
            self.outbox.put_nowait({"type": "_terminate"})
        except queue.Full:
            pass

    def touch(self) -> None:
        self.last_seen = time.time()

    def send(self, msg: dict) -> bool:
        """把消息塞进 outbox 等 helper 下一次 poll-task 取走。失败返回 False。"""
        if not self._alive:
            return False
        try:
            self.outbox.put_nowait(msg)
            return True
        except queue.Full:
            logger.warning(
                "[helper:%s] outbox 已满（%d），客户端长期不取 → 标记断开",
                self.helper_id, OUTBOX_MAX,
            )
            self.mark_dead()
            return False

    def drain(self, timeout: float, max_batch: int = 16) -> list[dict]:
        """长轮询取任务：阻塞 timeout 秒；有任务尽量多拿几条一起返回。"""
        out: list[dict] = []
        try:
            first = self.outbox.get(timeout=max(0.0, timeout))
            if first.get("type") != "_terminate":
                out.append(first)
        except queue.Empty:
            return out
        # 已拿到一个 → 立刻把剩下的非阻塞取出来一起返回，减少往返
        for _ in range(max_batch - 1):
            try:
                msg = self.outbox.get_nowait()
            except queue.Empty:
                break
            if msg.get("type") == "_terminate":
                continue
            out.append(msg)
        return out

    def to_status_dict(self) -> dict:
        return {
            "helper_id": self.helper_id,
            "owner_id": self.owner_id,
            "version": self.version,
            "platform": self.platform,
            "registered_at": int(self.registered_at),
            "last_seen": int(self.last_seen),
            "alive": self.alive,
        }


class HelperRegistry:
    """连接池 + 任务派发器（线程安全单例）。

    与单 helper 设计不同的是：本项目支持多用户，每个用户独立一份"在线 helper"
    选型 —— ``get_online(owner_id)`` 只返回该用户的 helper。
    """

    def __init__(self):
        self._sessions: dict[str, HelperSession] = {}     # helper_id -> session
        self._token_to_helper: dict[str, str] = {}        # token -> helper_id
        # task_id -> (result_q, owner_id)
        # 第二个元素让 cancel_task / 并发计数能反向查 owner，不必拿 result_q
        # 再回去问 session（task 派发后 helper 可能已经掉线，session 不存在）
        self._pending: dict[str, tuple[queue.Queue, int]] = {}
        self._lock = threading.Lock()
        self._log_sink: Callable[[int, str, str], None] = _default_log_sink

    # ── session 管理 ───────────────────────────────────────────

    def register(
        self,
        token: str,
        version: str,
        platform: str,
    ) -> tuple[Optional[HelperSession], Optional[str]]:
        """鉴权 + 注册一条新连接。返回 (session, error)，二者之一为 None。"""
        info = _tk.validate_token(token)
        if not info:
            return None, "token 无效或已撤销"

        helper_id = "h_" + secrets.token_hex(8)
        sess = HelperSession(
            helper_id=helper_id,
            token=token,
            owner_id=int(info.get("owner_id") or 0),
            version=version,
            platform=platform,
        )

        with self._lock:
            # 同一 token 已有 session → 顶替（用户重启 Helper / 重连）
            old_helper_id = self._token_to_helper.get(token)
            if old_helper_id:
                old_sess = self._sessions.pop(old_helper_id, None)
                if old_sess:
                    logger.info(
                        "[helper] 同 token 旧连接 %s 被新连接 %s 顶替",
                        old_helper_id, helper_id,
                    )
                    old_sess.mark_dead()
            self._sessions[helper_id] = sess
            self._token_to_helper[token] = helper_id

        try:
            _tk.touch_token(token, platform=platform, version=version)
        except Exception as e:  # noqa: BLE001
            logger.warning("[helper] touch_token 失败: %s", e)

        logger.info(
            "[helper] 注册成功 helper_id=%s owner_id=%d platform=%s version=%s",
            helper_id, sess.owner_id, platform, version,
        )
        return sess, None

    def unregister(self, helper_id: str) -> None:
        with self._lock:
            sess = self._sessions.pop(helper_id, None)
            if sess and self._token_to_helper.get(sess.token) == helper_id:
                self._token_to_helper.pop(sess.token, None)
        if sess:
            sess.mark_dead()
            logger.info("[helper] 注销 helper_id=%s", helper_id)

    def get(self, helper_id: str) -> Optional[HelperSession]:
        sess = self._sessions.get(helper_id)
        if sess and not sess.alive:
            return None
        return sess

    def get_online(self, owner_id: Optional[int] = None) -> Optional[HelperSession]:
        """返回最新一个在线 Helper。

        ``owner_id`` 非空时只返回该用户的 helper（多用户隔离）。
        """
        with self._lock:
            alive = [s for s in self._sessions.values() if s.alive]
        if owner_id is not None:
            alive = [s for s in alive if s.owner_id == int(owner_id)]
        if not alive:
            return None
        alive.sort(key=lambda s: s.registered_at, reverse=True)
        return alive[0]

    def is_online(self, owner_id: Optional[int] = None) -> bool:
        return self.get_online(owner_id=owner_id) is not None

    def status(self, owner_id: Optional[int] = None) -> dict:
        sess = self.get_online(owner_id=owner_id)
        if not sess:
            return {"online": False}
        info = sess.to_status_dict()
        info["online"] = True
        return info

    # ── 任务派发 ──────────────────────────────────────────────

    def dispatch(
        self,
        action: str,
        params: Optional[dict] = None,
        timeout: int = DEFAULT_TASK_TIMEOUT,
        owner_id: Optional[int] = None,
        min_helper_version: Optional[str] = None,
    ) -> dict:
        """把一个任务发给在线 Helper，阻塞等结果。

        - ``owner_id`` 非空 = 只用该用户的 helper
        - ``min_helper_version`` = 该 action 要求的最低 helper 版本（默认走全局
          ``MIN_HELPER_VERSION``）。低于此版本立即返回 ``needs_helper_upgrade=True``，
          引导用户在 Web 面板下载新 EXE
        - 返回 ``{"success": bool, "data"?: ..., "error"?: ..., "task_id": str, ...}``
        - 离线 / 写入失败 / 超时 / 取消 都作为 ``success: False`` 的结果返回，
          且会同步广播一条 SSE 日志让前端实时看到原因

        **必须**在 FastAPI 路由里包 ``starlette.concurrency.run_in_threadpool``
        调用，因为内部 ``queue.get(timeout)`` 是阻塞调用。
        """
        sess = self.get_online(owner_id=owner_id)
        if not sess:
            # 也广播一条让前端 SSE 日志窗能立刻看到原因
            self._broadcast(
                owner_id or 0,
                f"⚠ Helper 未连接，无法派发 {action}",
                "warning",
            )
            return {
                "success": False,
                "error": "Helper 未连接，请先在「邮箱助手」页面启动 Helper",
                "offline": True,
            }

        # 版本守门（仅业务 action 检查；echo / ping / version 这种连通性测试豁免）
        req_min = min_helper_version or MIN_HELPER_VERSION
        if action not in ALWAYS_ALLOWED_ACTIONS and not _version_ok(
            sess.version, req_min,
        ):
            self._broadcast(
                sess.owner_id,
                f"⚠ 本地 Helper 版本过低 (v{sess.version or '?'} < v{req_min})，"
                f"无法执行 {action}。请到「邮箱助手 → 📥 下载」更新 EXE",
                "warning",
            )
            return {
                "success": False,
                "error": (
                    f"本地 Helper 版本过低 (v{sess.version or '?'})，"
                    f"该功能要求 v{req_min}+。请到「邮箱助手 → 📥 下载」更新 EXE"
                ),
                "needs_helper_upgrade": True,
                "current_version": sess.version or "",
                "min_version": req_min,
            }

        # 并发上限检查 + 占坑 原子化：
        # 旧实现"检查 _pending 大小"与"插入 _pending[task_id]"是两步分离，
        # N 个线程同时进入会全部看到 in_flight=0 → 全部 admitted → 实际并发
        # 等于线程数而不是 MAX_CONCURRENT_TASKS_PER_OWNER。
        # 这里把检查 + 占坑放进同一个 ``with self._lock`` 块，保证原子。
        task_id = "t_" + secrets.token_hex(6)
        result_q: queue.Queue = queue.Queue(maxsize=1)
        too_many_resp = None
        with self._lock:
            if action not in ALWAYS_ALLOWED_ACTIONS:
                in_flight = sum(
                    1 for (_, oid) in self._pending.values()
                    if oid == sess.owner_id
                )
                if in_flight >= MAX_CONCURRENT_TASKS_PER_OWNER:
                    too_many_resp = {
                        "success": False,
                        "error": f"同时进行的任务太多（{in_flight}/"
                                 f"{MAX_CONCURRENT_TASKS_PER_OWNER}）。"
                                 f"请等当前任务完成再试。",
                        "too_many_concurrent": True,
                        "in_flight": in_flight,
                        "limit": MAX_CONCURRENT_TASKS_PER_OWNER,
                    }
            if too_many_resp is None:
                self._pending[task_id] = (result_q, sess.owner_id)

        if too_many_resp is not None:
            # broadcast 必须在锁外做（_broadcast 调 _log_sink 可能阻塞）
            self._broadcast(
                sess.owner_id,
                f"⚠ 同时进行的任务太多（{too_many_resp['in_flight']}/"
                f"{MAX_CONCURRENT_TASKS_PER_OWNER}），"
                f"请等当前任务完成再派 {action}",
                "warning",
            )
            return too_many_resp

        msg = {
            "type": "task",
            "task_id": task_id,
            "action": action,
            "params": params or {},
            "timeout": int(timeout),
        }
        if not sess.send(msg):
            with self._lock:
                self._pending.pop(task_id, None)
            self.unregister(sess.helper_id)
            self._broadcast(
                sess.owner_id,
                f"❌ {action} 出队失败，Helper 连接已断开",
                "error",
            )
            return {
                "success": False,
                "error": "Helper 出队失败，已断开",
                "task_id": task_id,
            }

        # 派单前先推一条 SSE 日志，让前端 Modal 立刻看到"已派发"，不必干等 30s 才有反馈
        self._broadcast(
            sess.owner_id,
            f"🛰 已派发任务到本地 Helper：action={action} task_id={task_id}",
            "info",
        )

        try:
            result = result_q.get(timeout=max(1, int(timeout)))
        except queue.Empty:
            logger.warning(
                "[helper:%s] 任务 %s (%s) 超时 %ds",
                sess.helper_id, task_id, action, timeout,
            )
            with self._lock:
                self._pending.pop(task_id, None)
            self._broadcast(
                sess.owner_id,
                f"⏱ 任务 {action} 超时（{timeout}s 内未收到 Helper 回报）",
                "error",
            )
            return {
                "success": False,
                "error": f"Helper 任务超时（{timeout}s）",
                "task_id": task_id,
            }
        finally:
            with self._lock:
                self._pending.pop(task_id, None)

        # 任务被显式取消（cancel_task 往结果队列里塞了一条 cancelled 消息）
        if result.get("_cancelled"):
            self._broadcast(
                sess.owner_id,
                f"🛑 任务 {action} (task_id={task_id}) 已被用户取消",
                "warning",
            )
            return {
                "success": False,
                "error": "任务已被用户取消",
                "cancelled": True,
                "task_id": task_id,
            }

        # 任务完成后再推一条总结日志（不依赖 helper 自己推 task-log）
        ok = bool(result.get("success"))
        emoji = "✅" if ok else "❌"
        suffix = ""
        if not ok and result.get("error"):
            suffix = f"：{str(result['error'])[:200]}"
        self._broadcast(
            sess.owner_id,
            f"{emoji} 任务 {action} 完成 (task_id={task_id}){suffix}",
            "info" if ok else "error",
        )

        result["task_id"] = task_id
        return result

    def cancel_task(self, owner_id: int, task_id: str) -> bool:
        """主动取消一个排队/执行中的任务。

        实现策略：
        1. 尝试**从 helper 的 outbox 队列里把还没被取走的 task 抽出来**：
           如果 task 还排在队列里（helper 还没 poll-task 拿到），抽走就等于
           helper 不会执行；这是最彻底的取消。
        2. 往 result_queue 塞 ``_cancelled=True`` 消息：让阻塞在
           ``result_q.get(timeout)`` 的 dispatch 立即返回。

        限制：如果 task 已经被 helper poll 走、正在执行中（chromium 已启动），
        HTTP 长轮询无法中断 helper 进程那边的执行；helper 还会跑完然后上报
        结果，但 server 这边 _pending 已经 pop，结果会被丢弃。Web 用户立刻
        看到 cancelled=True，体验上等价"取消"。

        ``owner_id`` 参数用于校验权限（防止跨用户取消）：仅当 _pending 里
        记录的 owner 与传入的 owner_id 一致时才允许取消。
        """
        with self._lock:
            entry = self._pending.get(task_id)
            if not entry:
                return False
            _q, task_owner = entry
            if task_owner != int(owner_id or 0):
                # 越权请求：不属于这个 owner 的 task 不能被取消
                return False

        # Step 1: 从该 owner 所有 helper 的 outbox 里清掉这个 task_id（如果还没派出去）
        cancelled_in_outbox = False
        with self._lock:
            for sess in list(self._sessions.values()):
                if sess.owner_id != int(owner_id or 0):
                    continue
                # queue.Queue 没有删除接口，只能整个 drain 再放回
                kept: list = []
                while True:
                    try:
                        m = sess.outbox.get_nowait()
                    except queue.Empty:
                        break
                    if (
                        isinstance(m, dict)
                        and m.get("type") == "task"
                        and m.get("task_id") == task_id
                    ):
                        cancelled_in_outbox = True
                        continue  # 抛弃这条
                    kept.append(m)
                for m in kept:
                    try:
                        sess.outbox.put_nowait(m)
                    except queue.Full:
                        # outbox 满 → mark_dead；极少触发，记录一下
                        logger.warning(
                            "[helper:%s] cancel 后回填 outbox 失败",
                            sess.helper_id,
                        )
                        sess.mark_dead()
                        break

        # Step 2: 唤醒阻塞的 dispatch
        with self._lock:
            entry = self._pending.get(task_id)
            if not entry:
                # 任务在我们抢锁的间隙已经被 dispatch finally pop 了
                return False
            q, _ = entry
        try:
            q.put_nowait({
                "_cancelled": True,
                "success": False,
                "error": "用户取消",
                "_cancelled_in_outbox": cancelled_in_outbox,
            })
        except queue.Full:
            return False
        return True

    # ── helper 上报 ────────────────────────────────────────────

    def submit_result(self, helper_id: str, msg: dict) -> bool:
        """处理 POST /api/helper/task-result。"""
        sess = self.get(helper_id)
        if not sess:
            return False
        sess.touch()
        task_id = msg.get("task_id") or ""
        with self._lock:
            entry = self._pending.get(task_id)
        if not entry:
            logger.debug(
                "[helper:%s] 收到无主 task_result task_id=%s（可能已被取消或超时）",
                helper_id, task_id,
            )
            return False
        q, _owner = entry
        result = {k: v for k, v in msg.items() if k not in ("type", "task_id")}
        if "success" not in result:
            result["success"] = False
            result.setdefault("error", "Helper 未给出 success 字段")
        try:
            q.put_nowait(result)
            return True
        except queue.Full:
            logger.warning("[helper] task %s 结果队列已满，丢弃", task_id)
            return False

    def submit_log(self, helper_id: str, msg: dict) -> bool:
        """处理 POST /api/helper/task-log（可批量）。"""
        sess = self.get(helper_id)
        if not sess:
            return False
        sess.touch()

        entries = msg.get("logs")
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                self._sink_log(
                    sess.owner_id,
                    entry.get("message"),
                    entry.get("level"),
                )
        else:
            self._sink_log(sess.owner_id, msg.get("message"), msg.get("level"))
        return True

    def heartbeat(self, helper_id: str) -> bool:
        """处理 POST /api/helper/heartbeat。"""
        sess = self.get(helper_id)
        if not sess:
            return False
        sess.touch()
        return True

    def _sink_log(self, owner_id: int, message: Any, level: Any) -> None:
        try:
            self._log_sink(
                int(owner_id or 0),
                str(message or ""),
                str((level or "info")).lower(),
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("[helper] log_sink 异常: %s", e)

    def _broadcast(self, owner_id: int, message: str, level: str = "info") -> None:
        """server 端主动推一条日志到对应 owner 的 SSE 订阅者。

        与 ``submit_log`` 不同：``submit_log`` 是 helper 客户端 → server 的
        日志上报；``_broadcast`` 是 server 自己生成的状态日志（派单、超时、
        取消、版本警告等），不需要 helper 配合。
        """
        self._sink_log(owner_id, message, level)

    def broadcast_log(
        self, owner_id: int, message: str, level: str = "info",
    ) -> None:
        """外部模块（如 helper_routes）也能主动推 SSE 日志的公开入口。"""
        self._broadcast(owner_id, message, level)

    def set_log_sink(self, sink: Callable[[int, str, str], None]) -> None:
        """测试 / 自定义场景下覆写日志接收器。

        签名：``sink(owner_id, message, level)``。
        """
        self._log_sink = sink

    # ── 维护：把过期 session 清掉 ────────────────────────────

    def gc_expired(self) -> int:
        """物理清理已掉线 session，返回清理数。"""
        n = 0
        with self._lock:
            for hid in list(self._sessions.keys()):
                sess = self._sessions[hid]
                if not sess.alive:
                    self._sessions.pop(hid, None)
                    if self._token_to_helper.get(sess.token) == hid:
                        self._token_to_helper.pop(sess.token, None)
                    n += 1
        return n


# ── 实时日志广播 ─────────────────────────────────────────────────
# 用户在 Web 面板的「邮箱助手」页面订阅 SSE，helper 推上来的任务日志
# 通过本模块的 ``broadcast_helper_log`` 广播到对应 owner 的订阅者。
# 设计要点：
# - 每个 owner_id 各有一个广播桶（避免跨用户日志泄露）。
# - 订阅者拿到一个独立 queue.Queue；离开时主动 unsubscribe 让 GC 回收。
# - 单 owner 最多 16 个并发订阅者（实际上一个用户最多开几个标签）。

_log_subscribers: dict[int, list[queue.Queue]] = {}
_log_subscribers_lock = threading.Lock()
_MAX_SUBSCRIBERS_PER_OWNER = 16
_SUB_QUEUE_MAX = 256


def subscribe_logs(owner_id: int) -> queue.Queue:
    """订阅指定用户的 helper 日志流，返回独占的 queue。

    SSE 路由从该 queue.get 阻塞取消息；调用方在断开时**必须**
    调 ``unsubscribe_logs`` 释放，否则该 queue 会被持续 put 直到满。
    """
    q: queue.Queue = queue.Queue(maxsize=_SUB_QUEUE_MAX)
    with _log_subscribers_lock:
        bucket = _log_subscribers.setdefault(int(owner_id or 0), [])
        if len(bucket) >= _MAX_SUBSCRIBERS_PER_OWNER:
            # 单用户超过阈值 → 把最老的踢掉（最常见原因：旧 tab 没断干净）
            old = bucket.pop(0)
            try:
                old.put_nowait({"type": "_disconnect"})
            except queue.Full:
                pass
        bucket.append(q)
    return q


def unsubscribe_logs(owner_id: int, q: queue.Queue) -> None:
    with _log_subscribers_lock:
        bucket = _log_subscribers.get(int(owner_id or 0))
        if not bucket:
            return
        try:
            bucket.remove(q)
        except ValueError:
            pass
        if not bucket:
            _log_subscribers.pop(int(owner_id or 0), None)


def _default_log_sink(owner_id: int, message: str, level: str) -> None:
    """默认日志接收器：广播到对应 owner 的 SSE 订阅者。"""
    with _log_subscribers_lock:
        bucket = list(_log_subscribers.get(int(owner_id or 0)) or [])
    payload = {
        "type": "log",
        "message": message,
        "level": level,
        "ts": int(time.time()),
    }
    for q in bucket:
        try:
            q.put_nowait(payload)
        except queue.Full:
            pass


# ── 模块单例 ─────────────────────────────────────────────────────

registry = HelperRegistry()


__all__ = (
    "DEFAULT_TASK_TIMEOUT",
    "HEARTBEAT_DEAD_AFTER",
    "POLL_BLOCK_SECONDS",
    "MIN_HELPER_VERSION",
    "ALWAYS_ALLOWED_ACTIONS",
    "HelperRegistry",
    "HelperSession",
    "registry",
    "subscribe_logs",
    "unsubscribe_logs",
)
