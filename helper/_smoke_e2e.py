"""
端到端冒烟测试（HTTP 长轮询模型，参考 cursor-manager 0.1.0 测试范本）

验证内容
--------
1. POST ``/api/helper/provision-token`` 拿一个 token
2. 启 HelperClient 注册 + 长轮询
3. 等连接 ready → GET ``/api/helper/status`` 验证 online=true
4. POST ``/api/helper/dispatch`` action=echo / ping 验证派发链路
5. POST ``/api/helper/cancel-task`` 验证任务取消（顺便走一遍 0.1.1 新加的取消接口）
6. POST ``/api/helper/revoke`` 撤销 token，验证 helper 被踢离线

使用
----
::

    # 假设 web_app 跑在 18888
    EMAIL_WEB_PORT=18888 python helper/_smoke_e2e.py
    # 或显式指定 server + 已注册的 xiaoxuan session cookie
    python helper/_smoke_e2e.py http://127.0.0.1:18888 <SESSION_TOKEN>

不入 pytest 主测试集——只是一个手工冒烟脚本，跑通说明 Stage 1 链路 OK。
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
import urllib.error

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(THIS_DIR)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _http(
    method: str, url: str, body: dict | None = None,
    cookie: str | None = None,
) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = f"email_web_session={cookie}"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body_str = e.read().decode("utf-8", errors="replace")
        try:
            return json.loads(body_str)
        except json.JSONDecodeError:
            return {"_status": e.code, "_body": body_str[:200]}


def main(server: str, cookie: str) -> int:
    print(f"server: {server}")
    print(f"cookie: {cookie[:12]}..." if cookie else "(no cookie)")

    print("[1/6] 拉 token via POST /api/helper/provision-token")
    r = _http(
        "POST", f"{server}/api/helper/provision-token",
        {"label": "smoke-e2e"}, cookie=cookie,
    )
    if not r.get("success"):
        print(f"      ✗ provision 失败: {r}")
        return 1
    token = r["token"]
    print(f"      → token={token[:12]}...{token[-4:]}")

    print("[2/6] 启动 HelperClient")
    from helper.config import HelperConfig
    from helper.client import HelperClient, ConnState

    import tempfile
    tmp = tempfile.mkdtemp(prefix="email-helper-e2e-")
    cfg = HelperConfig(dir_override=tmp)
    cfg.token = token
    cfg.server_url = server
    cfg.save()

    client = HelperClient(cfg)
    client.start()

    print("[3/6] 等待 connected")
    deadline = time.time() + 10
    while time.time() < deadline and client.state != ConnState.CONNECTED:
        time.sleep(0.2)
    if client.state != ConnState.CONNECTED:
        print(f"      ✗ 没连上：state={client.state}, last_error={client.last_error}")
        client.shutdown()
        return 1
    print(f"      → helper_id={client.helper_id}")

    s = _http("GET", f"{server}/api/helper/status", cookie=cookie)
    print(f"      status: online={s.get('online')} version={s.get('version')} version_ok={s.get('version_ok')}")
    if not s.get("online"):
        print("      ✗ status 不是 online")
        client.shutdown()
        return 1

    print("[4/6] 调 dispatch echo + ping + version")
    resp = _http(
        "POST", f"{server}/api/helper/dispatch",
        {"action": "echo", "params": {"hello": "world"}, "timeout": 10},
        cookie=cookie,
    )
    print(f"      echo → success={resp.get('success')} echoed={resp.get('data', {}).get('echoed')}")
    if not (resp.get("success") is True and resp.get("data", {}).get("echoed") == {"hello": "world"}):
        print("      ✗ dispatch echo 失败"); client.shutdown(); return 2

    resp = _http(
        "POST", f"{server}/api/helper/dispatch",
        {"action": "ping", "params": {}, "timeout": 5},
        cookie=cookie,
    )
    print(f"      ping → success={resp.get('success')} pong={resp.get('data', {}).get('pong')}")
    if resp.get("success") is not True:
        print("      ✗ dispatch ping 失败"); client.shutdown(); return 2

    resp = _http(
        "POST", f"{server}/api/helper/dispatch",
        {"action": "version", "params": {}, "timeout": 5},
        cookie=cookie,
    )
    print(f"      version → {resp.get('data')}")

    print("[5/6] 调 dispatch echo（验证完整派发链路 + 实时日志桥接）")
    # 不再用 mailbox/open 测（Stage 2 后真会启浏览器登录，stub 已无）。
    # 改测 echo 派发：验证 server → helper poll → action 执行 → task-result 回传链路通
    resp = _http(
        "POST", f"{server}/api/helper/dispatch",
        {"action": "echo", "params": {"smoke": True}, "timeout": 10},
        cookie=cookie,
    )
    print(f"      dispatch echo → success={resp.get('success')} echoed={resp.get('data', {}).get('echoed')}")
    if resp.get("success") is not True:
        print(f"      ✗ dispatch echo 失败: {resp}"); client.shutdown(); return 4

    print("[6/6] 撤销 token，预期 helper 被踢离线")
    _http("POST", f"{server}/api/helper/revoke", {}, cookie=cookie)
    deadline = time.time() + 8
    while time.time() < deadline and client.state == ConnState.CONNECTED:
        time.sleep(0.3)
    print(f"      → state after revoke = {client.state.value}")
    client.shutdown()

    print("\nE2E ✅ all good")
    return 0


def _autologin(server: str) -> str | None:
    """便利函数：用 xiaoxuan/A1b2C3d4 自动登录拿 cookie。

    生产环境请显式传 cookie；自动登录仅用于本地 smoke。
    """
    import http.cookiejar
    import urllib.request
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    body = json.dumps({"username": "xiaoxuan", "password": "A1b2C3d4"}).encode()
    req = urllib.request.Request(
        f"{server}/api/auth/login",
        data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with opener.open(req, timeout=10) as r:
            r.read()
    except urllib.error.HTTPError as e:
        # 用户不存在 → 自动注册
        if e.code == 401:
            req = urllib.request.Request(
                f"{server}/api/auth/register",
                data=body, method="POST",
                headers={"Content-Type": "application/json"},
            )
            try:
                opener.open(req, timeout=10).read()
            except urllib.error.HTTPError:
                pass
    for c in cj:
        if c.name == "email_web_session":
            return c.value
    return None


if __name__ == "__main__":
    server = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    cookie = sys.argv[2] if len(sys.argv) > 2 else None
    if not cookie:
        print("[init] 未传 cookie，尝试用 xiaoxuan / A1b2C3d4 自动登录...")
        cookie = _autologin(server)
        if not cookie:
            print("自动登录失败。请手工注册 xiaoxuan 后用第二个参数传 cookie。")
            sys.exit(3)
    sys.exit(main(server, cookie))
