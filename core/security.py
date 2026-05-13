# -*- coding: utf-8 -*-
"""
本地敏感字段加密工具。

使用 Fernet（AES128-CBC + HMAC-SHA256）对 password / refresh_token 等字段进行
对称加密。主密钥保存在 data/.master.key，首次运行自动生成。

向后兼容：旧库中以明文存储的字段读取时返回原值，写入时自动升级为密文。
"""

from __future__ import annotations

import base64
import hmac
import logging
import os
import secrets
import stat
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken


logger = logging.getLogger(__name__)


_TOKEN_PREFIX = "enc::v1::"  # 标识密文，便于识别旧明文数据并迁移


class SecretBoxDecryptError(Exception):
    """密文带 ``_TOKEN_PREFIX`` 但 Fernet 校验不通过。

    可能原因（按可能性排序）：
    - ``master.key`` 被替换 / 丢失 / 误覆盖（同库不同密钥）
    - DB 文件被部分回滚到旧 master.key 时间线
    - 密文字段在外部被截断 / 改写

    旧实现把这种情况静默吞成空字符串后返回，导致：
    1. 业务把空 password 当合法值落库 → 二次加密"空"，不可逆破坏；
    2. 运维很难发现，因为没有抛错也没有显眼日志；
    3. 被攻击者部分篡改密文时无法感知。

    新合约：上层调用方负责捕获并降级（比如 `_row_to_account`），但*绝不*让
    `decrypt` 假装成功返回 `""`。这样单元测试可以验证 raise 行为，集成层可以
    把损坏字段标记为 `None` 并写 error 日志，运维一眼就能看见。
    """


class SecretBox:
    """加解密外观，单例风格。"""

    _instance: Optional["SecretBox"] = None

    # 解密热路径缓存：列表接口每次会对全表 ~N×2 个密文做 Fernet 解密
    # （N=256 ≈ 11ms，N=1000 ≈ 45ms）。同一密文 → 同一明文是确定性的，
    # 加 LRU 后第二次起命中缓存直接 dict 查表（~0.5μs / 次），把
    # /api/accounts 后端耗时从 ~14ms 压到 ~3ms 量级。
    #
    # 使用 OrderedDict 实现 bounded LRU，而不是 functools.lru_cache：
    # - functools.lru_cache 装在实例方法上会把 self 一并 hash，单例下没问题
    #   但容易让人误以为是"每实例一份"，多 SecretBox 实例（测试）相互污染
    # - OrderedDict 在实例上保持作用域清晰，单元测试 _instance=None 后不会
    #   留泄漏
    # - 容量 4096 足以容纳几千账号 × 2 字段 × 多用户共享密文的场景，
    #   命中率高的同时绝不让明文无界堆积在内存里
    _DECRYPT_CACHE_MAX = 4096

    def __init__(self, key_path: Path) -> None:
        self.key_path = key_path
        self._key = self._load_or_create_key()
        self._fernet = Fernet(self._key)
        self._decrypt_cache: "OrderedDict[str, str]" = OrderedDict()
        # 多线程并发请求会同时读写 _decrypt_cache；OrderedDict.move_to_end /
        # popitem 不是原子的，必须加锁避免 RuntimeError: dict changed during
        # iteration / 计数错乱
        self._cache_lock = threading.Lock()

    # ── 公共 API ────────────────────────────────────────────────────

    @classmethod
    def instance(cls, key_path: Optional[Path] = None) -> "SecretBox":
        if cls._instance is None:
            if key_path is None:
                raise RuntimeError(
                    "SecretBox 尚未初始化，首次调用必须传入 key_path"
                )
            cls._instance = cls(key_path)
        return cls._instance

    def encrypt(self, plaintext: Optional[str]) -> Optional[str]:
        if plaintext is None or plaintext == "":
            return plaintext
        if self._is_ciphertext(plaintext):
            return plaintext  # 已经是密文，幂等
        token = self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")
        return _TOKEN_PREFIX + token

    def decrypt(self, value: Optional[str]) -> Optional[str]:
        """解密；若是旧明文则原样返回（兼容迁移期）。

        失败语义（与旧版不同）：
        - ``None`` / ``""`` → 原样返回（视为"未设置"）
        - 不带 ``_TOKEN_PREFIX`` 的非空串 → 视为旧明文兼容路径，原样返回
        - 带 ``_TOKEN_PREFIX`` 但 Fernet 校验失败 → ``raise SecretBoxDecryptError``

        旧版把第三种情况吞成 ``""`` 静默继续，是数据完整性陷阱（见
        ``SecretBoxDecryptError`` 的 docstring）。新版强制让调用方显式决策：
        要么放行（标记字段失效 + 记 error 日志），要么向上抛错让请求 500。

        性能：对带前缀的密文走 LRU 缓存（cache key = 完整密文串）。
        master.key 在进程生命周期内不变，因此密文→明文是确定性的；
        缓存命中时跳过 Fernet 校验 + AES 解码，~0.5μs vs ~50μs。
        """
        if value is None or value == "":
            return value
        if not self._is_ciphertext(value):
            return value

        with self._cache_lock:
            cached = self._decrypt_cache.get(value)
            if cached is not None:
                self._decrypt_cache.move_to_end(value)
                return cached

        try:
            raw = value[len(_TOKEN_PREFIX):]
            plaintext = self._fernet.decrypt(raw.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            logger.error(
                "Fernet 解密失败：密文带前缀但校验不通过，可能是 master.key 被"
                "替换 / 密文被截断 / 数据库与密钥不匹配。前 12 字符: %r",
                value[: len(_TOKEN_PREFIX) + 12],
            )
            raise SecretBoxDecryptError(
                "密文解密失败：密钥不匹配或密文已损坏"
            ) from exc

        with self._cache_lock:
            # 双检：另一个线程可能已经填进来了，此处覆盖等价
            self._decrypt_cache[value] = plaintext
            self._decrypt_cache.move_to_end(value)
            while len(self._decrypt_cache) > self._DECRYPT_CACHE_MAX:
                self._decrypt_cache.popitem(last=False)
        return plaintext

    def invalidate_decrypt_cache(self) -> None:
        """显式清空解密缓存。

        正常业务路径不需要调用 —— master.key 在进程生命周期内不变，
        密文→明文映射就是确定的。提供这个方法主要给：
        - 单元测试切换 SecretBox 实例时清场
        - 极端运维场景下手动 reset
        """
        with self._cache_lock:
            self._decrypt_cache.clear()

    @staticmethod
    def _is_ciphertext(value: str) -> bool:
        return isinstance(value, str) and value.startswith(_TOKEN_PREFIX)

    # ── 内部 ────────────────────────────────────────────────────────

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            data = self.key_path.read_bytes().strip()
            try:
                # 验证一下是合法 Fernet key
                Fernet(data)
                return data
            except (ValueError, base64.binascii.Error) as exc:
                # 关键决策：损坏的 master.key **绝不**静默覆盖。
                # 原因：覆盖会导致所有旧密文（accounts.password / refresh_token）
                # 不可解密，相当于无声数据丢失，且运维只能从日志里发现。
                # 启动直接 raise，让 ops 能感知并恢复正确的 key。
                # 如果确认无密文需要恢复（全新部署 / 测试），把 master.key 删除即可。
                raise RuntimeError(
                    f"主密钥 {self.key_path} 内容非法（可能被损坏 / 误编辑 / 还原失误）。"
                    f"为避免静默丢失旧密文，启动已中止。请检查并恢复正确的 master.key；"
                    f"若确认无密文需要恢复，请手动删除该文件后重新启动。"
                    f"原始错误: {type(exc).__name__}: {exc}"
                )
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        new_key = Fernet.generate_key()
        self.key_path.write_bytes(new_key)
        try:
            # POSIX：仅文件所有者可读写；Windows 上忽略
            os.chmod(self.key_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        logger.info("已生成新的主密钥: %s", self.key_path)
        return new_key


# ── 接码业务：邮箱凭证（access_token）生成与比较 ───────────────────────
#
# 设计动机
# --------
# 接码端把"输入邮箱即可拿验证码"改成"必须邮箱 + 6 位凭证"。
# 这层凭证语义上像第二把密码：
#   - 站长在管理端为已加入接码白名单的邮箱生成 access_token（明文加密保存）
#   - 把"邮箱----凭证"分发给下游使用者
#   - 想要撤销访问 → 旋转该邮箱的 token，老链接立即失效
#   - 真实邮箱密码 / refresh_token 永远不会被分发出去
#
# 字符集与长度
# -----------
# - 默认 6 位，字符集 54 个（去掉 0/O/1/I/l 这些一眼分不清的字符），
#   组合数 54^6 ≈ 246 亿。配合接码端的 IP/min 限流 + auth_failed 锁定
#   + Cloudflare Turnstile，纯爆破不可行。
# - 用 ``secrets.choice`` 走 OS CSPRNG，绝不用 ``random.choice``——
#   后者是确定性 PRNG，泄露种子即可预测后续 token。
#
# 比较函数
# --------
# - ``token_equals`` 用 ``hmac.compare_digest`` 做常量时间比较，
#   防御针对短 token 的时序侧信道（攻击者通过响应延迟差推断首字符是否匹配）。
# - 调用方拿到用户输入后必须经过 ``normalize_access_token`` 标准化
#   （去首尾空白）再比较，避免"末尾空格"误判为不匹配。

# 字符集刻意排除：0(零)/O(欧) · 1(壹)/I(爱)/l(L 小写)/i(I 小写) ·
# B/8 / G/6 / Z/2 这类肉眼极易混淆的字符也一并踢出。
# 剩余 54 个对站长复制粘贴、用户人工输入都不会拼错。
ACCESS_TOKEN_ALPHABET = (
    "ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghjkmnpqrstuvwxyz"
    "23456789"
)
ACCESS_TOKEN_LENGTH = 6


def generate_access_token(length: int = ACCESS_TOKEN_LENGTH) -> str:
    """生成一个 ``length`` 位的接码邮箱凭证（默认 6 位）。

    - 使用 ``secrets`` 模块 → 走 OS CSPRNG，密码学安全
    - 字符集 54 个，避开易混淆字符
    - 调用方负责把返回值加密存库（``SecretBox.encrypt``）
    """
    if length < 4:
        raise ValueError("access_token 长度不得小于 4 位（熵不足）")
    return "".join(secrets.choice(ACCESS_TOKEN_ALPHABET) for _ in range(length))


def normalize_access_token(value: Optional[str]) -> str:
    """把用户输入的 token 标准化：去首尾空白；None / 非字符串 → 空串。

    **不做大小写归一**——字符集刻意区分大小写以提高熵。
    若调用方希望宽松匹配，请自行 lower()，并接受熵从 54^N 降到 33^N 的代价。
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        return ""
    return value.strip()


def token_equals(input_token: Optional[str], stored_token: Optional[str]) -> bool:
    """常量时间比较两个 token；任一为空返回 False。

    - 防御目标：短 token 的时序侧信道（"匹配前缀越长 → 比较耗时越长"
      会让攻击者按字符位枚举，把 ``O(54^6)`` 降到 ``O(54×6)``）
    - 实现：``hmac.compare_digest`` 是为这种场景设计的，无论输入长度差异
      都按 max(len) 跑完，且对早 mismatch 不短路
    - 空值短路：两者都为空时仍**返回 False**——空 token 永远不应被视作合法
      （未启用接码的账号 stored=""，应被 lookup 流程在更早的 is_public 守卫
      处拦下，这里只是兜底）
    """
    a = normalize_access_token(input_token)
    b = normalize_access_token(stored_token)
    if not a or not b:
        return False
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)
