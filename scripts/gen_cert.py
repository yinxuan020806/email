# -*- coding: utf-8 -*-
"""
生成自签 TLS 证书，用于在内网启用 HTTPS。

使用:
    python scripts/gen_cert.py
    # → 生成 data/server.key 和 data/server.crt（默认绑定 localhost + 127.0.0.1）

    python scripts/gen_cert.py --hosts 192.168.1.100,mail.local
    # → 增加额外的 SAN 条目

启动:
    $env:EMAIL_WEB_SSL_KEY  = "data/server.key"
    $env:EMAIL_WEB_SSL_CERT = "data/server.crt"
    python web_app.py
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def parse_san(hosts: list[str]) -> list[x509.GeneralName]:
    """把 host 字符串列表转成 SAN 条目（自动区分 IP / DNS）。"""
    items: list[x509.GeneralName] = []
    seen: set[str] = set()
    for h in hosts:
        h = h.strip()
        if not h or h in seen:
            continue
        seen.add(h)
        try:
            items.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            items.append(x509.DNSName(h))
    return items


def main() -> int:
    parser = argparse.ArgumentParser(description="生成自签 TLS 证书")
    parser.add_argument(
        "--hosts",
        default="localhost,127.0.0.1,::1",
        help="逗号分隔的主机/IP（写入 SAN）。默认: localhost,127.0.0.1,::1",
    )
    parser.add_argument(
        "--out-dir",
        default="data",
        help="输出目录（默认 data/）",
    )
    parser.add_argument(
        "--days", type=int, default=825,
        help="有效期天数（默认 825，超过 825 天浏览器会提示不安全）",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / "server.key"
    crt_path = out_dir / "server.crt"

    if key_path.exists() or crt_path.exists():
        print(f"⚠️  {key_path} 或 {crt_path} 已存在；如要重新生成请先删除。")
        return 1

    print("生成 RSA 2048 私钥...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    san_items = parse_san(args.hosts.split(","))
    print(f"SAN: {[s.value if hasattr(s, 'value') else str(s) for s in san_items]}")

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Email Web Self-Signed"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EmailWeb"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=args.days))
        .add_extension(x509.SubjectAlternativeName(san_items), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass

    print(f"✓ 私钥: {key_path}")
    print(f"✓ 证书: {crt_path}")
    print()
    print("启动 HTTPS 服务:")
    print(f'  $env:EMAIL_WEB_SSL_KEY  = "{key_path.as_posix()}"')
    print(f'  $env:EMAIL_WEB_SSL_CERT = "{crt_path.as_posix()}"')
    print( "  python web_app.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
