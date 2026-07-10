#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 IPsec / ISAKMP 报文中批量提取证书并解析国密 SM2 X.509 字段。

思路（与你的 Java 后端一致）：
1. 先用 tshark 从 pcap 中导出 isakmp.cert.data（十六进制）。
2. 按 RFC 2408 Certificate Payload 结构切掉首字节的 Cert Encoding。
3. 用 asn1crypto 解析 X.509 DER，避免自己手撸 BER/DER。
4. 对国密 OID 维护映射表，解决 asn1crypto 默认不认识 SM2 曲线/签名算法的问题。

依赖：
    pip install asn1crypto
    tshark 需在 PATH 中（Wireshark 自带）。

用法：
    python extract_ipsec_certs.py ../15、客户端访问后台抓包ipsec.pcap
"""

import argparse
import base64
import binascii
import os
import subprocess
import sys
from pathlib import Path

from asn1crypto import x509

# 国密 OID 映射表（与 Java 后端 OidNames 保持一致）
OID_MAP = {
    # 公钥算法 / 曲线
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.2.156.10197.1.301": "sm2p256v1 (SM2 曲线)",
    # 签名算法
    "1.2.156.10197.1.501": "SM3withSM2",
    "1.2.156.10197.1.502": "SM2withSM3",
    "1.2.156.10197.1.503": "SM2withSHA1",
    "1.2.156.10197.1.504": "SM2withSHA256",
    "1.2.156.10197.1.505": "SM2withSHA384",
    "1.2.156.10197.1.506": "SM2withSHA512",
    # 杂凑/对称
    "1.2.156.10197.1.401": "SM3",
    "1.2.156.10197.1.104": "SM4",
}


def oid_name(oid: str) -> str:
    return OID_MAP.get(oid, oid)


def run_tshark(pcap_path: Path) -> list[str]:
    """调用 tshark 导出 isakmp.cert.data 十六进制字段。"""
    cmd = [
        "tshark",
        "-r", str(pcap_path),
        "-Y", "isakmp",
        "-T", "fields",
        "-e", "isakmp.cert.data",
    ]
    print(f"[tshark] {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
        )
    except FileNotFoundError:
        print("错误：未找到 tshark，请确保 Wireshark/tshark 已安装并在 PATH 中。", file=sys.stderr)
        sys.exit(1)

    if result.returncode != 0:
        print(f"tshark 退出码 {result.returncode}：{result.stderr.strip()}", file=sys.stderr)

    # 每行可能包含多个用逗号分隔的 cert data
    lines = []
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        for part in line.split(","):
            part = part.strip()
            if part:
                lines.append(part)
    return lines


def extract_der_from_cert_payload(body: bytes) -> tuple[bytes, int] | None:
    """
    按 RFC 2408 Certificate Payload 切出 DER。
    返回 (der_bytes, cert_encoding)，无法识别时返回 None。
    """
    if not body:
        return None
    # 国密私有载荷可能直接以 DER SEQUENCE (0x30) 开头
    if body[0] == 0x30:
        return body, 0x100
    encoding = body[0]
    if len(body) < 2:
        return None
    return body[1:], encoding


def parse_certificate(der: bytes, index: int, output_dir: Path) -> dict | None:
    """用 asn1crypto 解析 X.509 DER 并返回字段字典。"""
    try:
        cert = x509.Certificate.load(der)
    except Exception as e:
        print(f"  证书 {index}: 无法解析为 X.509: {e}")
        return None

    sig_oid = cert["signature_algorithm"]["algorithm"].native
    pk_alg = cert["tbs_certificate"]["subject_public_key_info"]["algorithm"]["algorithm"].native

    # 密钥用法
    key_usage = None
    for ext in cert["tbs_certificate"]["extensions"]:
        if ext["extn_id"].native == "key_usage":
            key_usage = ", ".join(ext["extn_value"].parsed.native)
            break

    result = {
        "index": index,
        "version": str(cert["tbs_certificate"]["version"].native),
        "serial_number": hex(cert.serial_number),
        "signature_algorithm": oid_name(sig_oid),
        "signature_oid": sig_oid,
        "public_key_algorithm": oid_name(pk_alg),
        "public_key_oid": pk_alg,
        "subject": cert.subject.native,
        "issuer": cert.issuer.native,
        "not_before": str(cert["tbs_certificate"]["validity"]["not_before"].native),
        "not_after": str(cert["tbs_certificate"]["validity"]["not_after"].native),
        "key_usage": key_usage,
        "der_length": len(der),
    }

    # 导出 DER / PEM
    der_path = output_dir / f"cert_{index:03d}.der"
    pem_path = output_dir / f"cert_{index:03d}.pem"
    der_path.write_bytes(der)
    pem_path.write_text(
        "-----BEGIN CERTIFICATE-----\n"
        + base64.encodebytes(der).decode("ascii")
        + "-----END CERTIFICATE-----\n"
    )
    result["der_file"] = str(der_path)
    result["pem_file"] = str(pem_path)
    return result


def print_certificate(cert: dict) -> None:
    print(f"\n===== 证书 #{cert['index']} =====")
    print(f"版本:        {cert['version']}")
    print(f"序列号:      {cert['serial_number']}")
    print(f"签名算法:    {cert['signature_algorithm']} ({cert['signature_oid']})")
    print(f"公钥算法:    {cert['public_key_algorithm']} ({cert['public_key_oid']})")
    print(f"使用者:      {cert['subject']}")
    print(f"颁发者:      {cert['issuer']}")
    print(f"有效期:      {cert['not_before']} ~ {cert['not_after']}")
    print(f"密钥用法:    {cert['key_usage']}")
    print(f"DER 长度:    {cert['der_length']}")
    print(f"导出文件:    {cert['der_file']}, {cert['pem_file']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="从 IPsec pcap 中提取并解析 ISAKMP 证书")
    parser.add_argument("pcap", help="pcap/pcapng 文件路径")
    parser.add_argument(
        "-o", "--output", default="extracted_certs",
        help="证书导出目录（默认：extracted_certs）"
    )
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"错误：文件不存在 {pcap_path}", file=sys.stderr)
        return 1

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    hex_lines = run_tshark(pcap_path)
    if not hex_lines:
        print("未从 tshark 输出中提取到 isakmp.cert.data，可能该 pcap 不含证书或 tshark 字段名不匹配。")
        return 0

    print(f"\n共获取 {len(hex_lines)} 个 Certificate Payload 候选。\n")

    parsed_count = 0
    for i, hex_data in enumerate(hex_lines):
        # tshark 某些版本输出为 "xx:yy:zz" 或连续十六进制
        hex_clean = hex_data.replace(":", "").replace(" ", "").strip()
        if not hex_clean:
            continue
        try:
            body = binascii.unhexlify(hex_clean)
        except binascii.Error as e:
            print(f"  候选 {i}: 十六进制解码失败: {e}")
            continue

        extracted = extract_der_from_cert_payload(body)
        if extracted is None:
            print(f"  候选 {i}: 无法按 RFC 2408 切出 DER（首字节 0x{body[0]:02x}）")
            continue

        der, encoding = extracted
        print(f"候选 {i}: Cert Encoding=0x{encoding:02x}, DER 长度={len(der)}")
        cert = parse_certificate(der, i, output_dir)
        if cert:
            print_certificate(cert)
            parsed_count += 1

    print(f"\n解析完成：共 {len(hex_lines)} 个候选，成功解析 {parsed_count} 张 X.509 证书。")
    print(f"证书导出目录：{output_dir.absolute()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
