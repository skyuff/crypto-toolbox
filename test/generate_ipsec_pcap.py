#!/usr/bin/env python3
"""
生成一个最小 IPSEC / IKEv2 会话 pcap 文件，用于测试 IPSEC 流量包解析功能。
包含：IKE_SA_INIT 请求/响应、IKE_AUTH 请求/响应，使用国密 SM4/SM3/SM2 算法。
"""
from scapy.all import Ether, IP, UDP, Raw, wrpcap

client = ("10.12.54.201", 500)
server = ("10.65.200.23", 500)
pkts = []


def u8(v):
    return bytes([v & 0xff])


def u16(v):
    return v.to_bytes(2, "big")


def u32(v):
    return v.to_bytes(4, "big")


def pad4(data):
    return data + b"\x00" * ((4 - len(data) % 4) % 4)


def isakmp_header(initiator_spi, responder_spi, next_payload, version,
                  exchange_type, flags, message_id, length):
    return (
        initiator_spi
        + responder_spi
        + u8(next_payload)
        + u8(version)
        + u8(exchange_type)
        + u8(flags)
        + u32(message_id)
        + u32(length)
    )


def make_payload(ptype, data, critical=True):
    """返回 (ptype, bytes)，其中 bytes 首字节为 next-payload 占位符（稍后链接时填充）。"""
    body = pad4(data)
    length = 4 + len(body)
    flags = 0x80 if critical else 0x00
    return ptype, u8(0) + u8(flags) + u16(length) + body


def link_payloads(payloads):
    """根据 payloads 列表自动填充 next-payload 链，返回 (first_ptype, concatenated_bytes)。"""
    ptypes = [p[0] for p in payloads]
    chunks = []
    for i, (ptype, raw) in enumerate(payloads):
        next_ptype = ptypes[i + 1] if i + 1 < len(ptypes) else 0
        chunks.append(u8(next_ptype) + raw[1:])
    return (ptypes[0] if ptypes else 0), b"".join(chunks)


# IKEv2 变换类型编号
ENCR_AES_CBC = 12
ENCR_SM4_CBC = 20
PRF_SM3 = 8
AUTH_SM3_96 = 8
DH_SM2_256 = 31


def proposal(last, protocol_id, spi, transforms):
    """
    IKEv2 Proposal 子结构：
    last(1) + reserved(1) + length(2) + proposal#(1) + protocol(1) + spiSize(1) + transformCount(1)
    + [SPI] + Transform...
    """
    body = u8(1) + u8(protocol_id) + u8(len(spi)) + u8(len(transforms)) + spi
    for i, (t_type, t_id) in enumerate(transforms):
        next_t = 0 if i == len(transforms) - 1 else 3
        t_body = u8(t_type) + u8(0) + u16(t_id)
        t_len = 4 + len(t_body)
        body += u8(next_t) + u8(0) + u16(t_len) + t_body
    prop_len = 4 + len(body)
    return u8(last) + u8(0) + u16(prop_len) + body


def build_sa_payload(transforms):
    sa_data = proposal(0, 1, b"", transforms)
    return make_payload(33, sa_data)


def build_ke_payload(group, key_data):
    return make_payload(34, u16(group) + pad4(key_data))


def build_nonce_payload(nonce):
    return make_payload(40, nonce)


def build_notify_payload(notify_type, data=b""):
    body = u8(1) + u8(0) + u16(notify_type) + data
    return make_payload(41, body)


def build_id_payload(ptype, id_type, identity):
    body = u8(id_type) + b"\x00\x00\x00" + pad4(identity)
    return make_payload(ptype, body)


def build_auth_payload(method, auth_data):
    body = u8(method) + b"\x00\x00\x00" + pad4(auth_data)
    return make_payload(39, body)


def build_cert_payload(encoding, cert_data):
    body = u8(encoding) + cert_data
    return make_payload(37, body)


def build_certreq_payload(encoding, data=b""):
    body = u8(encoding) + data
    return make_payload(38, body)


def assemble_message(initiator_spi, responder_spi, exchange_type, flags,
                     message_id, payload_chain):
    next_payload, body = link_payloads(payload_chain)
    length = 28 + len(body)
    return isakmp_header(initiator_spi, responder_spi, next_payload, 0x20,
                         exchange_type, flags, message_id, length) + body


def add_packet(src_ip, dst_ip, sport, dport, isakmp_bytes):
    pkts.append(Ether() / IP(src=src_ip, dst=dst_ip) /
                UDP(sport=sport, dport=dport) / Raw(load=isakmp_bytes))


# 固定 SPI
initiator_spi = b"\x11" * 8
responder_spi = b"\x22" * 8

# IKE_SA_INIT 请求
sa_init_req_transforms = [
    (1, ENCR_AES_CBC),
    (1, ENCR_SM4_CBC),
    (2, PRF_SM3),
    (3, AUTH_SM3_96),
    (4, DH_SM2_256),
]
ike_sa_init_req = assemble_message(
    initiator_spi, b"\x00" * 8, 34, 0x08, 0,
    [
        build_sa_payload(sa_init_req_transforms),
        build_ke_payload(DH_SM2_256, bytes(range(32))),
        build_nonce_payload(bytes(range(16, 48))),
        build_notify_payload(16385, b"\x00" * 8),  # IKE_SA_ESTABLISHED
    ]
)
add_packet(client[0], server[0], client[1], server[1], ike_sa_init_req)

# IKE_SA_INIT 响应
sa_init_resp_transforms = [
    (1, ENCR_SM4_CBC),
    (2, PRF_SM3),
    (3, AUTH_SM3_96),
    (4, DH_SM2_256),
]
ike_sa_init_resp = assemble_message(
    initiator_spi, responder_spi, 34, 0x20, 0,
    [
        build_sa_payload(sa_init_resp_transforms),
        build_ke_payload(DH_SM2_256, bytes(range(32, 64))),
        build_nonce_payload(bytes(range(48, 80))),
        build_notify_payload(16385, b"\x00" * 8),
    ]
)
add_packet(server[0], client[0], server[1], client[1], ike_sa_init_resp)

# IKE_AUTH 请求：IDi -> AUTH -> CERTREQ -> NOTIFY
ike_auth_req = assemble_message(
    initiator_spi, responder_spi, 35, 0x08, 1,
    [
        build_id_payload(35, 2, b"client.example.com"),
        build_auth_payload(1, bytes(range(80, 112))),
        build_certreq_payload(4, b"\x00" * 20),
        build_notify_payload(16385, b"\x00" * 8),
    ]
)
add_packet(client[0], server[0], client[1], server[1], ike_auth_req)

# IKE_AUTH 响应：IDr -> AUTH -> CERT
ike_auth_resp = assemble_message(
    initiator_spi, responder_spi, 35, 0x20, 1,
    [
        build_id_payload(36, 2, b"server.example.com"),
        build_auth_payload(1, bytes(range(112, 144))),
        build_cert_payload(4, bytes(range(144, 208))),
    ]
)
add_packet(server[0], client[0], server[1], client[1], ike_auth_resp)

wrpcap("ipsec_session_demo.pcap", pkts)
print("Generated ipsec_session_demo.pcap with", len(pkts), "packets")
