#!/usr/bin/env python3
"""
生成一个最小 SSH 会话 pcap 文件，用于测试 SSH 流量包解析功能。
包含：TCP 三次握手、banner 交换、KEXINIT 交换、KEXDH_INIT / KEXDH_REPLY、NEWKEYS。
"""
from scapy.all import Ether, IP, TCP, Raw, wrpcap

client = ("10.12.54.201", 55234)
server = ("10.65.200.23", 22)
seq_c = 1000
seq_s = 2000
pkts = []

def pkt(src, dst, sport, dport, seq, ack, flags, payload=b"", ts=0):
    return Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)/Raw(load=payload)

# TCP 三次握手
pkts.append(pkt(client[0], server[0], client[1], server[1], seq_c, 0, "S"))
seq_c += 1
pkts.append(pkt(server[0], client[0], server[1], client[1], seq_s, seq_c, "SA"))
seq_s += 1
pkts.append(pkt(client[0], server[0], client[1], server[1], seq_c, seq_s, "A"))

def ssh_binary_packet(msg_code, payload):
    payload_full = bytes([msg_code]) + payload
    block_size = 8
    pad_len = block_size - ((len(payload_full) + 5) % block_size)
    if pad_len < 4:
        pad_len += block_size
    packet_length = len(payload_full) + 1 + pad_len
    return (
        packet_length.to_bytes(4, "big")
        + bytes([pad_len])
        + payload_full
        + bytes(pad_len)
    )

def name_list(names):
    s = ",".join(names).encode("ascii")
    return len(s).to_bytes(4, "big") + s

def string_field(data):
    return len(data).to_bytes(4, "big") + data

client_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
pkts.append(pkt(client[0], server[0], client[1], server[1], seq_c, seq_s, "PA", client_banner))
seq_c += len(client_banner)

server_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
pkts.append(pkt(server[0], client[0], server[1], client[1], seq_s, seq_c, "PA", server_banner))
seq_s += len(server_banner)

# 客户端 KEXINIT
client_kex_algs = b"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group16-sha512"
server_host_key_algs = b"ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512"
enc_algs = b"chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-ctr"
mac_algs = b"umac-64-etm@openssh.com,hmac-sha2-256"
comp_algs = b"none,zlib@openssh.com"
lang = b""
client_kex_payload = (
    bytes(16)  # cookie
    + name_list([client_kex_algs.decode()])
    + name_list([server_host_key_algs.decode()])
    + name_list([enc_algs.decode()])
    + name_list([enc_algs.decode()])
    + name_list([mac_algs.decode()])
    + name_list([mac_algs.decode()])
    + name_list([comp_algs.decode()])
    + name_list([comp_algs.decode()])
    + name_list([lang.decode()])
    + name_list([lang.decode()])
    + bytes([0])  # first_kex_packet_follows
    + (0).to_bytes(4, "big")  # reserved
)
client_kex = ssh_binary_packet(20, client_kex_payload)
pkts.append(pkt(client[0], server[0], client[1], server[1], seq_c, seq_s, "PA", client_kex))
seq_c += len(client_kex)

# 服务端 KEXINIT
server_kex_payload = (
    bytes(16)
    + name_list([client_kex_algs.decode()])
    + name_list([server_host_key_algs.decode()])
    + name_list([enc_algs.decode()])
    + name_list([enc_algs.decode()])
    + name_list([mac_algs.decode()])
    + name_list([mac_algs.decode()])
    + name_list([comp_algs.decode()])
    + name_list([comp_algs.decode()])
    + name_list([lang.decode()])
    + name_list([lang.decode()])
    + bytes([0])
    + (0).to_bytes(4, "big")
)
server_kex = ssh_binary_packet(20, server_kex_payload)
pkts.append(pkt(server[0], client[0], server[1], client[1], seq_s, seq_c, "PA", server_kex))
seq_s += len(server_kex)

# 客户端 KEXDH_INIT (curve25519 public key, 32 bytes)
client_ephemeral = bytes(range(32))
client_dh_init = ssh_binary_packet(30, string_field(client_ephemeral))
pkts.append(pkt(client[0], server[0], client[1], server[1], seq_c, seq_s, "PA", client_dh_init))
seq_c += len(client_dh_init)

# 服务端 KEXDH_REPLY
server_host_pub = bytes(range(32, 64))  # 模拟 host public key
server_ephemeral_pub = bytes(range(64, 96))  # 模拟 server public key
signature_blob = string_field(b"ssh-ed25519") + string_field(bytes(range(96, 160)))
signature = string_field(signature_blob)
server_dh_reply_payload = (
    string_field(server_host_pub)
    + string_field(server_ephemeral_pub)
    + signature
)
server_dh_reply = ssh_binary_packet(31, server_dh_reply_payload)
pkts.append(pkt(server[0], client[0], server[1], client[1], seq_s, seq_c, "PA", server_dh_reply))
seq_s += len(server_dh_reply)

# NEWKEYS
client_newkeys = ssh_binary_packet(21, b"")
server_newkeys = ssh_binary_packet(21, b"")
pkts.append(pkt(client[0], server[0], client[1], server[1], seq_c, seq_s, "PA", client_newkeys))
seq_c += len(client_newkeys)
pkts.append(pkt(server[0], client[0], server[1], client[1], seq_s, seq_c, "PA", server_newkeys))
seq_s += len(server_newkeys)

wrpcap("ssh_session_demo.pcap", pkts)
print("Generated ssh_session_demo.pcap with", len(pkts), "packets")
