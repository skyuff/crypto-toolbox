from scapy.all import Ether, IP, TCP, wrpcap, Raw

# TLS ClientHello
client_hello = bytes.fromhex(
    '1603010037'
    '01000033'
    '0303'
    + '00' * 32
    + '00'
    + '000a'
    + '1301130200c6130300ff'
    + '01'
    + '00'
    + '0000'
)

# TLS ServerHello（record 负载 44B：handshake 头 4B + body 40B）
server_hello = bytes.fromhex(
    '160301002c'
    '02000028'
    '0303'
    + '11' * 32
    + '00'
    + 'e013'
    + '00'
    + '0000'
)

# Build packets with full TCP handshake and TLS exchange
client_ip = '10.12.54.201'
server_ip = '10.65.200.23'
client_port = 54321
server_port = 443

syn = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags='S', seq=100)
synack = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags='SA', seq=200, ack=101)
ack = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags='A', seq=101, ack=201)
client_pkt = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags='PA', seq=101, ack=201)/Raw(client_hello)
server_pkt = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags='PA', seq=201, ack=101+len(client_hello))/Raw(server_hello)

wrpcap('test/tls_session_demo.pcap', [syn, synack, ack, client_pkt, server_pkt])
print('Generated test/tls_session_demo.pcap')
