package com.smtool.module.parse;

import java.net.InetAddress;

/**
 * 从链路层字节解析 Ethernet -> IPv4/IPv6 -> TCP。
 */
public class PacketParser {

    public static void parse(PcapPacket packet) {
        byte[] raw = packet.getRaw();
        if (raw == null || raw.length < 14) {
            return;
        }
        int linkType = packet.getLinkType();
        int offset;
        int etherType;
        if (linkType == 1) {
            // Ethernet II
            offset = 14;
            etherType = ((raw[12] & 0xff) << 8) | (raw[13] & 0xff);
            // handle 802.1Q VLAN tagging
            while (etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100) {
                if (raw.length < offset + 4) {
                    return;
                }
                etherType = ((raw[offset + 2] & 0xff) << 8) | (raw[offset + 3] & 0xff);
                offset += 4;
            }
        } else if (linkType == 101) {
            // LINKTYPE_RAW (Linux cooked capture)
            offset = 0;
            etherType = ((raw[0] & 0xff) << 8) | (raw[1] & 0xff);
        } else {
            // unsupported link type
            return;
        }

        if (etherType == 0x0800) {
            parseIPv4(packet, raw, offset);
        } else if (etherType == 0x86dd) {
            parseIPv6(packet, raw, offset);
        }
    }

    private static void parseIPv4(PcapPacket packet, byte[] raw, int offset) {
        if (raw.length < offset + 20) {
            return;
        }
        int versionIhl = raw[offset] & 0xff;
        int ihl = versionIhl & 0x0f;
        int headerLen = ihl * 4;
        int protocol = raw[offset + 9] & 0xff;
        packet.setSrcIp(ipToString(raw, offset + 12));
        packet.setDstIp(ipToString(raw, offset + 16));

        if (protocol == 6) {
            parseTcp(packet, raw, offset + headerLen);
        } else if (protocol == 17) {
            packet.setProtocol("udp");
        }
    }

    private static void parseIPv6(PcapPacket packet, byte[] raw, int offset) {
        if (raw.length < offset + 40) {
            return;
        }
        int nextHeader = raw[offset + 6] & 0xff;
        packet.setSrcIp(ip6ToString(raw, offset + 8));
        packet.setDstIp(ip6ToString(raw, offset + 24));

        // skip extension headers (simplified)
        int payloadOffset = offset + 40;
        while (isExtensionHeader(nextHeader)) {
            if (raw.length < payloadOffset + 8) {
                return;
            }
            nextHeader = raw[payloadOffset] & 0xff;
            int extLen = (raw[payloadOffset + 1] & 0xff) * 8 + 8;
            payloadOffset += extLen;
        }

        if (nextHeader == 6) {
            parseTcp(packet, raw, payloadOffset);
        } else if (nextHeader == 17) {
            packet.setProtocol("udp");
        }
    }

    private static boolean isExtensionHeader(int protocol) {
        return protocol == 0 || protocol == 43 || protocol == 44 || protocol == 60 || protocol == 135;
    }

    private static void parseTcp(PcapPacket packet, byte[] raw, int offset) {
        if (raw.length < offset + 20) {
            return;
        }
        int srcPort = ((raw[offset] & 0xff) << 8) | (raw[offset + 1] & 0xff);
        int dstPort = ((raw[offset + 2] & 0xff) << 8) | (raw[offset + 3] & 0xff);
        int dataOffset = ((raw[offset + 12] & 0xff) >> 4) * 4;
        packet.setSrcPort(srcPort);
        packet.setDstPort(dstPort);
        packet.setProtocol("tcp");
        if (raw.length > offset + dataOffset) {
            byte[] payload = new byte[raw.length - offset - dataOffset];
            System.arraycopy(raw, offset + dataOffset, payload, 0, payload.length);
            packet.setPayload(payload);
        } else {
            packet.setPayload(new byte[0]);
        }
    }

    private static String ipToString(byte[] raw, int offset) {
        try {
            byte[] addr = new byte[4];
            System.arraycopy(raw, offset, addr, 0, 4);
            return InetAddress.getByAddress(addr).getHostAddress();
        } catch (Exception e) {
            return "";
        }
    }

    private static String ip6ToString(byte[] raw, int offset) {
        try {
            byte[] addr = new byte[16];
            System.arraycopy(raw, offset, addr, 0, 16);
            return InetAddress.getByAddress(addr).getHostAddress();
        } catch (Exception e) {
            return "";
        }
    }
}
