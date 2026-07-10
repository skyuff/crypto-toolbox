package com.smtool.module.parse;

import java.net.InetAddress;

/**
 * 通用链路层/网络层偏移计算工具。
 * <p>
 * 统一处理 Ethernet、RAW、Linux cooked capture v1/v2 等链路类型，
 * 并正确计算 IPv4/IPv6 到传输层/载荷协议的偏移，供 PacketParser、TcpReassemblyService、PcapngReader 复用。
 */
public class PacketOffsetUtil {

    /** Ethernet II */
    public static final int LINKTYPE_ETHERNET = 1;
    /** Raw IP */
    public static final int LINKTYPE_RAW = 101;
    /** Linux cooked capture */
    public static final int LINKTYPE_LINUX_SLL = 113;
    /** Linux cooked capture v2 */
    public static final int LINKTYPE_LINUX_SLL2 = 228;
    /** BSD loopback / NULL */
    public static final int LINKTYPE_NULL = 0;
    /** PPP */
    public static final int LINKTYPE_PPP = 9;
    /** IEEE 802.11 wireless */
    public static final int LINKTYPE_IEEE802_11 = 105;

    /** IPv4 */
    public static final int ETHERTYPE_IPV4 = 0x0800;
    /** IPv6 */
    public static final int ETHERTYPE_IPV6 = 0x86dd;

    /** 802.1Q VLAN */
    private static final int ETHERTYPE_VLAN = 0x8100;
    /** 802.1ad Q-in-Q */
    private static final int ETHERTYPE_VLAN_QINQ = 0x88a8;
    /** 802.1QinQ */
    private static final int ETHERTYPE_VLAN_9100 = 0x9100;

    public static class Result {
        /** 是否成功识别 */
        public final boolean supported;
        /** 不支持时的原因 */
        public final String unsupportedReason;
        /** 链路类型 */
        public final int linkType;
        /** IP 头起始偏移 */
        public final int networkOffset;
        /** 传输层/载荷协议头起始偏移（ESP/AH/ICMP 等同样适用） */
        public final int transportOffset;
        /** 链路层之上的协议类型：0x0800(IPv4) 或 0x86dd(IPv6) */
        public final int etherType;
        /** IP 协议号：6/17/50/51/1/58 等，-1 表示未知 */
        public final int ipProtocol;
        /** 源 IP 字符串 */
        public final String srcIp;
        /** 目的 IP 字符串 */
        public final String dstIp;

        private Result(boolean supported, String unsupportedReason, int linkType, int networkOffset,
                       int transportOffset, int etherType, int ipProtocol, String srcIp, String dstIp) {
            this.supported = supported;
            this.unsupportedReason = unsupportedReason;
            this.linkType = linkType;
            this.networkOffset = networkOffset;
            this.transportOffset = transportOffset;
            this.etherType = etherType;
            this.ipProtocol = ipProtocol;
            this.srcIp = srcIp;
            this.dstIp = dstIp;
        }

        public static Result unsupported(int linkType, String reason) {
            return new Result(false, reason, linkType, -1, -1, -1, -1, null, null);
        }

        public static Result ok(int linkType, int networkOffset, int transportOffset, int etherType,
                                int ipProtocol, String srcIp, String dstIp) {
            return new Result(true, null, linkType, networkOffset, transportOffset, etherType, ipProtocol, srcIp, dstIp);
        }
    }

    /**
     * 解析原始链路层数据包，返回网络层与传输层偏移信息。
     */
    public static Result parse(byte[] raw, int linkType) {
        if (raw == null) {
            return Result.unsupported(linkType, "raw data is null");
        }

        int offset;
        int etherType;
        switch (linkType) {
            case LINKTYPE_ETHERNET -> {
                if (raw.length < 14) {
                    return Result.unsupported(linkType, "Ethernet frame too short");
                }
                offset = 14;
                etherType = readU16(raw, 12);
                while (etherType == ETHERTYPE_VLAN || etherType == ETHERTYPE_VLAN_QINQ || etherType == ETHERTYPE_VLAN_9100) {
                    if (raw.length < offset + 4) {
                        return Result.unsupported(linkType, "VLAN tag truncated");
                    }
                    etherType = readU16(raw, offset + 2);
                    offset += 4;
                }
            }
            case LINKTYPE_RAW -> {
                // LINKTYPE_RAW: packet starts directly with IPv4/IPv6 header (no ether type)
                if (raw.length < 1) {
                    return Result.unsupported(linkType, "RAW frame too short");
                }
                offset = 0;
                int version = (raw[0] >> 4) & 0x0f;
                etherType = switch (version) {
                    case 4 -> ETHERTYPE_IPV4;
                    case 6 -> ETHERTYPE_IPV6;
                    default -> -1;
                };
                if (etherType == -1) {
                    return Result.unsupported(linkType, "RAW frame unknown IP version: " + version);
                }
            }
            case LINKTYPE_LINUX_SLL -> {
                // Linux cooked capture v1:
                // packet_type(2) + ARPHRD(2) + lladdr_len(2) + lladdr(8) + etherType(2) = 16 bytes
                if (raw.length < 16) {
                    return Result.unsupported(linkType, "Linux SLL header too short");
                }
                offset = 16;
                etherType = readU16(raw, 14);
                while (etherType == ETHERTYPE_VLAN || etherType == ETHERTYPE_VLAN_QINQ || etherType == ETHERTYPE_VLAN_9100) {
                    if (raw.length < offset + 4) {
                        return Result.unsupported(linkType, "Linux SLL VLAN tag truncated");
                    }
                    etherType = readU16(raw, offset + 2);
                    offset += 4;
                }
            }
            case LINKTYPE_LINUX_SLL2 -> {
                // Linux cooked capture v2:
                // protocol_type(2) + reserved(2) + ARPHRD(4) + lladdr_len(4) + lladdr(8) + etherType(2) = 20 bytes
                if (raw.length < 20) {
                    return Result.unsupported(linkType, "Linux SLL2 header too short");
                }
                offset = 20;
                etherType = readU16(raw, 18);
                while (etherType == ETHERTYPE_VLAN || etherType == ETHERTYPE_VLAN_QINQ || etherType == ETHERTYPE_VLAN_9100) {
                    if (raw.length < offset + 4) {
                        return Result.unsupported(linkType, "Linux SLL2 VLAN tag truncated");
                    }
                    etherType = readU16(raw, offset + 2);
                    offset += 4;
                }
            }
            case LINKTYPE_NULL -> {
                // BSD NULL/Loopback: 4-byte family, commonly little-endian
                if (raw.length < 4) {
                    return Result.unsupported(linkType, "NULL header too short");
                }
                offset = 4;
                etherType = resolveNullFamily(raw);
                if (etherType == -1) {
                    return Result.unsupported(linkType, "NULL family unknown");
                }
            }
            case LINKTYPE_PPP -> {
                // PPP: 2-byte protocol field
                if (raw.length < 2) {
                    return Result.unsupported(linkType, "PPP header too short");
                }
                offset = 2;
                etherType = resolvePppProtocol(readU16(raw, 0));
                if (etherType == -1) {
                    return Result.unsupported(linkType, "PPP protocol unknown");
                }
            }
            case LINKTYPE_IEEE802_11 -> {
                // IEEE 802.11: 仅处理 Data 帧 + LLC/SNAP 封装
                Result wifi = parse80211(raw, linkType);
                if (wifi != null) {
                    return wifi;
                }
                // parse80211 内部已返回 unsupported，这里兜底
                return Result.unsupported(linkType, "802.11 unsupported frame");
            }
            default -> {
                return Result.unsupported(linkType, "Unsupported link type: " + linkType);
            }
        }

        if (etherType == ETHERTYPE_IPV4) {
            return parseIpv4(raw, offset, linkType);
        } else if (etherType == ETHERTYPE_IPV6) {
            return parseIpv6(raw, offset, linkType);
        }
        return Result.unsupported(linkType, "Unsupported ether type: 0x" + Integer.toHexString(etherType));
    }

    private static Result parseIpv4(byte[] raw, int offset, int linkType) {
        if (raw.length < offset + 20) {
            return Result.unsupported(linkType, "IPv4 header truncated");
        }
        int ihl = raw[offset] & 0x0f;
        int headerLen = ihl * 4;
        if (headerLen < 20 || raw.length < offset + headerLen) {
            return Result.unsupported(linkType, "IPv4 IHL invalid or truncated");
        }
        int protocol = raw[offset + 9] & 0xff;
        String srcIp = ipToString(raw, offset + 12);
        String dstIp = ipToString(raw, offset + 16);
        int transportOffset = offset + headerLen;
        return Result.ok(linkType, offset, transportOffset, ETHERTYPE_IPV4, protocol, srcIp, dstIp);
    }

    private static Result parseIpv6(byte[] raw, int offset, int linkType) {
        if (raw.length < offset + 40) {
            return Result.unsupported(linkType, "IPv6 header truncated");
        }
        int nextHeader = raw[offset + 6] & 0xff;
        String srcIp = ip6ToString(raw, offset + 8);
        String dstIp = ip6ToString(raw, offset + 24);
        int payloadOffset = offset + 40;

        // 遍历 IPv6 扩展头，直到遇到真正的载荷协议
        while (isIpv6ExtensionHeader(nextHeader)) {
            if (raw.length < payloadOffset + 2) {
                return Result.unsupported(linkType, "IPv6 extension header truncated");
            }
            int extLen;
            if (nextHeader == 44) {
                // Fragment 头固定 8 字节
                extLen = 8;
            } else {
                // 其他扩展头长度 = (header[1] + 1) * 8
                extLen = (raw[payloadOffset + 1] & 0xff) * 8 + 8;
            }
            if (raw.length < payloadOffset + extLen) {
                return Result.unsupported(linkType, "IPv6 extension header payload truncated");
            }
            nextHeader = raw[payloadOffset] & 0xff;
            payloadOffset += extLen;
        }

        return Result.ok(linkType, offset, payloadOffset, ETHERTYPE_IPV6, nextHeader, srcIp, dstIp);
    }

    /**
     * 判断是否为 IPv6 扩展头（AH 同时是扩展头和载荷协议，遇到时停止遍历，由调用方按 ipProtocol 处理）。
     */
    private static boolean isIpv6ExtensionHeader(int protocol) {
        return switch (protocol) {
            case 0, 43, 44, 60, 135, 139, 140 -> true; // Hop-by-Hop, Routing, Fragment, Destination Options, Mobility, HIP, Shim6
            default -> false;
        };
    }

    private static int resolveNullFamily(byte[] raw) {
        // 常见实现为 little-endian 4 字节 family；同时兼容 big-endian
        int le = (raw[0] & 0xff) | ((raw[1] & 0xff) << 8)
                | ((raw[2] & 0xff) << 16) | ((raw[3] & 0xff) << 24);
        if (le == 2) return ETHERTYPE_IPV4;
        if (le == 24 || le == 28) return ETHERTYPE_IPV6;
        int be = ((raw[0] & 0xff) << 24) | ((raw[1] & 0xff) << 16)
                | ((raw[2] & 0xff) << 8) | (raw[3] & 0xff);
        if (be == 2) return ETHERTYPE_IPV4;
        if (be == 24 || be == 28) return ETHERTYPE_IPV6;
        return -1;
    }

    private static int resolvePppProtocol(int protocol) {
        return switch (protocol) {
            case 0x0021 -> ETHERTYPE_IPV4;
            case 0x0057 -> ETHERTYPE_IPV6;
            default -> -1;
        };
    }

    private static Result parse80211(byte[] raw, int linkType) {
        if (raw.length < 24) {
            return Result.unsupported(linkType, "802.11 header too short");
        }
        int type = (raw[0] >> 2) & 0x3;
        int subtype = (raw[0] >> 4) & 0xF;
        if (type != 2) {
            return Result.unsupported(linkType, "802.11 non-data frame");
        }
        boolean toDs = (raw[1] & 0x01) != 0;
        boolean fromDs = (raw[1] & 0x02) != 0;
        int headerLen = 24;
        if (toDs && fromDs) {
            if (raw.length < headerLen + 6) {
                return Result.unsupported(linkType, "802.11 4-address header truncated");
            }
            headerLen += 6;
        }
        if (subtype >= 8) { // QoS Data
            if (raw.length < headerLen + 2) {
                return Result.unsupported(linkType, "802.11 QoS header truncated");
            }
            headerLen += 2;
        }
        // LLC/SNAP
        if (raw.length < headerLen + 8) {
            return Result.unsupported(linkType, "802.11 LLC/SNAP truncated");
        }
        if ((raw[headerLen] & 0xFF) != 0xAA || (raw[headerLen + 1] & 0xFF) != 0xAA
                || (raw[headerLen + 2] & 0xFF) != 0x03) {
            return Result.unsupported(linkType, "802.11 LLC/SNAP not found");
        }
        if ((raw[headerLen + 3] & 0xFF) != 0x00 || (raw[headerLen + 4] & 0xFF) != 0x00
                || (raw[headerLen + 5] & 0xFF) != 0x00) {
            return Result.unsupported(linkType, "802.11 LLC/SNAP OUI not IEEE");
        }
        int etherType = readU16(raw, headerLen + 6);
        int offset = headerLen + 8;
        while (etherType == ETHERTYPE_VLAN || etherType == ETHERTYPE_VLAN_QINQ || etherType == ETHERTYPE_VLAN_9100) {
            if (raw.length < offset + 4) {
                return Result.unsupported(linkType, "802.11 VLAN tag truncated");
            }
            etherType = readU16(raw, offset + 2);
            offset += 4;
        }
        if (etherType == ETHERTYPE_IPV4) {
            return parseIpv4(raw, offset, linkType);
        } else if (etherType == ETHERTYPE_IPV6) {
            return parseIpv6(raw, offset, linkType);
        }
        return Result.unsupported(linkType, "Unsupported 802.11 ether type: 0x" + Integer.toHexString(etherType));
    }

    private static int readU16(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
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
