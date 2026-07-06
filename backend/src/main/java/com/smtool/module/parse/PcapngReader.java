package com.smtool.module.parse;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 轻量级 pcapng 读取器，支持 Section Header、Interface Description 与 Enhanced Packet 块。
 */
public class PcapngReader {

    private static final int SHB_TYPE = 0x0A0D0D0A;
    private static final int IDB_TYPE = 0x00000001;
    private static final int EPB_TYPE = 0x00000006;
    private static final int SPB_TYPE = 0x00000003;

    private final byte[] data;
    private boolean littleEndian = true;

    public PcapngReader(byte[] data) {
        this.data = data;
    }

    public List<PcapPacket> readAll() throws Exception {
        List<PcapPacket> packets = new ArrayList<>();
        if (data.length < 12) {
            return packets;
        }

        int pos = 0;
        Map<Integer, Integer> interfaceLinkTypes = new HashMap<>();
        int interfaceCount = 0;

        while (pos + 12 <= data.length) {
            int blockType = readInt(pos);
            int blockLength = readInt(pos + 4);
            if (blockLength < 12 || pos + blockLength > data.length) {
                break;
            }
            int blockEnd = pos + blockLength;
            int trailingLength = readInt(blockEnd - 4);
            if (blockLength != trailingLength) {
                // malformed block, try to continue at next word
                pos += 4;
                continue;
            }

            int bodyStart = pos + 8;
            int bodyLength = blockLength - 12;

            if (blockType == SHB_TYPE) {
                // Section Header Block: magic(4) + major(2) + minor(2) + sectionLength(8) + options
                if (bodyLength >= 4) {
                    int magic = readInt(bodyStart);
                    littleEndian = (magic == 0x1A2B3C4D);
                    if (!littleEndian && magic != 0x4D3C2B1A) {
                        // unknown byte order, stop
                        break;
                    }
                }
                // reset per-section interface state
                interfaceLinkTypes.clear();
                interfaceCount = 0;
            } else if (blockType == IDB_TYPE) {
                // Interface Description Block: linkType(2) + reserved(2) + snapLen(4) + options
                if (bodyLength >= 8) {
                    int linkType = readShort(bodyStart) & 0xffff;
                    interfaceLinkTypes.put(interfaceCount++, linkType);
                }
            } else if (blockType == EPB_TYPE) {
                // Enhanced Packet Block: interfaceId(4) + timestampHi(4) + timestampLo(4) +
                // capturedLen(4) + packetLen(4) + packetData(padded) + options
                if (bodyLength >= 20) {
                    int interfaceId = readInt(bodyStart);
                    int capturedLen = readInt(bodyStart + 12);
                    int packetLen = readInt(bodyStart + 16);
                    int dataStart = bodyStart + 20;
                    int paddedLen = padTo4(capturedLen);
                    if (paddedLen <= bodyLength - 20 && capturedLen >= 0 && capturedLen <= packetLen) {
                        byte[] packetData = new byte[capturedLen];
                        System.arraycopy(data, dataStart, packetData, 0, capturedLen);
                        int linkType = interfaceLinkTypes.getOrDefault(interfaceId, 1);

                        PcapPacket pkt = new PcapPacket();
                        pkt.setTimestampMicros(0);
                        pkt.setLinkType(linkType);
                        pkt.setRaw(packetData);
                        PacketParser.parse(pkt);
                        if (pkt.getProtocol() != null) {
                            packets.add(pkt);
                            if ("10.65.200.23".equals(pkt.getSrcIp()) && pkt.getSrcPort() == 2000 && pkt.getDstPort() == 55017) {
                                System.out.println("[EPB-55017] cap=" + capturedLen + " raw=" + packetData.length
                                        + " tcpOff=" + findTcpOffset(packetData)
                                        + " seqBytes=" + bytesToHex(packetData, findTcpOffset(packetData), 4)
                                        + " head=" + bytesToHex(packetData, 0, 30));
                            }
                        }
                    }
                }
            } else if (blockType == SPB_TYPE) {
                // Simple Packet Block: packetLen(4) + packetData(padded) + options
                if (bodyLength >= 4) {
                    int packetLen = readInt(bodyStart);
                    int paddedLen = padTo4(packetLen);
                    if (paddedLen <= bodyLength - 4) {
                        byte[] packetData = new byte[packetLen];
                        System.arraycopy(data, bodyStart + 4, packetData, 0, packetLen);
                        int linkType = interfaceLinkTypes.getOrDefault(0, 1);

                        PcapPacket pkt = new PcapPacket();
                        pkt.setTimestampMicros(0);
                        pkt.setLinkType(linkType);
                        pkt.setRaw(packetData);
                        PacketParser.parse(pkt);
                        if (pkt.getProtocol() != null) {
                            packets.add(pkt);
                        }
                    }
                }
            }

            pos = blockEnd;
        }

        return packets;
    }

    private int readInt(int offset) {
        if (littleEndian) {
            return (data[offset] & 0xff)
                    | ((data[offset + 1] & 0xff) << 8)
                    | ((data[offset + 2] & 0xff) << 16)
                    | ((data[offset + 3] & 0xff) << 24);
        }
        return ((data[offset] & 0xff) << 24)
                | ((data[offset + 1] & 0xff) << 16)
                | ((data[offset + 2] & 0xff) << 8)
                | (data[offset + 3] & 0xff);
    }

    private int readShort(int offset) {
        if (littleEndian) {
            return (data[offset] & 0xff) | ((data[offset + 1] & 0xff) << 8);
        }
        return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
    }

    private static int padTo4(int len) {
        return (len + 3) & ~3;
    }

    private static int findTcpOffset(byte[] raw) {
        if (raw == null || raw.length < 14) {
            return -1;
        }
        int offset;
        int etherType = ((raw[12] & 0xff) << 8) | (raw[13] & 0xff);
        offset = 14;
        while (etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100) {
            if (raw.length < offset + 4) {
                return -1;
            }
            etherType = ((raw[offset + 2] & 0xff) << 8) | (raw[offset + 3] & 0xff);
            offset += 4;
        }
        if (etherType == 0x0800) {
            int ihl = raw[offset] & 0x0f;
            return offset + ihl * 4;
        } else if (etherType == 0x86dd) {
            return offset + 40;
        }
        return -1;
    }

    private static String bytesToHex(byte[] data, int offset, int len) {
        if (data == null || offset < 0 || offset >= data.length) {
            return "";
        }
        int end = Math.min(offset + len, data.length);
        StringBuilder sb = new StringBuilder();
        for (int i = offset; i < end; i++) {
            sb.append(String.format("%02x", data[i] & 0xff));
        }
        return sb.toString();
    }
}
