package com.smtool.module.parse;

/**
 * 从链路层字节解析 Ethernet / RAW / Linux cooked capture -> IPv4/IPv6 -> TCP/UDP/ESP/AH/ICMP。
 */
public class PacketParser {

    private static final int PROTOCOL_TCP = 6;
    private static final int PROTOCOL_UDP = 17;
    private static final int PROTOCOL_ICMP = 1;
    private static final int PROTOCOL_ICMPV6 = 58;
    private static final int PROTOCOL_ESP = 50;
    private static final int PROTOCOL_AH = 51;

    public static void parse(PcapPacket packet) {
        byte[] raw = packet.getRaw();
        PacketOffsetUtil.Result result = PacketOffsetUtil.parse(raw, packet.getLinkType());
        if (!result.supported) {
            return;
        }

        packet.setSrcIp(result.srcIp);
        packet.setDstIp(result.dstIp);
        packet.setNetworkProtocol(result.ipProtocol);
        packet.setNetworkOffset(result.networkOffset);
        packet.setTransportOffset(result.transportOffset);

        switch (result.ipProtocol) {
            case PROTOCOL_TCP -> parseTcp(packet, raw, result.transportOffset);
            case PROTOCOL_UDP -> parseUdp(packet, raw, result.transportOffset);
            case PROTOCOL_ESP -> parseEsp(packet, raw, result.transportOffset);
            case PROTOCOL_AH -> parseAh(packet, raw, result.transportOffset);
            case PROTOCOL_ICMP, PROTOCOL_ICMPV6 -> parseIcmp(packet, raw, result.transportOffset);
            default -> {
                packet.setProtocol("other");
                packet.setPayload(extractPayload(raw, result.transportOffset));
            }
        }
    }

    private static void parseTcp(PcapPacket packet, byte[] raw, int offset) {
        if (raw.length < offset + 20) {
            return;
        }
        int srcPort = readU16(raw, offset);
        int dstPort = readU16(raw, offset + 2);
        int dataOffset = ((raw[offset + 12] & 0xff) >> 4) * 4;
        packet.setSrcPort(srcPort);
        packet.setDstPort(dstPort);
        packet.setProtocol("tcp");
        packet.setPayload(extractPayload(raw, offset + dataOffset));
    }

    private static void parseUdp(PcapPacket packet, byte[] raw, int offset) {
        if (raw.length < offset + 8) {
            return;
        }
        int srcPort = readU16(raw, offset);
        int dstPort = readU16(raw, offset + 2);
        int len = readU16(raw, offset + 4);
        int dataLen = len - 8;
        packet.setSrcPort(srcPort);
        packet.setDstPort(dstPort);
        packet.setProtocol("udp");
        if (dataLen > 0 && raw.length >= offset + 8 + dataLen) {
            byte[] payload = new byte[dataLen];
            System.arraycopy(raw, offset + 8, payload, 0, dataLen);
            packet.setPayload(payload);
        } else {
            packet.setPayload(new byte[0]);
        }
    }

    private static void parseEsp(PcapPacket packet, byte[] raw, int offset) {
        // ESP header: SPI(4) + Sequence Number(4) + IV/payload...
        if (raw.length < offset + 8) {
            return;
        }
        packet.setEspSpi(readU32(raw, offset));
        packet.setEspSequence(readU32(raw, offset + 4));
        packet.setProtocol("esp");
        packet.setPayload(extractPayload(raw, offset + 8));
    }

    private static void parseAh(PcapPacket packet, byte[] raw, int offset) {
        // AH header: Next Header(1) + Payload Len(1) + Reserved(2) + SPI(4) + Sequence Number(4) + ICV...
        if (raw.length < offset + 12) {
            return;
        }
        packet.setAhSpi(readU32(raw, offset + 4));
        packet.setAhSequence(readU32(raw, offset + 8));
        packet.setProtocol("ah");
        int payloadLen = (raw[offset + 1] & 0xff) * 4 + 8;
        packet.setPayload(extractPayload(raw, offset + payloadLen));
    }

    private static void parseIcmp(PcapPacket packet, byte[] raw, int offset) {
        packet.setProtocol("icmp");
        packet.setPayload(extractPayload(raw, offset));
    }

    private static byte[] extractPayload(byte[] raw, int offset) {
        if (offset < 0 || offset >= raw.length) {
            return new byte[0];
        }
        byte[] payload = new byte[raw.length - offset];
        System.arraycopy(raw, offset, payload, 0, payload.length);
        return payload;
    }

    private static int readU16(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
    }

    private static long readU32(byte[] data, int offset) {
        return ((data[offset] & 0xffL) << 24)
                | ((data[offset + 1] & 0xffL) << 16)
                | ((data[offset + 2] & 0xffL) << 8)
                | (data[offset + 3] & 0xffL);
    }
}
