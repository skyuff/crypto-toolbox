package com.smtool.module.parse;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * TCP 流重组服务。
 */
@Service
public class TcpReassemblyService {

    public static class SessionKey {
        public final String ipA;
        public final int portA;
        public final String ipB;
        public final int portB;

        public SessionKey(String ipA, int portA, String ipB, int portB) {
            // normalize: smaller IP/port first
            int cmp = ipA.compareTo(ipB);
            if (cmp < 0 || (cmp == 0 && portA <= portB)) {
                this.ipA = ipA;
                this.portA = portA;
                this.ipB = ipB;
                this.portB = portB;
            } else {
                this.ipA = ipB;
                this.portA = portB;
                this.ipB = ipA;
                this.portB = portA;
            }
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof SessionKey that)) return false;
            return portA == that.portA && portB == that.portB
                    && ipA.equals(that.ipA) && ipB.equals(that.ipB);
        }

        @Override
        public int hashCode() {
            int result = ipA.hashCode();
            result = 31 * result + portA;
            result = 31 * result + ipB.hashCode();
            result = 31 * result + portB;
            return result;
        }

        @Override
        public String toString() {
            return ipA + ":" + portA + " <-> " + ipB + ":" + portB;
        }
    }

    public static class BidirectionalStream {
        public final TcpStream aToB = new TcpStream();
        public final TcpStream bToA = new TcpStream();
        public final SessionKey key;

        public BidirectionalStream(SessionKey key) {
            this.key = key;
        }
    }

    /**
     * 将包列表按五元组分组并重组为双向 TCP 字节流。
     */
    public Map<SessionKey, BidirectionalStream> reassemble(List<PcapPacket> packets) {
        Map<SessionKey, BidirectionalStream> sessions = new HashMap<>();
        for (PcapPacket pkt : packets) {
            if (!"tcp".equals(pkt.getProtocol()) || pkt.getPayload() == null) {
                continue;
            }
            SessionKey key = new SessionKey(pkt.getSrcIp(), pkt.getSrcPort(), pkt.getDstIp(), pkt.getDstPort());
            BidirectionalStream stream = sessions.computeIfAbsent(key, BidirectionalStream::new);

            // 通过比较 key 中的 A 与包的源地址判断方向
            boolean isAToB = key.ipA.equals(pkt.getSrcIp()) && key.portA == pkt.getSrcPort();
            int tcpOffset = findTcpOffset(pkt);
            if (tcpOffset < 0) {
                continue;
            }
            // TCP 头起始位置后 4 字节为 Sequence Number，再后 4 字节为 Ack Number
            long seq = readUnsignedInt(pkt.getRaw(), tcpOffset + 4);
            long ack = readUnsignedInt(pkt.getRaw(), tcpOffset + 8);
            int flags = pkt.getRaw()[tcpOffset + 13] & 0xff;
            byte[] payload = pkt.getPayload();
            if ("10.65.200.23".equals(pkt.getSrcIp()) && pkt.getSrcPort() == 2000 && pkt.getDstPort() == 55017) {
                System.out.println("[PKT-55017] raw=" + pkt.getRaw().length + " tcpOff=" + tcpOffset
                        + " seq=" + seq + " flags=" + flags + " payload=" + (payload == null ? 0 : payload.length)
                        + " head=" + (payload == null || payload.length == 0 ? "" : CodecUtil.toHex(java.util.Arrays.copyOf(payload, Math.min(payload.length, 20)))));
            }
            TcpSegment segment = new TcpSegment(seq, ack, payload, flags, pkt.getTimestampMicros());
            if (isAToB) {
                stream.aToB.addSegment(segment);
            } else {
                stream.bToA.addSegment(segment);
            }
        }
        return sessions;
    }

    private static int findTcpOffset(PcapPacket pkt) {
        PacketOffsetUtil.Result result = PacketOffsetUtil.parse(pkt.getRaw(), pkt.getLinkType());
        if (!result.supported || result.ipProtocol != 6) {
            return -1;
        }
        return result.transportOffset;
    }

    private static long readUnsignedInt(byte[] data, int offset) {
        if (offset < 0 || data.length < offset + 4) {
            return 0;
        }
        return ((data[offset] & 0xffL) << 24)
                | ((data[offset + 1] & 0xffL) << 16)
                | ((data[offset + 2] & 0xffL) << 8)
                | (data[offset + 3] & 0xffL);
    }
}
