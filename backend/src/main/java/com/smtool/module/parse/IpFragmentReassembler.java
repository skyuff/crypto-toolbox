package com.smtool.module.parse;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * IPv4 分片重组器。
 * <p>
 * 对抓包中跨多个 IP 分片的 UDP/500（IKE）等报文进行重组，生成完整的 PcapPacket 后再交给
 * {@link PacketParser} 解析，避免 ISAKMP 消息被截断导致证书、身份等载荷丢失。
 */
public class IpFragmentReassembler {

    /**
     * 重组输入报文中的 IPv4 分片，返回新的报文列表（分片被替换为重组后的完整报文）。
     */
    public static List<PcapPacket> reassemble(List<PcapPacket> packets) {
        if (packets == null || packets.isEmpty()) {
            return packets;
        }

        List<PcapPacket> result = new ArrayList<>();
        Map<FragmentKey, List<PcapPacket>> groups = new HashMap<>();

        for (PcapPacket pkt : packets) {
            FragmentInfo info = extractFragmentInfo(pkt);
            if (info == null || !info.fragment) {
                result.add(pkt);
                continue;
            }
            groups.computeIfAbsent(info.key, k -> new ArrayList<>()).add(pkt);
        }

        for (Map.Entry<FragmentKey, List<PcapPacket>> entry : groups.entrySet()) {
            List<PcapPacket> frags = entry.getValue();
            PcapPacket reassembled = tryReassemble(frags);
            if (reassembled != null) {
                result.add(reassembled);
            } else {
                result.addAll(frags);
            }
        }

        return result;
    }

    private static FragmentInfo extractFragmentInfo(PcapPacket pkt) {
        byte[] raw = pkt.getRaw();
        if (raw == null) {
            return null;
        }
        // 优先使用已经解析好的 networkOffset；未解析则临时用 PacketOffsetUtil 计算
        int networkOffset = pkt.getNetworkOffset();
        if (networkOffset < 0) {
            PacketOffsetUtil.Result r = PacketOffsetUtil.parse(raw, pkt.getLinkType());
            if (!r.supported || r.etherType != PacketOffsetUtil.ETHERTYPE_IPV4) {
                return null;
            }
            networkOffset = r.networkOffset;
        }
        if (raw.length < networkOffset + 20) {
            return null;
        }
        int version = (raw[networkOffset] >> 4) & 0x0F;
        if (version != 4) {
            return null;
        }
        int flagsFrag = ((raw[networkOffset + 6] & 0xFF) << 8) | (raw[networkOffset + 7] & 0xFF);
        int flags = flagsFrag >> 13;
        int fragOffset = flagsFrag & 0x1FFF;
        boolean moreFragments = (flags & 0x01) != 0;
        boolean isFragment = moreFragments || fragOffset != 0;
        int protocol = raw[networkOffset + 9] & 0xFF;
        int identification = ((raw[networkOffset + 4] & 0xFF) << 8) | (raw[networkOffset + 5] & 0xFF);
        int ihl = raw[networkOffset] & 0x0F;
        int headerLen = ihl * 4;
        int totalLen = ((raw[networkOffset + 2] & 0xFF) << 8) | (raw[networkOffset + 3] & 0xFF);

        // 分片键需要源/目的 IP；若 PacketParser 尚未解析，从原始字节兜底提取
        String srcIp = pkt.getSrcIp();
        String dstIp = pkt.getDstIp();
        if (srcIp == null || dstIp == null) {
            srcIp = ipToString(raw, networkOffset + 12);
            dstIp = ipToString(raw, networkOffset + 16);
        }

        FragmentKey key = new FragmentKey(srcIp, dstIp, identification, protocol);
        return new FragmentInfo(key, isFragment, fragOffset, moreFragments, headerLen, totalLen, networkOffset);
    }

    private static String ipToString(byte[] raw, int offset) {
        if (raw == null || offset + 4 > raw.length) {
            return null;
        }
        return (raw[offset] & 0xFF) + "." + (raw[offset + 1] & 0xFF) + "."
                + (raw[offset + 2] & 0xFF) + "." + (raw[offset + 3] & 0xFF);
    }

    private static PcapPacket tryReassemble(List<PcapPacket> frags) {
        if (frags.isEmpty()) {
            return null;
        }
        frags.sort(Comparator.comparingInt(a -> {
            FragmentInfo info = extractFragmentInfo(a);
            return info != null ? info.fragOffset : 0;
        }));

        PcapPacket first = frags.get(0);
        FragmentInfo firstInfo = extractFragmentInfo(first);
        if (firstInfo == null || firstInfo.fragOffset != 0) {
            return null; // 缺少第一个分片，无法重组
        }

        // 计算完整 IP 载荷长度
        int totalIpPayloadLen = 0;
        for (PcapPacket f : frags) {
            FragmentInfo info = extractFragmentInfo(f);
            if (info == null) {
                return null;
            }
            // 该分片携带的 IP 层载荷字节数 = totalLen - ipHeaderLen
            int payloadLen = info.totalLen - info.headerLen;
            totalIpPayloadLen += payloadLen;
        }

        byte[] firstRaw = first.getRaw();
        int linkHeaderLen = firstInfo.networkOffset;
        int firstHeaderLen = firstInfo.headerLen;

        // 第一个分片包含 UDP 头，后续分片只有 IP 载荷
        byte[] reassembled = new byte[linkHeaderLen + firstHeaderLen + totalIpPayloadLen];
        System.arraycopy(firstRaw, 0, reassembled, 0, linkHeaderLen + firstHeaderLen);

        int pos = linkHeaderLen + firstHeaderLen;
        for (PcapPacket f : frags) {
            FragmentInfo info = extractFragmentInfo(f);
            if (info == null) {
                return null;
            }
            byte[] raw = f.getRaw();
            int payloadLen = info.totalLen - info.headerLen;
            int srcPayloadStart = linkHeaderLen + info.headerLen;
            if (raw.length < srcPayloadStart + payloadLen) {
                payloadLen = raw.length - srcPayloadStart;
            }
            System.arraycopy(raw, srcPayloadStart, reassembled, pos, payloadLen);
            pos += payloadLen;
        }

        // 修正 IP 头：清分片标志、更新总长度、清零校验和
        int ipOff = firstInfo.networkOffset;
        int newTotalLen = firstHeaderLen + totalIpPayloadLen;
        reassembled[ipOff + 2] = (byte) ((newTotalLen >> 8) & 0xFF);
        reassembled[ipOff + 3] = (byte) (newTotalLen & 0xFF);
        reassembled[ipOff + 6] = 0x40; // Don't Fragment = 1, MF = 0, frag offset high byte = 0
        reassembled[ipOff + 7] = 0x00; // frag offset low byte = 0
        reassembled[ipOff + 10] = 0x00; // checksum zero
        reassembled[ipOff + 11] = 0x00;
        int checksum = computeIpChecksum(reassembled, ipOff, firstHeaderLen);
        reassembled[ipOff + 10] = (byte) ((checksum >> 8) & 0xFF);
        reassembled[ipOff + 11] = (byte) (checksum & 0xFF);

        PcapPacket pkt = new PcapPacket();
        pkt.setTimestampMicros(first.getTimestampMicros());
        pkt.setLinkType(first.getLinkType());
        pkt.setRaw(reassembled);
        return pkt;
    }

    private static int computeIpChecksum(byte[] data, int offset, int len) {
        long sum = 0;
        for (int i = 0; i < len; i += 2) {
            int word = ((data[offset + i] & 0xFF) << 8);
            if (i + 1 < len) {
                word |= (data[offset + i + 1] & 0xFF);
            }
            sum += word;
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return ~((int) sum) & 0xFFFF;
    }

    private static class FragmentKey {
        final String srcIp;
        final String dstIp;
        final int identification;
        final int protocol;

        FragmentKey(String srcIp, String dstIp, int identification, int protocol) {
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.identification = identification;
            this.protocol = protocol;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof FragmentKey)) return false;
            FragmentKey that = (FragmentKey) o;
            return identification == that.identification &&
                    protocol == that.protocol &&
                    Objects.equals(srcIp, that.srcIp) &&
                    Objects.equals(dstIp, that.dstIp);
        }

        @Override
        public int hashCode() {
            return Objects.hash(srcIp, dstIp, identification, protocol);
        }
    }

    private static class FragmentInfo {
        final FragmentKey key;
        final boolean fragment;
        final int fragOffset;
        final boolean moreFragments;
        final int headerLen;
        final int totalLen;
        final int networkOffset;

        FragmentInfo(FragmentKey key, boolean fragment, int fragOffset, boolean moreFragments,
                     int headerLen, int totalLen, int networkOffset) {
            this.key = key;
            this.fragment = fragment;
            this.fragOffset = fragOffset;
            this.moreFragments = moreFragments;
            this.headerLen = headerLen;
            this.totalLen = totalLen;
            this.networkOffset = networkOffset;
        }
    }
}
