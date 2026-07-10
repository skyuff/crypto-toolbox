package com.smtool.module.parse;

import java.io.File;
import java.nio.file.Files;
import java.util.List;

/**
 * 扫描 pcap 中是否存在 IP 分片，特别是 UDP/500 相关的分片。
 */
public class IpsecFragmentScan {

    public static void main(String[] args) throws Exception {
        File pcap = new File("../15、客户端访问 后台抓包ipsec.pcap");
        byte[] data = Files.readAllBytes(pcap.toPath());
        List<PcapPacket> packets = new PcapReader(data).readAll();

        int total = 0;
        int fragments = 0;
        int udp500 = 0;
        int udp500Fragments = 0;

        for (PcapPacket pkt : packets) {
            PacketParser.parse(pkt);
            total++;
            byte[] raw = pkt.getRaw();
            if (raw == null || raw.length < 20) continue;
            int ipOff = pkt.getNetworkOffset();
            if (ipOff < 0 || raw.length < ipOff + 20) continue;
            int version = (raw[ipOff] >> 4) & 0x0F;
            if (version != 4) continue;
            int flagsFrag = ((raw[ipOff + 6] & 0xFF) << 8) | (raw[ipOff + 7] & 0xFF);
            int flags = flagsFrag >> 13;
            int fragOffset = flagsFrag & 0x1FFF;
            boolean moreFragments = (flags & 0x01) != 0;
            boolean isFragment = moreFragments || fragOffset != 0;
            int protocol = raw[ipOff + 9] & 0xFF;
            int totalLen = ((raw[ipOff + 2] & 0xFF) << 8) | (raw[ipOff + 3] & 0xFF);
            int srcPort = pkt.getSrcPort();
            int dstPort = pkt.getDstPort();
            boolean isUdp500 = "udp".equals(pkt.getProtocol()) && (srcPort == 500 || dstPort == 500);

            if (isFragment) {
                fragments++;
                if (isUdp500 || protocol == 17) {
                    udp500Fragments++;
                    System.out.println("Fragmented UDP packet: idx=" + total
                            + " " + pkt.getSrcIp() + "->" + pkt.getDstIp()
                            + " protocol=" + protocol
                            + " fragOffset=" + fragOffset + " more=" + moreFragments
                            + " totalLen=" + totalLen + " capturedLen=" + raw.length);
                }
            }
            if (isUdp500) {
                udp500++;
            }
        }
        System.out.println("Total packets=" + total + ", UDP/500=" + udp500
                + ", total IP fragments=" + fragments + ", UDP/500 fragments=" + udp500Fragments);
    }
}
