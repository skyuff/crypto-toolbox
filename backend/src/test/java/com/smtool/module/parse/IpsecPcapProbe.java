package com.smtool.module.parse;

import java.io.File;
import java.nio.file.Files;
import java.util.List;

public class IpsecPcapProbe {
    public static void main(String[] args) throws Exception {
        File pcap = new File("../15、客户端访问 后台抓包ipsec.pcap");
        byte[] data = Files.readAllBytes(pcap.toPath());
        List<PcapPacket> packets = new PcapReader(data).readAll();
        for (PcapPacket pkt : packets) {
            PacketParser.parse(pkt);
            if (!"udp".equals(pkt.getProtocol())) continue;
            if (pkt.getSrcPort() != 500 && pkt.getSrcPort() != 4500
                    && pkt.getDstPort() != 500 && pkt.getDstPort() != 4500) {
                continue;
            }
            byte[] isakmp = IpsecParseService.stripNattMarker(pkt.getPayload(), pkt.getSrcPort(), pkt.getDstPort());
            if (isakmp.length < 28) continue;
            String iSpi = bytesToHex(isakmp, 0, 8);
            String rSpi = bytesToHex(isakmp, 8, 8);
            int next = isakmp[16] & 0xff;
            int version = isakmp[17] & 0xff;
            int major = (version >> 4) & 0x0f;
            int exchange = isakmp[18] & 0xff;
            int flags = isakmp[19] & 0xff;
            System.out.println("ts=" + pkt.getTimestampMicros()
                    + " " + pkt.getSrcIp() + ":" + pkt.getSrcPort()
                    + " -> " + pkt.getDstIp() + ":" + pkt.getDstPort()
                    + " v=" + major + " ex=" + exchange
                    + " flags=0x" + String.format("%02x", flags)
                    + " next=" + next
                    + " iSPI=" + iSpi + " rSPI=" + rSpi
                    + " len=" + isakmp.length);
        }
    }

    private static String bytesToHex(byte[] data, int off, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = off; i < off + len && i < data.length; i++) {
            sb.append(String.format("%02x", data[i] & 0xff));
        }
        return sb.toString();
    }
}
