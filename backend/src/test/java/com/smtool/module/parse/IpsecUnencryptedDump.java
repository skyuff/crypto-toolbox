package com.smtool.module.parse;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

public class IpsecUnencryptedDump {

    public static void main(String[] args) throws Exception {
        File pcap = new File("../15、客户端访问 后台抓包ipsec.pcap");
        byte[] data = Files.readAllBytes(pcap.toPath());
        List<PcapPacket> packets = new PcapReader(data).readAll();
        int count = 0;
        for (PcapPacket pkt : packets) {
            PacketParser.parse(pkt);
            if (!"udp".equals(pkt.getProtocol())) continue;
            if (pkt.getSrcPort() != 500 && pkt.getDstPort() != 500) continue;
            byte[] isakmp = IpsecParseService.stripNattMarker(pkt.getPayload(), pkt.getSrcPort(), pkt.getDstPort());
            if (isakmp.length < 28) continue;
            IpsecParseService svc = new IpsecParseService();
            Map<String, Object> parsed = svc.parseMessage(isakmp);
            Map<String, Object> h = (Map<String, Object>) parsed.get("header");
            String flags = (String) h.get("flags");
            if (flags != null && flags.contains("Encryption")) continue;
            List<Map<String, Object>> payloads = (List<Map<String, Object>>) parsed.get("payloads");
            System.out.println("\n=== pkt " + count + " " + pkt.getSrcIp() + ":" + pkt.getSrcPort()
                    + " -> " + pkt.getDstIp() + ":" + pkt.getDstPort()
                    + " iSPI=" + h.get("initiatorSpi") + " rSPI=" + h.get("responderSpi")
                    + " ex=" + h.get("exchangeType") + " flags=" + flags);
            if (payloads != null) {
                for (Map<String, Object> p : payloads) {
                    System.out.println("  code=" + p.get("payloadTypeCode") + " type=" + p.get("payloadType") + " len=" + p.get("payloadLength"));
                }
            }
            count++;
        }
        System.out.println("\nUnencrypted IKE packets=" + count);
    }
}
