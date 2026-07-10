package com.smtool.module.parse;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

/**
 * _dump_ IKEv1 主模式前 6 条消息，观察 KE/NONCE/ID/CERT 等载荷。
 */
public class IpsecMainModeDump {

    public static void main(String[] args) throws Exception {
        File pcap = new File("../15、客户端访问 后台抓包ipsec.pcap");
        byte[] data = Files.readAllBytes(pcap.toPath());
        List<PcapPacket> packets = new PcapReader(data).readAll();
        int count = 0;
        int printed = 0;
        for (PcapPacket pkt : packets) {
            PacketParser.parse(pkt);
            if (!"udp".equals(pkt.getProtocol())) continue;
            if (pkt.getSrcPort() != 500 && pkt.getDstPort() != 500) continue;
            byte[] isakmp = IpsecParseService.stripNattMarker(pkt.getPayload(), pkt.getSrcPort(), pkt.getDstPort());
            if (isakmp.length < 28) continue;
            IpsecParseService svc = new IpsecParseService();
            Map<String, Object> parsed = svc.parseMessage(isakmp);
            Map<String, Object> h = (Map<String, Object>) parsed.get("header");
            String exchange = (String) h.get("exchangeType");
            String flags = (String) h.get("flags");
            boolean isMainMode = exchange != null && exchange.startsWith("2 (");
            boolean isEncrypted = flags != null && flags.contains("Encryption");
            if (isMainMode && printed < 10) {
                System.out.println("\n=== packet idx=" + count + " " + pkt.getSrcIp() + ":" + pkt.getSrcPort()
                        + " -> " + pkt.getDstIp() + ":" + pkt.getDstPort()
                        + " ts=" + pkt.getTimestampMicros());
                System.out.println("header=" + h);
                List<Map<String, Object>> payloads = (List<Map<String, Object>>) parsed.get("payloads");
                if (payloads != null) {
                    for (int i = 0; i < payloads.size(); i++) {
                        Map<String, Object> p = payloads.get(i);
                        String hex = (String) p.get("data");
                        System.out.println("  payload[" + i + "] code=" + p.get("payloadTypeCode")
                                + " type=" + p.get("payloadType")
                                + " len=" + p.get("payloadLength")
                                + " data=" + (hex.length() > 300 ? hex.substring(0, 300) + "..." : hex));
                    }
                }
                printed++;
            }
            count++;
        }
        System.out.println("\nTotal IKE packets=" + count);
    }
}
