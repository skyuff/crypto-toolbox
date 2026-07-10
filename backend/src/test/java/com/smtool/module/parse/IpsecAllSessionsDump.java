package com.smtool.module.parse;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 不过滤任何会话，按 IKE SPI 分组并展示所有消息，用于发现隐藏的证书交换。
 */
public class IpsecAllSessionsDump {

    public static void main(String[] args) throws Exception {
        File pcap = new File("../15、客户端访问 后台抓包ipsec.pcap");
        byte[] data = Files.readAllBytes(pcap.toPath());
        List<PcapPacket> packets = new PcapReader(data).readAll();

        Map<String, List<Map<String, Object>>> sessions = new HashMap<>();
        Map<String, Long> firstTimestamps = new HashMap<>();
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
            String iSpi = (String) h.get("initiatorSpi");
            sessions.computeIfAbsent(iSpi, k -> new ArrayList<>()).add(parsed);
            firstTimestamps.merge(iSpi, pkt.getTimestampMicros(), Math::min);
            count++;
        }

        List<String> keys = new ArrayList<>(sessions.keySet());
        keys.sort(Comparator.comparingLong(firstTimestamps::get));

        for (String spi : keys) {
            System.out.println("\n========== IKE SA initiatorSpi=" + spi + " messages=" + sessions.get(spi).size() + " ==========");
            for (Map<String, Object> parsed : sessions.get(spi)) {
                Map<String, Object> h = (Map<String, Object>) parsed.get("header");
                System.out.println("  exchange=" + h.get("exchangeType")
                        + " flags=" + h.get("flags")
                        + " len=" + h.get("length")
                        + " next=" + h.get("nextPayload"));
                List<Map<String, Object>> payloads = (List<Map<String, Object>>) parsed.get("payloads");
                if (payloads != null) {
                    for (Map<String, Object> p : payloads) {
                        System.out.println("    payload code=" + p.get("payloadTypeCode")
                                + " type=" + p.get("payloadType")
                                + " len=" + p.get("payloadLength"));
                    }
                }
            }
        }
        System.out.println("\nTotal IKE packets=" + count + ", sessions=" + keys.size());
    }

}
