package com.smtool.module.parse;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

/**
 * 汇总所有 ISAKMP/IKE 消息的 exchange type、payload 类型分布，帮助定位证书所在位置。
 */
public class IpsecExchangeSummaryDump {

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
            List<Map<String, Object>> payloads = (List<Map<String, Object>>) parsed.get("payloads");
            StringBuilder types = new StringBuilder();
            if (payloads != null) {
                for (Map<String, Object> p : payloads) {
                    types.append(p.get("payloadTypeCode")).append(" ");
                }
            }
            System.out.println("idx=" + count
                    + " " + pkt.getSrcIp() + ":" + pkt.getSrcPort() + " -> " + pkt.getDstIp() + ":" + pkt.getDstPort()
                    + " len=" + h.get("length")
                    + " exchange=" + h.get("exchangeType")
                    + " flags=" + h.get("flags")
                    + " next=" + h.get("nextPayload")
                    + " payloads=" + types);
            count++;
        }
        System.out.println("Total IKE packets=" + count);
    }
}
