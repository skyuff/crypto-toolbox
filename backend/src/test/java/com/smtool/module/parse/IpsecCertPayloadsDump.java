package com.smtool.module.parse;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

/**
 * _dump_ 所有 ISAKMP 消息中的证书相关 payload（type 128 私有载荷、标准 CERT type 6 等）。
 */
public class IpsecCertPayloadsDump {

    public static void main(String[] args) throws Exception {
        File pcap = new File("../15、客户端访问 后台抓包ipsec.pcap");
        byte[] data = Files.readAllBytes(pcap.toPath());
        List<PcapPacket> packets = new PcapReader(data).readAll();
        int count = 0;
        int certMessages = 0;
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
            if (payloads == null) continue;

            boolean hasCert = false;
            for (Map<String, Object> p : payloads) {
                Integer code = (Integer) p.get("payloadTypeCode");
                if (code != null && (code == 128 || code == 6 || code == 12 || code == 4)) {
                    hasCert = true;
                    break;
                }
            }
            if (!hasCert) {
                count++;
                continue;
            }

            certMessages++;
            System.out.println("\n=== packet idx=" + count + " " + pkt.getSrcIp() + ":" + pkt.getSrcPort()
                    + " -> " + pkt.getDstIp() + ":" + pkt.getDstPort()
                    + " ts=" + pkt.getTimestampMicros());
            System.out.println("header=" + h);
            for (int i = 0; i < payloads.size(); i++) {
                Map<String, Object> p = payloads.get(i);
                Integer code = (Integer) p.get("payloadTypeCode");
                String hex = (String) p.get("data");
                System.out.println("  payload[" + i + "] code=" + code
                        + " type=" + p.get("payloadType")
                        + " len=" + p.get("payloadLength")
                        + " startsWith=" + (hex.length() >= 4 ? hex.substring(0, 4) : hex)
                        + " data=" + (hex.length() > 400 ? hex.substring(0, 400) + "..." : hex));
            }
            count++;
        }
        System.out.println("\nTotal IKE packets=" + count + ", messages with cert payload=" + certMessages);
    }
}
