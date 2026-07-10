package com.smtool.module.parse;

import com.smtool.util.CodecUtil;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

/**
 * 深度扫描 pcap 中所有可能的证书数据：
 * 1. 列出所有 payload 类型、长度、起始字节
 * 2. 找出所有以 0x30 开头的大 payload（可能是 X.509 DER）
 * 3. 统计加密/未加密消息分布
 */
public class IpsecDeepCertScan {

    public static void main(String[] args) throws Exception {
        File pcap = new File("../15、客户端访问 后台抓包ipsec.pcap");
        byte[] data = Files.readAllBytes(pcap.toPath());
        List<PcapPacket> packets = new PcapReader(data).readAll();
        int ikeCount = 0;
        int certLikePayloads = 0;
        int encryptedCount = 0;

        System.out.println("=== 所有 IKE/ISAKMP 消息 payload 概览 ===");
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
            String flags = (String) h.get("flags");
            boolean encrypted = flags != null && flags.contains("Encryption");
            if (encrypted) encryptedCount++;

            StringBuilder sb = new StringBuilder();
            sb.append("idx=").append(ikeCount)
              .append(" ").append(pkt.getSrcIp()).append(":").append(pkt.getSrcPort())
              .append("->").append(pkt.getDstIp()).append(":").append(pkt.getDstPort())
              .append(" len=").append(h.get("length"))
              .append(" ").append(h.get("exchangeType"))
              .append(" flags=").append(flags);

            if (payloads != null) {
                for (Map<String, Object> p : payloads) {
                    Integer code = (Integer) p.get("payloadTypeCode");
                    Integer plen = (Integer) p.get("payloadLength");
                    String hex = (String) p.get("data");
                    sb.append(" |").append(code).append(":").append(plen);
                    if (hex != null && hex.startsWith("30")) {
                        sb.append("(DER?)");
                        certLikePayloads++;
                    }
                }
            }
            System.out.println(sb);
            ikeCount++;
        }
        System.out.println("\nTotal IKE packets=" + ikeCount + ", encrypted=" + encryptedCount + ", DER-like starts=" + certLikePayloads);
    }
}
