package com.smtool.module.parse;

import com.smtool.util.CodecUtil;

import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * 验证 IP 分片重组后能否从 ISAKMP 中提取证书。
 */
public class IpsecReassembleCertDump {

    public static void main(String[] args) throws Exception {
        File pcap = new File("../15、客户端访问 后台抓包ipsec.pcap");
        byte[] data = Files.readAllBytes(pcap.toPath());
        List<PcapPacket> packets = new PcapReader(data).readAll();
        System.out.println("Before reassembly: " + packets.size() + " packets");
        packets = IpFragmentReassembler.reassemble(packets);
        System.out.println("After reassembly: " + packets.size() + " packets");

        int ikeCount = 0;
        int certPayloadCount = 0;
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
            System.out.println("IKE " + ikeCount + " " + pkt.getSrcIp() + ":" + pkt.getSrcPort()
                    + "->" + pkt.getDstIp() + ":" + pkt.getDstPort()
                    + " len=" + isakmp.length
                    + " exchange=" + h.get("exchangeType")
                    + " flags=" + h.get("flags"));
            if (payloads != null) {
                for (Map<String, Object> p : payloads) {
                    Integer code = (Integer) p.get("payloadTypeCode");
                    Integer plen = (Integer) p.get("payloadLength");
                    System.out.println("  payload code=" + code + " len=" + plen);
                    if (code != null && code == 6) {
                        certPayloadCount++;
                        String hex = (String) p.get("data");
                        if (hex != null && hex.length() > 2) {
                            byte[] body = CodecUtil.fromHex(hex);
                            if (body.length > 1) {
                                int encoding = body[0] & 0xFF;
                                System.out.println("    CERT encoding=" + encoding + " (4=X.509-Signature)");
                                if (body.length > 1) {
                                    byte[] der = Arrays.copyOfRange(body, 1, body.length);
                                    System.out.println("    DER first bytes=" + CodecUtil.toHex(Arrays.copyOf(der, 16)));
                                    System.out.println("    DER total len=" + der.length);
                                }
                            }
                        }
                    }
                }
            }
            ikeCount++;
        }
        System.out.println("\nTotal cert payloads (type=6): " + certPayloadCount);
    }
}
