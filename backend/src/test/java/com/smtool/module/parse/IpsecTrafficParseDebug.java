package com.smtool.module.parse;

import com.smtool.module.cert.CertCheckService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.mock.web.MockMultipartFile;

import java.io.File;
import java.nio.file.Files;
import java.security.Security;
import java.util.List;
import java.util.Map;

public class IpsecTrafficParseDebug {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) throws Exception {
        parseAndPrint("../test/ipsec_session_demo.pcap");
        parseAndPrint("../15、客户端访问 后台抓包ipsec.pcap");
    }

    private static void parseAndPrint(String path) throws Exception {
        System.out.println("\n========== Parsing: " + path + " ==========");
        File pcap = new File(path);
        byte[] data = Files.readAllBytes(pcap.toPath());

        IpsecParseService parseService = new IpsecParseService();
        CertCheckService certCheckService = new CertCheckService();
        IpsecSessionAnalyzer analyzer = new IpsecSessionAnalyzer(parseService, certCheckService);
        IpsecSessionMapper mapper = new IpsecSessionMapper();
        IpsecTrafficParseService trafficService = new IpsecTrafficParseService(analyzer, mapper, certCheckService);

        MockMultipartFile file = new MockMultipartFile("file", pcap.getName(),
                "application/vnd.tcpdump.pcap", data);
        IpsecTrafficParseResult result = trafficService.parse(file);
        System.out.println("sessions=" + result.getSessionCount() + ", parseTimeMs=" + result.getParseTimeMs());
        for (IpsecSessionDto dto : result.getSessions()) {
            System.out.println("--- DTO ---");
            System.out.println("protocolVersion=" + dto.getProtocolVersion());
            System.out.println("src=" + dto.getSrcIp() + ":" + dto.getSrcPort() + " -> dst=" + dto.getDstIp() + ":" + dto.getDstPort());
            System.out.println("gm=" + dto.isGm());
            System.out.println("hasDataPlane=" + dto.isHasDataPlane());
            System.out.println("dataPlaneSaCount=" + (dto.getDataPlaneSas() == null ? 0 : dto.getDataPlaneSas().size()));
            if (dto.getDataPlaneSas() != null) {
                for (IpsecDataPlaneSaDto sa : dto.getDataPlaneSas()) {
                    System.out.println("  SA: " + sa.getProtocol() + " spi=" + sa.getSpiHex()
                            + " packets=" + sa.getPacketCount() + " bytes=" + sa.getByteCount()
                            + " seq=" + sa.getFirstSeq() + "-" + sa.getLastSeq());
                }
            }
            System.out.println("selectedEncryption=" + dto.getSelectedEncryption());
            System.out.println("selectedIntegrity=" + dto.getSelectedIntegrity());
            System.out.println("selectedPrf=" + dto.getSelectedPrf());
            System.out.println("selectedDhGroup=" + dto.getSelectedDhGroup());
            System.out.println("initiatorIdentity=" + dto.getInitiatorIdentity());
            System.out.println("responderIdentity=" + dto.getResponderIdentity());
            System.out.println("authMethod=" + dto.getAuthMethod());
            System.out.println("certificateCount=" + dto.getCertificateCount());
            System.out.println("notifyTypes=" + dto.getNotifyTypes());
            System.out.println("initiatorAlgorithms=" + dto.getInitiatorAlgorithms());
            System.out.println("responderAlgorithms=" + dto.getResponderAlgorithms());
            System.out.println("certChain(initiator)=" + dto.getInitiatorCertificates().size());
            System.out.println("certChain(responder)=" + dto.getResponderCertificates().size());
            System.out.println("notes=" + dto.getNotes());
            System.out.println("--- messages ---");
            for (int i = 0; i < dto.getMessages().size(); i++) {
                Map<String, Object> msg = dto.getMessages().get(i);
                Map<String, Object> h = (Map<String, Object>) msg.get("header");
                String dir = (String) msg.get("direction");
                System.out.println("  msg[" + i + "] dir=" + dir
                        + " exchange=" + (h == null ? "-" : h.get("exchangeType"))
                        + " flags=" + (h == null ? "-" : h.get("flags"))
                        + " next=" + (h == null ? "-" : h.get("nextPayload")));
                List<Map<String, Object>> payloads = (List<Map<String, Object>>) msg.get("payloads");
                if (payloads != null) {
                    for (int j = 0; j < payloads.size(); j++) {
                        Map<String, Object> p = payloads.get(j);
                        String dataHex = (String) p.get("data");
                        String preview = dataHex != null && dataHex.length() > 64 ? dataHex.substring(0, 64) + "..." : dataHex;
                        String fullData = dataHex != null && dataHex.length() > 256 ? dataHex.substring(0, 256) + "..." : dataHex;
                        System.out.println("    payload[" + j + "] type=" + p.get("payloadType")
                                + " len=" + p.get("payloadLength")
                                + " data=" + preview);
                        if (dataHex != null && (dataHex.startsWith("00000001") || dataHex.startsWith("00000002"))) {
                            System.out.println("           full=" + fullData);
                        }
                    }
                }
            }
        }
    }
}
