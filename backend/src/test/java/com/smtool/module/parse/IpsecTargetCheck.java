package com.smtool.module.parse;

import com.smtool.module.cert.CertCheckService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.mock.web.MockMultipartFile;

import java.io.File;
import java.nio.file.Files;
import java.security.Security;
import java.util.List;
import java.util.Map;

public class IpsecTargetCheck {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) {
        try {
            parseAndPrint("../15、客户端访问 后台抓包ipsec.pcap");
        } catch (Exception e) {
            System.out.println("EXCEPTION: " + e);
            e.printStackTrace();
        }
    }

    private static void parseAndPrint(String path) throws Exception {
        System.out.println("========== Parsing: " + path + " ==========");
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
            System.out.println("certChain(initiator)=" + dto.getInitiatorCertificates().size() + " list=" + dto.getInitiatorCertificates());
            for (IpsecCertificateInfoDto cert : dto.getInitiatorCertificates()) {
                System.out.println("  initiator cert[" + cert.getIndex() + "]: version=" + cert.getVersion()
                        + ", serial=" + cert.getSerialNumber()
                        + ", subject=" + cert.getSubject()
                        + ", issuer=" + cert.getIssuer()
                        + ", notBefore=" + cert.getNotBefore()
                        + ", notAfter=" + cert.getNotAfter()
                        + ", sigAlg=" + cert.getSignatureAlgorithm()
                        + ", pkAlg=" + cert.getPublicKeyAlgorithm()
                        + ", keyUsage=" + cert.getKeyUsage()
                        + ", derLen=" + (cert.getDerBase64() == null ? 0 : cert.getDerBase64().length() * 3 / 4));
            }
            System.out.println("certChain(responder)=" + dto.getResponderCertificates().size());
            for (IpsecCertificateInfoDto cert : dto.getResponderCertificates()) {
                System.out.println("  responder cert[" + cert.getIndex() + "]: version=" + cert.getVersion()
                        + ", serial=" + cert.getSerialNumber()
                        + ", subject=" + cert.getSubject()
                        + ", issuer=" + cert.getIssuer()
                        + ", notBefore=" + cert.getNotBefore()
                        + ", notAfter=" + cert.getNotAfter()
                        + ", sigAlg=" + cert.getSignatureAlgorithm()
                        + ", pkAlg=" + cert.getPublicKeyAlgorithm()
                        + ", keyUsage=" + cert.getKeyUsage()
                        + ", derLen=" + (cert.getDerBase64() == null ? 0 : cert.getDerBase64().length() * 3 / 4));
            }
            System.out.println("notes=" + dto.getNotes());
            System.out.println("messageCount=" + dto.getMessages().size());
            for (int i = 0; i < Math.min(dto.getMessages().size(), 10); i++) {
                Map<String, Object> msg = dto.getMessages().get(i);
                Map<String, Object> h = (Map<String, Object>) msg.get("header");
                String dir = (String) msg.get("direction");
                System.out.println("  msg[" + i + "] dir=" + dir
                        + " exchange=" + (h == null ? "-" : h.get("exchangeType"))
                        + " flags=" + (h == null ? "-" : h.get("flags"))
                        + " next=" + (h == null ? "-" : h.get("nextPayload")));
            }
        }
    }
}
