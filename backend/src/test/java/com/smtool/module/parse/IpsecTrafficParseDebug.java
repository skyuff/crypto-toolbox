package com.smtool.module.parse;

import org.springframework.mock.web.MockMultipartFile;

import java.io.File;
import java.nio.file.Files;

public class IpsecTrafficParseDebug {

    public static void main(String[] args) throws Exception {
        File pcap = new File("../test/ipsec_session_demo.pcap");
        byte[] data = Files.readAllBytes(pcap.toPath());

        IpsecParseService parseService = new IpsecParseService();
        IpsecSessionAnalyzer analyzer = new IpsecSessionAnalyzer(parseService);
        IpsecSessionMapper mapper = new IpsecSessionMapper();
        IpsecTrafficParseService trafficService = new IpsecTrafficParseService(analyzer, mapper, parseService);

        MockMultipartFile file = new MockMultipartFile("file", "ipsec_session_demo.pcap",
                "application/vnd.tcpdump.pcap", data);
        IpsecTrafficParseResult result = trafficService.parse(file);
        System.out.println("sessions=" + result.getSessionCount());
        for (IpsecSessionDto dto : result.getSessions()) {
            System.out.println("--- DTO ---");
            System.out.println("protocolVersion=" + dto.getProtocolVersion());
            System.out.println("gm=" + dto.isGm());
            System.out.println("initiatorAlgorithms=" + dto.getInitiatorAlgorithms());
            System.out.println("responderAlgorithms=" + dto.getResponderAlgorithms());
            System.out.println("selectedEncryption=" + dto.getSelectedEncryption());
            System.out.println("selectedIntegrity=" + dto.getSelectedIntegrity());
            System.out.println("selectedPrf=" + dto.getSelectedPrf());
            System.out.println("selectedDhGroup=" + dto.getSelectedDhGroup());
            System.out.println("initiatorIdentity=" + dto.getInitiatorIdentity());
            System.out.println("responderIdentity=" + dto.getResponderIdentity());
            System.out.println("authMethod=" + dto.getAuthMethod());
            System.out.println("certificateCount=" + dto.getCertificateCount());
            System.out.println("notifyTypes=" + dto.getNotifyTypes());
        }
    }
}
