package com.smtool.module.parse;

import com.smtool.module.cert.CertCheckService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import java.io.File;
import java.nio.file.Files;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class IpsecTrafficParseServiceTest {

    @BeforeAll
    static void setupProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final CertCheckService certCheckService = new CertCheckService();
    private final IpsecTrafficParseService service = new IpsecTrafficParseService(
            new IpsecSessionAnalyzer(new IpsecParseService(), certCheckService),
            new IpsecSessionMapper(),
            certCheckService
    );

    @Test
    void testDemoPcap() throws Exception {
        File pcap = new File("../test/ipsec_session_demo.pcap");
        byte[] data = Files.readAllBytes(pcap.toPath());
        MockMultipartFile file = new MockMultipartFile("file", pcap.getName(),
                "application/vnd.tcpdump.pcap", data);

        IpsecTrafficParseResult result = service.parse(file);
        assertNotNull(result);
        assertTrue(result.getSessionCount() > 0, "应至少解析出 1 个 IKE 会话");
        assertNotNull(result.getSessions().get(0).getProtocolVersion());
    }

    @Test
    void testLinuxSllEspPcap() throws Exception {
        File pcap = new File("../15、客户端访问 后台抓包ipsec.pcap");
        if (!pcap.exists()) {
            System.out.println("跳过测试：未找到 " + pcap.getPath());
            return;
        }
        byte[] data = Files.readAllBytes(pcap.toPath());
        MockMultipartFile file = new MockMultipartFile("file", pcap.getName(),
                "application/vnd.tcpdump.pcap", data);

        IpsecTrafficParseResult result = service.parse(file);
        assertNotNull(result);
        assertTrue(result.getSessionCount() > 0, "应至少解析出 1 个会话");

        long totalDataPlanePackets = result.getSessions().stream()
                .filter(IpsecSessionDto::isHasDataPlane)
                .flatMap(s -> s.getDataPlaneSas().stream())
                .mapToLong(IpsecDataPlaneSaDto::getPacketCount)
                .sum();
        assertTrue(totalDataPlanePackets > 0, "应至少解析出若干 ESP 数据面包");

        // 验证所有 ESP SA 的 SPI 和序列号范围合理
        for (IpsecSessionDto session : result.getSessions()) {
            for (IpsecDataPlaneSaDto sa : session.getDataPlaneSas()) {
                assertNotNull(sa.getSpiHex());
                assertTrue(sa.getPacketCount() > 0);
                assertTrue(sa.getFirstSeq() >= 0);
                assertTrue(sa.getLastSeq() >= sa.getFirstSeq());
            }
        }

        // 验证 IP 分片重组后能从 ISAKMP Certificate payload 中解析出国密 SM2 证书链
        IpsecSessionDto mainSession = result.getSessions().stream()
                .filter(s -> s.getInitiatorCertificates() != null && !s.getInitiatorCertificates().isEmpty())
                .findFirst().orElse(null);
        assertNotNull(mainSession, "应至少有一个会话包含证书链");
        assertTrue(mainSession.getInitiatorCertificates().size() >= 2,
                "发起方应至少解析出 2 张证书（签名证书 + 加密证书）");
        assertTrue(mainSession.getResponderCertificates().size() >= 2,
                "响应方应至少解析出 2 张证书（签名证书 + 加密证书）");

        for (IpsecCertificateInfoDto cert : mainSession.getInitiatorCertificates()) {
            assertNotNull(cert.getDerBase64(), "每张证书都应包含可导出的 DER Base64");
        }
        for (IpsecCertificateInfoDto cert : mainSession.getResponderCertificates()) {
            assertNotNull(cert.getDerBase64(), "每张证书都应包含可导出的 DER Base64");
        }

        // 至少有一张标准 X.509 SM2 证书被正确解析出主题、颁发者和有效期
        boolean hasParsedX509 = mainSession.getInitiatorCertificates().stream()
                .anyMatch(c -> c.getVersion() != null && c.getSubject() != null && c.getIssuer() != null);
        assertTrue(hasParsedX509, "应解析出标准 X.509 证书字段");
    }
}
