package com.smtool.module.parse;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TlsParseService 单元测试。
 */
class TlsParseServiceTest {

    private final TlsParseService service = new TlsParseService();

    @Test
    void testParseTls13ServerHelloWithSupportedVersions() {
        // Record: handshake(0x16), legacy_version=0x0303, length=0x0032(50)
        // Handshake: server_hello(0x02), length=0x00002e(46)
        // ServerHello body: version=0x0303, random(32 bytes 0xAB), sessionIdLen=0,
        //   cipherSuite=0x1301, compression=0x00, extensionsLength=0x0006
        // Extension: supported_versions(0x002b), len=2, selected_version=0x0304(TLS1.3)
        String hex = "1603030032" // record header
                + "0200002e" // handshake header
                + "0303" // legacy version
                + "abababababababababababababababababababababababababababababababab" // random (32)
                + "00" // session id len
                + "1301" // TLS_AES_128_GCM_SHA256
                + "00" // compression
                + "0006" // extensions length
                + "002b00020304"; // supported_versions -> TLS 1.3

        TlsParseRequest req = new TlsParseRequest();
        req.setInput(hex);
        req.setFormat("hex");

        Map<String, Object> result = service.parse(req);
        assertFalse(result.containsKey("truncated"), "报文应完整解析");

        @SuppressWarnings("unchecked")
        Map<String, Object> hs = (Map<String, Object>) result.get("handshake");
        assertNotNull(hs);
        assertEquals("server_hello", ((String) hs.get("handshakeType")).split(" ")[1].replace("(", "").replace(")", ""));

        @SuppressWarnings("unchecked")
        Map<String, Object> suite = (Map<String, Object>) hs.get("cipherSuite");
        assertNotNull(suite);
        assertEquals("0x1301", suite.get("value"));
        assertTrue(((String) suite.get("name")).contains("TLS_AES_128_GCM_SHA256"));
        assertFalse((Boolean) suite.get("gm"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> exts = (List<Map<String, Object>>) hs.get("extensions");
        assertNotNull(exts);
        Map<String, Object> sv = exts.stream()
                .filter(e -> ((String) e.get("type")).startsWith("0x002b"))
                .findFirst()
                .orElseThrow();
        assertEquals("0x0304 (TLS 1.3)", sv.get("selectedVersion"));
        assertEquals(0x0304, sv.get("selectedVersionValue"));
    }

    @Test
    void testParseGmServerHello() {
        // ServerHello 选择国密套件 0xe013 ECDHE_SM4_SM3
        String hex = "160303002a"
                + "02000026"
                + "0101" // TLCP version
                + "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" // random
                + "00"
                + "e013" // ECDHE_SM4_SM3
                + "00"
                + "0002"
                + "002b00020101"; // supported_versions -> TLCP

        TlsParseRequest req = new TlsParseRequest();
        req.setInput(hex);
        req.setFormat("hex");

        Map<String, Object> result = service.parse(req);
        assertFalse(result.containsKey("truncated"));

        @SuppressWarnings("unchecked")
        Map<String, Object> hs = (Map<String, Object>) result.get("handshake");
        @SuppressWarnings("unchecked")
        Map<String, Object> suite = (Map<String, Object>) hs.get("cipherSuite");
        assertEquals("0xe013", suite.get("value"));
        assertTrue((Boolean) suite.get("gm"));
        assertTrue(((String) suite.get("name")).contains("ECDHE_SM4_SM3"));
    }

    @Test
    void testParseClientHelloListsUnknownSuite() {
        // ClientHello with two cipher suites: 0x1302 and an unknown 0x9999
        // 握手体长度 = 2(version) + 32(random) + 1(sessionIdLen) + 2(csLen) + 4(cs) + 1(cmLen) + 1(cm) + 2(extLen) = 45 = 0x2d
        String hex = "1603030031"
                + "0100002d"
                + "0303"
                + "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
                + "00" // session id len
                + "0004" // cipher suites length
                + "1302" + "9999" // TLS_AES_256_GCM_SHA384 + unknown
                + "0100" // compression length=1, method=0
                + "0000"; // extensions length=0

        TlsParseRequest req = new TlsParseRequest();
        req.setInput(hex);
        req.setFormat("hex");

        Map<String, Object> result = service.parse(req);
        @SuppressWarnings("unchecked")
        Map<String, Object> hs = (Map<String, Object>) result.get("handshake");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> suites = (List<Map<String, Object>>) hs.get("cipherSuites");
        assertEquals(2, suites.size());
        assertEquals("0x1302", suites.get(0).get("value"));
        assertTrue(((String) suites.get(0).get("name")).contains("TLS_AES_256_GCM_SHA384"));
        assertEquals("0x9999", suites.get(1).get("value"));
        assertEquals("0x9999", suites.get(1).get("name"));
    }
}
