package com.smtool.module.parse;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TlsSessionAnalyzer 单元测试。
 */
class TlsSessionAnalyzerTest {

    private final TlsParseService tlsParseService = new TlsParseService();
    private final TlsStreamParser tlsStreamParser = new TlsStreamParser();
    private final TlsCertificateExtractor certExtractor = new TlsCertificateExtractor();
    private final TlsSessionAnalyzer analyzer = new TlsSessionAnalyzer(tlsParseService, tlsStreamParser, certExtractor);

    @Test
    void testTls13VersionExtractedFromSupportedVersions() {
        TcpReassemblyService.BidirectionalStream stream = new TcpReassemblyService.BidirectionalStream(
                new TcpReassemblyService.SessionKey("10.0.0.1", 12345, "10.0.0.2", 443));

        // client -> server: ClientHello
        stream.aToB.addSegment(new TcpSegment(100, 0, clientHelloBytes(), 0x18, 0));
        // server -> client: ServerHello (legacy 0x0303 but real version 0x0304 in supported_versions)
        stream.bToA.addSegment(new TcpSegment(200, 0, tls13ServerHelloBytes(), 0x18, 0));

        TlsSession session = analyzer.analyze(stream);
        assertNotNull(session);
        assertTrue(session.isSawServerHello());
        assertEquals(0x0304, session.getServerHelloVersion());
    }

    @Test
    void testGmServerHelloRecognized() {
        TcpReassemblyService.BidirectionalStream stream = new TcpReassemblyService.BidirectionalStream(
                new TcpReassemblyService.SessionKey("10.0.0.1", 12345, "10.0.0.2", 443));

        stream.aToB.addSegment(new TcpSegment(100, 0, clientHelloBytes(), 0x18, 0));
        stream.bToA.addSegment(new TcpSegment(200, 0, gmServerHelloBytes(), 0x18, 0));

        TlsSession session = analyzer.analyze(stream);
        assertNotNull(session);
        assertEquals(0xe013, session.getServerCipherSuite());
        assertEquals(0x0101, session.getServerHelloVersion());
    }

    private byte[] clientHelloBytes() {
        return hexToBytes(
                "1603030031" // record: length=4+45=49
                        + "0100002d" // handshake header: length=45
                        + "0303" // client version
                        + "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef" // random
                        + "00" // session id len
                        + "0004" // cipher suites len
                        + "1302" + "9999" // TLS_AES_256_GCM_SHA384 + unknown
                        + "0100" // compression length=1, method=0
                        + "0000" // extensions len
        );
    }

    private byte[] tls13ServerHelloBytes() {
        return hexToBytes(
                "1603030032"
                        + "0200002e"
                        + "0303" // legacy version TLS 1.2
                        + "abababababababababababababababababababababababababababababababab"
                        + "00"
                        + "1301" // TLS_AES_128_GCM_SHA256
                        + "00"
                        + "0006"
                        + "002b00020304" // supported_versions -> TLS 1.3
        );
    }

    private byte[] gmServerHelloBytes() {
        return hexToBytes(
                "160303002a"
                        + "02000026"
                        + "0101" // TLCP
                        + "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                        + "00"
                        + "e013" // ECDHE_SM4_SM3
                        + "00"
                        + "0002"
                        + "002b00020101"
        );
    }

    private byte[] hexToBytes(String hex) {
        return com.smtool.util.CodecUtil.fromHex(hex);
    }
}
