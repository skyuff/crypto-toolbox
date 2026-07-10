package com.smtool.module.parse;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TlsCertificateExtractor 单元测试。
 */
class TlsCertificateExtractorTest {

    private final TlsCertificateExtractor extractor = new TlsCertificateExtractor();

    @Test
    void testExtractSingleCertificate() {
        byte[] cert1 = new byte[]{0x30, (byte) 0x82, 0x01, 0x00}; // 模拟 DER 前缀
        byte[] payload = buildPayload(cert1);

        List<byte[]> certs = extractor.extractCertificates(payload);
        assertEquals(1, certs.size());
        assertArrayEquals(cert1, certs.get(0));
    }

    @Test
    void testExtractMultipleCertificates() {
        byte[] cert1 = new byte[]{0x30, 0x01, 0x02};
        byte[] cert2 = new byte[]{0x30, 0x03, 0x04, 0x05, 0x06};
        byte[] payload = buildPayload(cert1, cert2);

        List<byte[]> certs = extractor.extractCertificates(payload);
        assertEquals(2, certs.size());
        assertArrayEquals(cert1, certs.get(0));
        assertArrayEquals(cert2, certs.get(1));
    }

    @Test
    void testExtractEmptyPayload() {
        List<byte[]> certs = extractor.extractCertificates(new byte[0]);
        assertTrue(certs.isEmpty());
    }

    @Test
    void testExtractTls13CertificateWithExtensions() {
        byte[] cert1 = new byte[]{0x30, 0x01, 0x02};
        byte[] cert2 = new byte[]{0x30, 0x03, 0x04, 0x05, 0x06};
        byte[] payload = buildTls13Payload(cert1, cert2);

        List<byte[]> certs = extractor.extractCertificates(payload, true);
        assertEquals(2, certs.size());
        assertArrayEquals(cert1, certs.get(0));
        assertArrayEquals(cert2, certs.get(1));
    }

    private byte[] buildTls13Payload(byte[]... certs) {
        int total = 0;
        for (byte[] c : certs) {
            total += 3 + c.length + 2; // cert_len(3) + cert + extensions_len(2) + no extensions
        }
        byte[] payload = new byte[1 + 3 + total]; // ctxLen(1) + listLen(3) + entries
        payload[0] = 0; // certificate_request_context length = 0
        payload[1] = (byte) ((total >> 16) & 0xff);
        payload[2] = (byte) ((total >> 8) & 0xff);
        payload[3] = (byte) (total & 0xff);
        int pos = 4;
        for (byte[] c : certs) {
            payload[pos++] = (byte) ((c.length >> 16) & 0xff);
            payload[pos++] = (byte) ((c.length >> 8) & 0xff);
            payload[pos++] = (byte) (c.length & 0xff);
            System.arraycopy(c, 0, payload, pos, c.length);
            pos += c.length;
            payload[pos++] = 0;
            payload[pos++] = 0; // extensions length = 0
        }
        return payload;
    }

    private byte[] buildPayload(byte[]... certs) {
        int total = 0;
        for (byte[] c : certs) {
            total += 3 + c.length;
        }
        byte[] payload = new byte[3 + total];
        payload[0] = (byte) ((total >> 16) & 0xff);
        payload[1] = (byte) ((total >> 8) & 0xff);
        payload[2] = (byte) (total & 0xff);
        int pos = 3;
        for (byte[] c : certs) {
            payload[pos++] = (byte) ((c.length >> 16) & 0xff);
            payload[pos++] = (byte) ((c.length >> 8) & 0xff);
            payload[pos++] = (byte) (c.length & 0xff);
            System.arraycopy(c, 0, payload, pos, c.length);
            pos += c.length;
        }
        return payload;
    }
}
