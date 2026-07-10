package com.smtool.module.parse;

import com.smtool.util.CodecUtil;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class IsakmpCertificateExtractorTest {

    /** 构造一个最小 ISAKMP 消息：含两个 Certificate Payload（encoding=4 与 encoding=5）。 */
    private byte[] buildSampleIsakmpMessage(byte[]... certDers) {
        // 28 字节 ISAKMP 通用头
        byte[] header = new byte[28];
        // initiator SPI = 0x11...11 (8 bytes)
        for (int i = 0; i < 8; i++) header[i] = 0x11;
        // responder SPI = 0x22...22 (8 bytes)
        for (int i = 8; i < 16; i++) header[i] = 0x22;
        header[16] = 6; // next payload = Certificate
        header[17] = 0x11; // version: major=1 minor=1 (ISAKMP 1.1)
        header[18] = 2; // exchange type = Identity Protection
        header[19] = 0; // flags
        header[20] = 0; header[21] = 0; header[22] = 0; header[23] = 0; // message ID
        // length 占位，后面再算

        List<byte[]> payloads = new ArrayList<>();
        for (int i = 0; i < certDers.length; i++) {
            byte[] der = certDers[i];
            byte[] payload = new byte[4 + 1 + der.length];
            payload[0] = (byte) ((i == certDers.length - 1) ? 0 : 6); // next payload
            payload[1] = 0; // reserved
            int plen = 5 + der.length;
            payload[2] = (byte) ((plen >> 8) & 0xFF);
            payload[3] = (byte) (plen & 0xFF);
            payload[4] = (byte) ((i % 2 == 0) ? 4 : 5); // 4=X.509-Signature, 5=X.509-KeyExchange
            System.arraycopy(der, 0, payload, 5, der.length);
            payloads.add(payload);
        }

        int totalLen = header.length;
        for (byte[] p : payloads) totalLen += p.length;
        header[24] = (byte) ((totalLen >> 24) & 0xFF);
        header[25] = (byte) ((totalLen >> 16) & 0xFF);
        header[26] = (byte) ((totalLen >> 8) & 0xFF);
        header[27] = (byte) (totalLen & 0xFF);

        byte[] message = new byte[totalLen];
        System.arraycopy(header, 0, message, 0, header.length);
        int pos = header.length;
        for (byte[] p : payloads) {
            System.arraycopy(p, 0, message, pos, p.length);
            pos += p.length;
        }
        return message;
    }

    @Test
    void testExtractFromRawMessage() {
        // DER: SEQUENCE { BOOLEAN TRUE }
        byte[] der1 = new byte[]{0x30, 0x03, 0x01, 0x01, (byte) 0xFF};
        byte[] der2 = new byte[]{0x30, 0x03, 0x01, 0x01, 0x00};
        byte[] message = buildSampleIsakmpMessage(der1, der2);

        List<IsakmpCertificateExtractor.ExtractResult> results =
                IsakmpCertificateExtractor.extractCertificates(message);

        assertEquals(2, results.size());
        assertArrayEquals(der1, results.get(0).getDer());
        assertEquals(4, results.get(0).getEncoding());
        assertFalse(results.get(0).isRawDer());
        assertEquals("X.509 Certificate - Signature", results.get(0).getEncodingName());
        assertEquals(0, results.get(0).getPayloadIndex());

        assertArrayEquals(der2, results.get(1).getDer());
        assertEquals(5, results.get(1).getEncoding());
        assertEquals("X.509 Certificate - Key Exchange", results.get(1).getEncodingName());
        assertEquals(1, results.get(1).getPayloadIndex());
    }

    @Test
    void testExtractRawDerGmPrivatePayload() {
        // 国密私有载荷直接以 0x30 开头，不需要 Cert Encoding
        byte[] rawDer = new byte[]{0x30, 0x03, 0x01, 0x01, (byte) 0xFF};
        IsakmpCertificateExtractor.ExtractResult result =
                IsakmpCertificateExtractor.extractFromCertPayloadBody(rawDer);

        assertNotNull(result);
        assertArrayEquals(rawDer, result.getDer());
        assertTrue(result.isRawDer());
        assertEquals(IsakmpCertificateExtractor.CERT_ENCODING_RAW_DER, result.getEncoding());
        assertEquals("Raw DER / GM private certificate", result.getEncodingName());
    }

    @Test
    void testExtractFromParsedPayloads() {
        byte[] der = new byte[]{0x30, 0x03, 0x01, 0x01, (byte) 0xFF};

        List<Map<String, Object>> payloads = new ArrayList<>();
        Map<String, Object> certPayload = new LinkedHashMap<>();
        certPayload.put("payloadTypeCode", 6);
        certPayload.put("data", CodecUtil.toHex(new byte[]{4, (byte) 0x30, 0x03, 0x01, 0x01, (byte) 0xFF}));
        payloads.add(certPayload);

        List<IsakmpCertificateExtractor.ExtractResult> results =
                IsakmpCertificateExtractor.extractFromParsedPayloads(payloads);

        assertEquals(1, results.size());
        assertArrayEquals(der, results.get(0).getDer());
        assertEquals(4, results.get(0).getEncoding());
    }

    @Test
    void testEmptyOrInvalidPayload() {
        assertTrue(IsakmpCertificateExtractor.extractCertificates(new byte[0]).isEmpty());
        assertTrue(IsakmpCertificateExtractor.extractCertificates(null).isEmpty());
        assertNull(IsakmpCertificateExtractor.extractFromCertPayloadBody(new byte[0]));
        assertNull(IsakmpCertificateExtractor.extractFromCertPayloadBody(null));
    }

    @Test
    void testEncodingName() {
        assertEquals("X.509 Certificate - Signature",
                IsakmpCertificateExtractor.encodingName(4));
        assertEquals("X.509 Certificate - Key Exchange",
                IsakmpCertificateExtractor.encodingName(5));
        assertEquals("Raw DER / GM private certificate",
                IsakmpCertificateExtractor.encodingName(0x100));
        assertTrue(IsakmpCertificateExtractor.encodingName(99).contains("Unknown"));
    }

    @Test
    void testIsParseableX509Encoding() {
        assertTrue(IsakmpCertificateExtractor.isParseableX509Encoding(4));
        assertTrue(IsakmpCertificateExtractor.isParseableX509Encoding(5));
        assertTrue(IsakmpCertificateExtractor.isParseableX509Encoding(7));
        assertTrue(IsakmpCertificateExtractor.isParseableX509Encoding(0x100));
        assertFalse(IsakmpCertificateExtractor.isParseableX509Encoding(1));
        assertFalse(IsakmpCertificateExtractor.isParseableX509Encoding(99));
    }
}
