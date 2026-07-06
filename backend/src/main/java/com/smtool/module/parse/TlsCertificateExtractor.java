package com.smtool.module.parse;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 从 TLS Certificate 握手消息中提取 X.509 证书链 DER。
 */
@Component
public class TlsCertificateExtractor {

    /**
     * 解析 Certificate 握手消息负载。
     * 结构：certificates_length(3) [ cert_length(3) cert_der ... ]
     */
    public List<byte[]> extractCertificates(byte[] payload) {
        List<byte[]> certs = new ArrayList<>();
        if (payload == null || payload.length < 3) {
            return certs;
        }
        int pos = 0;
        int totalLen = readU24(payload, pos);
        pos += 3;
        if (totalLen < 0 || pos + totalLen > payload.length) {
            return certs;
        }
        int end = pos + totalLen;
        while (pos + 3 <= end) {
            int certLen = readU24(payload, pos);
            pos += 3;
            if (certLen < 0 || pos + certLen > end) {
                break;
            }
            byte[] cert = new byte[certLen];
            System.arraycopy(payload, pos, cert, 0, certLen);
            certs.add(cert);
            pos += certLen;
        }
        return certs;
    }

    private static int readU24(byte[] data, int offset) {
        if (offset + 3 > data.length) {
            return -1;
        }
        return ((data[offset] & 0xff) << 16)
                | ((data[offset + 1] & 0xff) << 8)
                | (data[offset + 2] & 0xff);
    }
}
