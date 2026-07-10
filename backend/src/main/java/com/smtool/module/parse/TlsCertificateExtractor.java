package com.smtool.module.parse;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 从 TLS Certificate 握手消息中提取 X.509 证书链 DER。
 * <p>
 * 支持 TLS 1.2 及更早版本的 {@code certificates_length(3) [ cert_length(3) cert_der ... ]} 结构，
 * 以及 TLS 1.3 的 {@code certificate_request_context(1) certificate_list(3) [ cert_length(3) cert_der extensions(2+) ... ]} 结构。
 */
@Component
public class TlsCertificateExtractor {

    /**
     * 解析 Certificate 握手消息负载，根据 payload 特征自动判断是否为 TLS 1.3。
     */
    public List<byte[]> extractCertificates(byte[] payload) {
        return extractCertificates(payload, isTls13CertificatePayload(payload));
    }

    /**
     * 按指定 TLS 版本格式解析 Certificate 握手消息负载。
     *
     * @param payload Certificate 握手消息的 payload（不含 handshake 头）
     * @param tls13   是否按 TLS 1.3 格式解析
     */
    public List<byte[]> extractCertificates(byte[] payload, boolean tls13) {
        List<byte[]> certs = new ArrayList<>();
        if (payload == null || payload.length < 3) {
            return certs;
        }
        int pos = 0;
        int end;
        if (tls13) {
            // TLS 1.3: certificate_request_context length (1) + certificate_list length (3)
            int ctxLen = payload[pos] & 0xff;
            pos += 1 + ctxLen;
            if (pos + 3 > payload.length) {
                return certs;
            }
            int totalLen = readU24(payload, pos);
            pos += 3;
            if (totalLen < 0 || pos + totalLen > payload.length) {
                return certs;
            }
            end = pos + totalLen;
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
                // 跳过该证书附带的 extensions（TLS 1.3）
                if (pos + 2 <= end) {
                    int extLen = ((payload[pos] & 0xff) << 8) | (payload[pos + 1] & 0xff);
                    if (extLen < 0 || pos + 2 + extLen > end) {
                        break;
                    }
                    pos += 2 + extLen;
                }
            }
        } else {
            // TLS 1.2 及以前: certificates_length(3) [ cert_length(3) cert_der ... ]
            int totalLen = readU24(payload, pos);
            pos += 3;
            if (totalLen < 0 || pos + totalLen > payload.length) {
                return certs;
            }
            end = pos + totalLen;
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
        }
        return certs;
    }

    /**
     * 启发式判断 Certificate payload 是否为 TLS 1.3 格式。
     * <p>
     * TLS 1.3 在 certificate_list 前有一个 1 字节的 certificate_request_context 长度字段。
     * 正常握手时该长度为 0，随后 3 字节为 certificate_list 长度。如果按 TLS 1.2 解析时
     * 首个证书长度与后续 DER 结构无法对齐，则回退为 TLS 1.3 解析，并做更严格校验。
     */
    private boolean isTls13CertificatePayload(byte[] payload) {
        if (payload == null || payload.length < 4) {
            return false;
        }
        // 尝试按 TLS 1.2 解析，看是否能对齐出完整证书链
        int totalLen = readU24(payload, 0);
        if (totalLen > 0 && totalLen <= payload.length - 3) {
            int pos = 3;
            int end = pos + totalLen;
            int certsFound = 0;
            while (pos + 3 <= end) {
                int certLen = readU24(payload, pos);
                pos += 3;
                if (certLen <= 0 || pos + certLen > end) {
                    break;
                }
                // 简单校验 DER 是否以 0x30 开头
                if (payload[pos] != 0x30) {
                    break;
                }
                certsFound++;
                pos += certLen;
            }
            if (pos == end && certsFound > 0) {
                return false;
            }
        }
        // TLS 1.3: ctxLen(1) + [ctx] + listLen(3) + [cert_list]
        int ctxLen = payload[0] & 0xff;
        if (ctxLen < 0 || ctxLen > payload.length - 4) {
            return false;
        }
        int listLenPos = 1 + ctxLen;
        int listLen = readU24(payload, listLenPos);
        if (listLen <= 0 || listLen > payload.length - listLenPos - 3) {
            return false;
        }
        int pos = listLenPos + 3;
        int end = pos + listLen;
        int certsFound = 0;
        while (pos + 3 <= end) {
            int certLen = readU24(payload, pos);
            pos += 3;
            if (certLen <= 0 || pos + certLen > end) {
                break;
            }
            if (payload[pos] != 0x30) {
                break;
            }
            certsFound++;
            pos += certLen;
            // 跳过该证书附带的 extensions
            if (pos + 2 <= end) {
                int extLen = ((payload[pos] & 0xff) << 8) | (payload[pos + 1] & 0xff);
                if (extLen < 0 || pos + 2 + extLen > end) {
                    break;
                }
                pos += 2 + extLen;
            }
        }
        return certsFound > 0 && pos <= end + 2;
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
