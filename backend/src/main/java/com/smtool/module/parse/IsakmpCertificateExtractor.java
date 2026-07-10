package com.smtool.module.parse;

import com.smtool.util.CodecUtil;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 从 ISAKMP (IKEv1/IKEv2) 报文中提取 Certificate Payload 里的 X.509 DER 数据。
 * <p>
 * 严格遵循 RFC 2408 Certificate Payload 结构：
 * <pre>
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Next Payload  |   RESERVED    |         Payload Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Cert Encoding |                                               |
 * +-+-+-+-+-+-+-+-+                                               |
 * ~                       Certificate Data                        ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * <ul>
 *   <li>Next Payload（1 字节）：下一个 payload 类型，6 表示还有 Certificate Payload。</li>
 *   <li>Payload Length（2 字节，大端）：本 payload 总长度，含 4 字节通用头。</li>
 *   <li>Cert Encoding（1 字节）：4 = X.509 Certificate - Signature，5 = X.509 Certificate - Key Exchange。</li>
 *   <li>Certificate Data：长度 = Payload Length - 5，为原始 X.509 DER 字节流。</li>
 * </ul>
 * <p>
 * 国密私有实现可能直接以 DER SEQUENCE (0x30) 开头，此时把整个 body 当作原始 DER 处理。
 */
public class IsakmpCertificateExtractor {

    /** RFC 2408: Certificate Payload 类型码 */
    public static final int PAYLOAD_TYPE_CERTIFICATE = 6;

    /** RFC 2408: X.509 Certificate - Signature */
    public static final int CERT_ENCODING_X509_SIGNATURE = 4;
    /** RFC 2408: X.509 Certificate - Key Exchange */
    public static final int CERT_ENCODING_X509_KEY_EXCHANGE = 5;
    /** PKCS #7 wrapped X.509 certificate */
    public static final int CERT_ENCODING_PKCS7 = 7;
    /** PGP Certificate (RFC 2408) */
    public static final int CERT_ENCODING_PGP = 1;
    /** DNS Signed Key (RFC 2408) */
    public static final int CERT_ENCODING_DNS_SIGNED_KEY = 2;
    /** Kerberos Tokens (RFC 2408) */
    public static final int CERT_ENCODING_KERBEROS = 3;
    /** Revocation List (RFC 2408) */
    public static final int CERT_ENCODING_REVOCATION_LIST = 8;
    /** Authority Revocation List (RFC 2408) */
    public static final int CERT_ENCODING_AUTH_REVOCATION_LIST = 9;
    /** SPKI Certificate (RFC 2408) */
    public static final int CERT_ENCODING_SPKI = 10;
    /** X.509 Certificate Attribute (RFC 2408) */
    public static final int CERT_ENCODING_X509_ATTRIBUTE = 11;
    /** Raw DER / 国密私有证书载荷（非 RFC 2408 标准编码） */
    public static final int CERT_ENCODING_RAW_DER = 0x100;

    /**
     * 单条证书提取结果。
     */
    public static class ExtractResult {
        private final byte[] der;
        private final int encoding;
        private final String encodingName;
        private final boolean rawDer;
        private final int payloadIndex;

        public ExtractResult(byte[] der, int encoding, String encodingName, boolean rawDer, int payloadIndex) {
            this.der = der;
            this.encoding = encoding;
            this.encodingName = encodingName;
            this.rawDer = rawDer;
            this.payloadIndex = payloadIndex;
        }

        /** 提取出的 X.509 DER 字节流（可直接交给 X.509 解析器）。 */
        public byte[] getDer() {
            return der;
        }

        /** RFC 2408 证书编码值，或 {@link #CERT_ENCODING_RAW_DER}。 */
        public int getEncoding() {
            return encoding;
        }

        /** 编码值的可读名称。 */
        public String getEncodingName() {
            return encodingName;
        }

        /** 是否为直接以 0x30 开头的原始 DER（国密私有载荷常见）。 */
        public boolean isRawDer() {
            return rawDer;
        }

        /** 该证书在 ISAKMP payload 链中的顺序（从 0 开始）。 */
        public int getPayloadIndex() {
            return payloadIndex;
        }

        /** DER 字节长度。 */
        public int getDerLength() {
            return der == null ? 0 : der.length;
        }
    }

    /**
     * 从完整 ISAKMP 消息中提取所有 Certificate Payload 里的 DER 数据。
     *
     * @param isakmpMessage ISAKMP 消息字节（含 28 字节通用头）
     * @return 提取结果列表；不会返回 null
     */
    public static List<ExtractResult> extractCertificates(byte[] isakmpMessage) {
        List<ExtractResult> results = new ArrayList<>();
        if (isakmpMessage == null || isakmpMessage.length < 28) {
            return results;
        }

        int nextPayload = isakmpMessage[16] & 0xFF;
        long length = ((isakmpMessage[24] & 0xFFL) << 24)
                | ((isakmpMessage[25] & 0xFFL) << 16)
                | ((isakmpMessage[26] & 0xFFL) << 8)
                | (isakmpMessage[27] & 0xFFL);
        if (length > isakmpMessage.length) {
            // 长度字段异常，按实际长度解析
            length = isakmpMessage.length;
        }

        int pos = 28;
        int index = 0;
        int guard = 0;
        while (nextPayload == PAYLOAD_TYPE_CERTIFICATE && pos + 4 <= length && guard++ < 64) {
            int thisNext = isakmpMessage[pos] & 0xFF;
            int reserved = isakmpMessage[pos + 1] & 0xFF;
            int payloadLength = ((isakmpMessage[pos + 2] & 0xFF) << 8) | (isakmpMessage[pos + 3] & 0xFF);
            if (payloadLength < 5 || pos + payloadLength > length) {
                break;
            }

            int bodyOffset = pos + 4;
            int bodyLen = payloadLength - 4;
            byte[] body = new byte[bodyLen];
            System.arraycopy(isakmpMessage, bodyOffset, body, 0, bodyLen);

            ExtractResult result = extractFromCertPayloadBody(body, index);
            if (result != null) {
                results.add(result);
            }

            pos += payloadLength;
            nextPayload = thisNext;
            index++;
        }
        return results;
    }

    /**
     * 从单个 Certificate Payload body（已去掉 4 字节通用头）中提取 DER。
     * <p>
     * 处理三种常见情况：
     * <ol>
     *   <li>body 以 0x30 开头：视为原始 DER（国密私有载荷）。</li>
     *   <li>body 首字节为 4/5：RFC 2408 X.509 Certificate，后接 DER。</li>
     *   <li>其他编码：目前仅记录，不返回可解析 DER。</li>
     * </ol>
     *
     * @param body Certificate Payload body（含 Cert Encoding 字节）
     * @return 提取结果；若无法识别编码则返回 null
     */
    public static ExtractResult extractFromCertPayloadBody(byte[] body) {
        return extractFromCertPayloadBody(body, 0);
    }

    private static ExtractResult extractFromCertPayloadBody(byte[] body, int payloadIndex) {
        if (body == null || body.length < 1) {
            return null;
        }

        // 国密私有证书载荷通常直接以 DER SEQUENCE (0x30) 开头
        if (body[0] == 0x30) {
            return new ExtractResult(body, CERT_ENCODING_RAW_DER, "Raw DER / GM private certificate", true, payloadIndex);
        }

        int encoding = body[0] & 0xFF;
        if (body.length < 2) {
            return null;
        }
        byte[] der = new byte[body.length - 1];
        System.arraycopy(body, 1, der, 0, der.length);

        String encodingName = encodingName(encoding);
        if (encoding == CERT_ENCODING_X509_SIGNATURE || encoding == CERT_ENCODING_X509_KEY_EXCHANGE) {
            return new ExtractResult(der, encoding, encodingName, false, payloadIndex);
        }
        // 其他编码目前也返回 DER，但标记为未知编码，由调用方决定是否解析
        return new ExtractResult(der, encoding, encodingName, false, payloadIndex);
    }

    /**
     * 从已解析的 ISAKMP payload 列表（{@link IpsecParseService} 输出）中提取所有证书 DER。
     *
     * @param payloads parseMessage/parsePayloadChain 返回的 payload 列表
     * @return 提取结果列表
     */
    public static List<ExtractResult> extractFromParsedPayloads(List<Map<String, Object>> payloads) {
        List<ExtractResult> results = new ArrayList<>();
        if (payloads == null) {
            return results;
        }
        int index = 0;
        for (Map<String, Object> p : payloads) {
            Integer codeObj = (Integer) p.get("payloadTypeCode");
            String dataHex = (String) p.get("data");
            if (codeObj == null || codeObj != PAYLOAD_TYPE_CERTIFICATE || dataHex == null) {
                continue;
            }
            byte[] body = CodecUtil.fromHex(dataHex);
            ExtractResult result = extractFromCertPayloadBody(body, index);
            if (result != null) {
                results.add(result);
            }
            index++;
        }
        return results;
    }

    /**
     * 返回 RFC 2408 证书编码的可读名称。
     */
    public static String encodingName(int encoding) {
        return switch (encoding) {
            case CERT_ENCODING_X509_SIGNATURE -> "X.509 Certificate - Signature";
            case CERT_ENCODING_X509_KEY_EXCHANGE -> "X.509 Certificate - Key Exchange";
            case CERT_ENCODING_PGP -> "PGP Certificate";
            case CERT_ENCODING_DNS_SIGNED_KEY -> "DNS Signed Key";
            case CERT_ENCODING_KERBEROS -> "Kerberos Tokens";
            case CERT_ENCODING_PKCS7 -> "PKCS #7 wrapped X.509 certificate";
            case CERT_ENCODING_REVOCATION_LIST -> "Revocation List";
            case CERT_ENCODING_AUTH_REVOCATION_LIST -> "Authority Revocation List";
            case CERT_ENCODING_SPKI -> "SPKI Certificate";
            case CERT_ENCODING_X509_ATTRIBUTE -> "X.509 Certificate Attribute";
            case CERT_ENCODING_RAW_DER -> "Raw DER / GM private certificate";
            default -> "Unknown encoding (" + encoding + ")";
        };
    }

    /**
     * 判断编码是否为可导出/可解析的 X.509 DER。
     */
    public static boolean isParseableX509Encoding(int encoding) {
        return encoding == CERT_ENCODING_X509_SIGNATURE
                || encoding == CERT_ENCODING_X509_KEY_EXCHANGE
                || encoding == CERT_ENCODING_PKCS7
                || encoding == CERT_ENCODING_RAW_DER;
    }

    /**
     * 构造一段 Certificate Payload 的简要描述（用于调试日志）。
     */
    public static Map<String, Object> describePayload(byte[] certPayloadBody) {
        Map<String, Object> desc = new LinkedHashMap<>();
        if (certPayloadBody == null || certPayloadBody.length < 1) {
            desc.put("valid", false);
            desc.put("reason", "body too short");
            return desc;
        }
        if (certPayloadBody[0] == 0x30) {
            desc.put("encoding", CERT_ENCODING_RAW_DER);
            desc.put("encodingName", encodingName(CERT_ENCODING_RAW_DER));
            desc.put("derLength", certPayloadBody.length);
        } else {
            int encoding = certPayloadBody[0] & 0xFF;
            desc.put("encoding", encoding);
            desc.put("encodingName", encodingName(encoding));
            desc.put("derLength", Math.max(0, certPayloadBody.length - 1));
        }
        desc.put("valid", true);
        return desc;
    }
}
