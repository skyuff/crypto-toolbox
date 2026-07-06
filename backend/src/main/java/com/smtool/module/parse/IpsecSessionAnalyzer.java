package com.smtool.module.parse;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 分析一组属于同一会话的 ISAKMP 消息，提取 IKE 协商信息。
 */
@Service
public class IpsecSessionAnalyzer {

    private final IpsecParseService ipsecParseService;

    public IpsecSessionAnalyzer(IpsecParseService ipsecParseService) {
        this.ipsecParseService = ipsecParseService;
    }

    /**
     * 分析一个会话分组内的所有 UDP 包，返回填充后的 IpsecSession。
     */
    public IpsecSession analyze(String sessionKey, List<PcapPacket> packets) {
        IpsecSession session = new IpsecSession();
        session.setSessionKey(sessionKey);

        if (packets == null || packets.isEmpty()) {
            return session;
        }

        // 用第一条消息确定发起方
        PcapPacket first = packets.get(0);
        byte[] firstPayload = extractIsakmpPayload(first);
        Map<String, Object> firstParsed = ipsecParseService.parseMessage(firstPayload);
        Map<String, Object> firstHeader = (Map<String, Object>) firstParsed.get("header");
        String firstFlags = firstHeader != null ? (String) firstHeader.get("flags") : "";
        boolean sourceIsInitiator = true;
        if (firstFlags != null) {
            boolean isInitiatorFlag = firstFlags.contains("Initiator");
            boolean isResponseFlag = firstFlags.contains("Response");
            if (isInitiatorFlag && !isResponseFlag) {
                sourceIsInitiator = true;
            } else if (!isInitiatorFlag && isResponseFlag) {
                sourceIsInitiator = false;
            }
        }

        if (sourceIsInitiator) {
            session.setInitiatorIp(first.getSrcIp());
            session.setInitiatorPort(first.getSrcPort());
            session.setResponderIp(first.getDstIp());
            session.setResponderPort(first.getDstPort());
        } else {
            session.setInitiatorIp(first.getDstIp());
            session.setInitiatorPort(first.getDstPort());
            session.setResponderIp(first.getSrcIp());
            session.setResponderPort(first.getSrcPort());
        }

        for (PcapPacket pkt : packets) {
            byte[] isakmp = extractIsakmpPayload(pkt);
            Map<String, Object> parsed = ipsecParseService.parseMessage(isakmp);
            Map<String, Object> header = (Map<String, Object>) parsed.get("header");

            String direction;
            if (pkt.getSrcIp().equals(session.getInitiatorIp()) && pkt.getSrcPort() == session.getInitiatorPort()) {
                direction = "initiator";
            } else {
                direction = "responder";
            }
            parsed.put("direction", direction);
            session.getMessages().add(parsed);

            if (header != null) {
                processHeader(session, header);
                List<Map<String, Object>> payloads = (List<Map<String, Object>>) parsed.get("payloads");
                if (payloads != null) {
                    for (Map<String, Object> p : payloads) {
                        processPayload(session, direction, p);
                    }
                }
            }
        }

        deriveSelectedAlgorithms(session);
        session.setGm(detectGm(session));
        return session;
    }

    /** 从 UDP payload 中提取 ISAKMP 消息（处理 NAT-T Non-ESP Marker）。 */
    private byte[] extractIsakmpPayload(PcapPacket pkt) {
        byte[] payload = pkt.getPayload();
        if (payload == null) {
            return new byte[0];
        }
        // UDP/4500 的 IKE 消息前 4 字节为 0x00 00 00 00（Non-ESP Marker）
        if (pkt.getSrcPort() == 4500 || pkt.getDstPort() == 4500) {
            if (payload.length > 4 && payload[0] == 0 && payload[1] == 0 && payload[2] == 0 && payload[3] == 0) {
                byte[] stripped = new byte[payload.length - 4];
                System.arraycopy(payload, 4, stripped, 0, stripped.length);
                return stripped;
            }
        }
        return payload;
    }

    private void processHeader(IpsecSession session, Map<String, Object> header) {
        String version = (String) header.get("version");
        if (version != null && session.getIkeVersion() == null) {
            if (version.contains("IKEv2")) {
                session.setIkeVersion("IKEv2");
            } else if (version.contains("IKEv1")) {
                session.setIkeVersion("IKEv1");
            } else {
                session.setIkeVersion("IKE");
            }
        }

        String initiatorSpi = (String) header.get("initiatorSpi");
        if (initiatorSpi != null && session.getInitiatorSpi() == null) {
            session.setInitiatorSpi(initiatorSpi);
        }

        String responderSpi = (String) header.get("responderSpi");
        if (responderSpi != null && !isAllZeroSpi(responderSpi) && session.getResponderSpi() == null) {
            session.setResponderSpi(responderSpi);
        }

        String exchangeType = (String) header.get("exchangeType");
        if (exchangeType != null && !session.getExchangeTypes().contains(exchangeType)) {
            session.getExchangeTypes().add(exchangeType);
        }

        String messageId = (String) header.get("messageId");
        if (messageId != null && !session.getMessageIds().contains(messageId)) {
            session.getMessageIds().add(messageId);
        }
    }

    private boolean isAllZeroSpi(String hex) {
        return hex != null && hex.replaceAll("0", "").isEmpty();
    }

    private void processPayload(IpsecSession session, String direction, Map<String, Object> payload) {
        Integer codeObj = (Integer) payload.get("payloadTypeCode");
        String dataHex = (String) payload.get("data");
        if (codeObj == null || dataHex == null) {
            return;
        }
        int code = codeObj;
        byte[] body = CodecUtil.fromHex(dataHex);
        boolean isInitiator = "initiator".equals(direction);
        boolean isV2 = "IKEv2".equals(session.getIkeVersion());

        switch (code) {
            case 33 -> { // IKEv2 SA
                if (isV2) processSaPayloadV2(body, session, isInitiator);
                else processSaPayloadV1(body, session, isInitiator);
            }
            case 1 -> { // IKEv1 SA
                processSaPayloadV1(body, session, isInitiator);
            }
            case 34, 4 -> { // KE
                processKePayload(body, session, isInitiator);
            }
            case 35, 5 -> { // IDi / ID (v1)
                processIdPayload(body, session, true, isV2);
            }
            case 36 -> { // IDr
                processIdPayload(body, session, false, isV2);
            }
            case 39, 9, 10 -> { // AUTH / SIG / HASH
                processAuthPayload(body, session, isV2);
            }
            case 37, 6 -> { // CERT
                processCertPayload(body, session);
            }
            case 43, 13 -> { // Vendor ID
                processVendorId(body, session);
            }
            case 41, 11 -> { // Notify
                processNotifyPayload(body, session, isV2);
            }
            case 42, 12 -> { // Delete
                processDeletePayload(body, session, isV2);
            }
            default -> {
                // 未知 payload 不处理
            }
        }
    }

    // ==================== SA 解析（IKEv2） ====================

    private void processSaPayloadV2(byte[] body, IpsecSession session, boolean isInitiator) {
        ByteReader r = new ByteReader(body);
        while (r.has(8)) {
            int last = r.u8();
            r.u8(); // reserved
            int proposalLength = r.u16();
            if (proposalLength < 8 || !r.has(proposalLength - 4)) {
                break;
            }
            r.u8(); // proposal number
            int protocolId = r.u8();
            int spiSize = r.u8();
            int transformCount = r.u8();
            if (spiSize > 0) {
                r.bytes(spiSize);
            }
            int transformBytesRead = 0;
            int maxTransformBytes = proposalLength - 8 - spiSize;
            for (int i = 0; i < transformCount && transformBytesRead < maxTransformBytes; i++) {
                int tLast = r.u8();
                r.u8(); // reserved
                int tLen = r.u16();
                if (tLen < 8 || !r.has(tLen - 4)) {
                    break;
                }
                int tType = r.u8();
                r.u8(); // reserved
                int tId = r.u16();
                int attrLen = tLen - 8;
                if (attrLen > 0) {
                    r.bytes(attrLen);
                }
                transformBytesRead += tLen;
                String name = resolveTransformName(tType, tId);
                addAlgorithm(session, isInitiator, tType, name);
            }
            // 只解析第一个 proposal（通常只有一个）
            if (last != 0) {
                break;
            }
        }
    }

    // ==================== SA 解析（IKEv1，简化） ====================

    private void processSaPayloadV1(byte[] body, IpsecSession session, boolean isInitiator) {
        ByteReader r = new ByteReader(body);
        // IKEv1 SA payload 内嵌 Proposal (2) / Transform (3) 子结构
        while (r.has(8)) {
            int next = r.u8();
            r.u8(); // reserved
            int length = r.u16();
            if (length < 8 || !r.has(length - 4)) {
                break;
            }
            int payloadType = r.u8();
            int proposalNumber = r.u8();
            int protocolId = r.u8();
            int spiSize = r.u8();
            int transformCount = r.u8();
            if (spiSize > 0) {
                r.bytes(spiSize);
            }
            int innerRead = 0;
            int innerMax = length - 8 - spiSize;
            for (int i = 0; i < transformCount && innerRead < innerMax; i++) {
                int tNext = r.u8();
                r.u8();
                int tLen = r.u16();
                if (tLen < 8 || !r.has(tLen - 4)) {
                    break;
                }
                int tType = r.u8();
                r.u8();
                int tId = r.u16();
                int attrLen = tLen - 8;
                if (attrLen > 0) {
                    r.bytes(attrLen);
                }
                innerRead += tLen;
                String name = resolveTransformName(tType, tId);
                addAlgorithm(session, isInitiator, tType, name);
            }
            if (next == 0 || payloadType != 2) {
                break;
            }
        }
    }

    private void addAlgorithm(IpsecSession session, boolean isInitiator, int type, String name) {
        if (name == null || name.isBlank()) {
            return;
        }
        switch (type) {
            case 1 -> {
                if (isInitiator) addUnique(session.getInitiatorProposalsEncryption(), name);
                else addUnique(session.getResponderProposalsEncryption(), name);
            }
            case 2 -> {
                if (isInitiator) addUnique(session.getInitiatorProposalsPrf(), name);
                else addUnique(session.getResponderProposalsPrf(), name);
            }
            case 3 -> {
                if (isInitiator) addUnique(session.getInitiatorProposalsIntegrity(), name);
                else addUnique(session.getResponderProposalsIntegrity(), name);
            }
            case 4 -> {
                if (isInitiator) addUnique(session.getInitiatorProposalsDhGroup(), name);
                else addUnique(session.getResponderProposalsDhGroup(), name);
            }
        }
    }

    private void addUnique(List<String> list, String value) {
        if (!list.contains(value)) {
            list.add(value);
        }
    }

    private String resolveTransformName(int type, int id) {
        return switch (type) {
            case 1 -> ENCR_MAP.getOrDefault(id, "ENCR_" + id);
            case 2 -> PRF_MAP.getOrDefault(id, "PRF_" + id);
            case 3 -> INTEG_MAP.getOrDefault(id, "AUTH_" + id);
            case 4 -> DH_MAP.getOrDefault(id, "DH_" + id);
            default -> "Transform(" + type + "/" + id + ")";
        };
    }

    private void processKePayload(byte[] body, IpsecSession session, boolean isInitiator) {
        if (body.length < 2) {
            return;
        }
        int group = ((body[0] & 0xff) << 8) | (body[1] & 0xff);
        String name = DH_MAP.getOrDefault(group, "DH_" + group);
        if (isInitiator) addUnique(session.getInitiatorProposalsDhGroup(), name);
        else addUnique(session.getResponderProposalsDhGroup(), name);
    }

    private void processIdPayload(byte[] body, IpsecSession session, boolean isInitiatorId, boolean isV2) {
        if (body.length < 4) {
            return;
        }
        int idType = body[0] & 0xff;
        byte[] idData = new byte[body.length - 4];
        System.arraycopy(body, 4, idData, 0, idData.length);
        String typeName = ID_TYPE_MAP.getOrDefault(idType, "ID_" + idType);
        String value = tryDecodeIdentity(idType, idData);
        String identity = typeName + ": " + value;
        if (isInitiatorId) {
            session.setInitiatorIdentity(identity);
        } else {
            session.setResponderIdentity(identity);
        }
    }

    private String tryDecodeIdentity(int idType, byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        // ID_FQDN (2), ID_RFC822_ADDR (3) 等可尝试 UTF-8/ASCII
        if (idType == 2 || idType == 3) {
            return new String(data, StandardCharsets.UTF_8);
        }
        return CodecUtil.toHex(data);
    }

    private void processAuthPayload(byte[] body, IpsecSession session, boolean isV2) {
        if (body.length < 1) {
            return;
        }
        int method = body[0] & 0xff;
        session.setAuthMethod(AUTH_METHOD_MAP.getOrDefault(method, "Auth_" + method));
    }

    private void processCertPayload(byte[] body, IpsecSession session) {
        if (body.length < 1) {
            return;
        }
        byte[] der = new byte[body.length - 1];
        System.arraycopy(body, 1, der, 0, der.length);
        if (der.length > 0) {
            session.getCertificateDerBase64().add(Base64.getEncoder().encodeToString(der));
        }
    }

    private void processVendorId(byte[] body, IpsecSession session) {
        if (body.length > 0) {
            addUnique(session.getVendorIds(), CodecUtil.toHex(body));
        }
    }

    private void processNotifyPayload(byte[] body, IpsecSession session, boolean isV2) {
        if (isV2) {
            if (body.length < 4) {
                return;
            }
            int type = ((body[2] & 0xff) << 8) | (body[3] & 0xff);
            addUnique(session.getNotifyTypes(), NOTIFY_TYPE_MAP.getOrDefault(type, "Notify_" + type));
        } else {
            if (body.length < 8) {
                return;
            }
            int type = ((body[6] & 0xff) << 8) | (body[7] & 0xff);
            addUnique(session.getNotifyTypes(), NOTIFY_TYPE_MAP.getOrDefault(type, "Notify_" + type));
        }
    }

    private void processDeletePayload(byte[] body, IpsecSession session, boolean isV2) {
        if (body.length < 4) {
            return;
        }
        int protocolId = body[0] & 0xff;
        addUnique(session.getDeleteTypes(), PROTOCOL_ID_MAP.getOrDefault(protocolId, "Proto_" + protocolId));
    }

    private void deriveSelectedAlgorithms(IpsecSession session) {
        // IKEv2 响应方 SA payload 中通常携带选中的算法；否则取首个共同算法，最后兜底发起方首个提案
        session.setSelectedEncryption(pickAlgorithm(session.getResponderProposalsEncryption(), session.getInitiatorProposalsEncryption()));
        session.setSelectedIntegrity(pickAlgorithm(session.getResponderProposalsIntegrity(), session.getInitiatorProposalsIntegrity()));
        session.setSelectedPrf(pickAlgorithm(session.getResponderProposalsPrf(), session.getInitiatorProposalsPrf()));
        session.setSelectedDhGroup(pickAlgorithm(session.getResponderProposalsDhGroup(), session.getInitiatorProposalsDhGroup()));
    }

    private String pickAlgorithm(List<String> responderList, List<String> initiatorList) {
        if (responderList != null && !responderList.isEmpty()) {
            return responderList.get(0);
        }
        String common = firstCommon(initiatorList, responderList);
        if (common != null) {
            return common;
        }
        if (initiatorList != null && !initiatorList.isEmpty()) {
            return initiatorList.get(0);
        }
        return null;
    }

    private String firstCommon(List<String> a, List<String> b) {
        if (a == null || b == null) {
            return null;
        }
        for (String s : a) {
            if (b.contains(s)) {
                return s;
            }
        }
        return null;
    }

    private boolean detectGm(IpsecSession session) {
        return containsGm(session.getSelectedEncryption())
                || containsGm(session.getSelectedIntegrity())
                || containsGm(session.getSelectedPrf())
                || containsGm(session.getSelectedDhGroup())
                || containsGm(session.getInitiatorIdentity())
                || containsGm(session.getResponderIdentity())
                || session.getVendorIds().stream().anyMatch(v -> v.toLowerCase().startsWith("sm"));
    }

    private boolean containsGm(String s) {
        if (s == null) {
            return false;
        }
        String lower = s.toLowerCase();
        return lower.contains("sm2") || lower.contains("sm3") || lower.contains("sm4");
    }

    // ==================== 常量映射表 ====================

    private static final Map<Integer, String> ENCR_MAP = new LinkedHashMap<>();
    private static final Map<Integer, String> PRF_MAP = new LinkedHashMap<>();
    private static final Map<Integer, String> INTEG_MAP = new LinkedHashMap<>();
    private static final Map<Integer, String> DH_MAP = new LinkedHashMap<>();
    private static final Map<Integer, String> AUTH_METHOD_MAP = new LinkedHashMap<>();
    private static final Map<Integer, String> ID_TYPE_MAP = new LinkedHashMap<>();
    private static final Map<Integer, String> NOTIFY_TYPE_MAP = new LinkedHashMap<>();
    private static final Map<Integer, String> PROTOCOL_ID_MAP = new LinkedHashMap<>();

    static {
        ENCR_MAP.put(1, "DES-IV64");
        ENCR_MAP.put(2, "DES");
        ENCR_MAP.put(3, "3DES");
        ENCR_MAP.put(4, "RC5");
        ENCR_MAP.put(5, "IDEA");
        ENCR_MAP.put(6, "CAST");
        ENCR_MAP.put(7, "BLOWFISH");
        ENCR_MAP.put(8, "3IDEA");
        ENCR_MAP.put(9, "DES-IV32");
        ENCR_MAP.put(11, "NULL");
        ENCR_MAP.put(12, "AES-CBC");
        ENCR_MAP.put(13, "AES-CTR");
        ENCR_MAP.put(14, "AES-GCM-16");
        ENCR_MAP.put(15, "AES-GCM-12");
        ENCR_MAP.put(16, "AES-CCM-16");
        ENCR_MAP.put(17, "AES-CCM-12");
        ENCR_MAP.put(18, "AES-CCM-8");
        ENCR_MAP.put(19, "AES-GCM-8");
        ENCR_MAP.put(20, "SM4-CBC（国密）");
        ENCR_MAP.put(21, "SM4-CTR（国密）");

        PRF_MAP.put(1, "PRF-HMAC-SHA1");
        PRF_MAP.put(2, "PRF-HMAC-SHA256");
        PRF_MAP.put(3, "PRF-HMAC-SHA384");
        PRF_MAP.put(4, "PRF-HMAC-SHA512");
        PRF_MAP.put(5, "PRF-HMAC-MD5");
        PRF_MAP.put(6, "PRF-HMAC-TIGER");
        PRF_MAP.put(7, "PRF-AES128-XCBC");
        PRF_MAP.put(8, "PRF-SM3（国密）");

        INTEG_MAP.put(1, "AUTH-HMAC-SHA1-96");
        INTEG_MAP.put(2, "AUTH-HMAC-SHA1-128");
        INTEG_MAP.put(3, "AUTH-HMAC-SHA256-128");
        INTEG_MAP.put(4, "AUTH-HMAC-SHA384-192");
        INTEG_MAP.put(5, "AUTH-HMAC-SHA512-256");
        INTEG_MAP.put(6, "AUTH-HMAC-MD5-96");
        INTEG_MAP.put(7, "AUTH-HMAC-SHA256-128");
        INTEG_MAP.put(8, "AUTH-SM3-96（国密）");
        INTEG_MAP.put(12, "AES-GMAC-16");
        INTEG_MAP.put(13, "AES-GMAC-12");
        INTEG_MAP.put(14, "AES-GMAC-8");
        INTEG_MAP.put(15, "AES-GMAC-16");

        DH_MAP.put(1, "MODP-768");
        DH_MAP.put(2, "MODP-1024");
        DH_MAP.put(5, "MODP-1536");
        DH_MAP.put(14, "MODP-2048");
        DH_MAP.put(15, "MODP-3072");
        DH_MAP.put(16, "MODP-4096");
        DH_MAP.put(19, "ECP-256");
        DH_MAP.put(20, "ECP-384");
        DH_MAP.put(21, "ECP-521");
        DH_MAP.put(24, "ECP-192");
        DH_MAP.put(31, "SM2-256（国密）");

        AUTH_METHOD_MAP.put(1, "RSA Digital Signature");
        AUTH_METHOD_MAP.put(2, "Shared Key Message Integrity");
        AUTH_METHOD_MAP.put(3, "DSS Digital Signature");
        AUTH_METHOD_MAP.put(9, "ECDSA with SHA-256");
        AUTH_METHOD_MAP.put(10, "ECDSA with SHA-384");
        AUTH_METHOD_MAP.put(11, "ECDSA with SHA-512");
        AUTH_METHOD_MAP.put(12, "Generic Secure Password Authentication Method");
        AUTH_METHOD_MAP.put(13, "NULL Authentication");
        AUTH_METHOD_MAP.put(14, "Digital Signature");

        ID_TYPE_MAP.put(1, "ID_IPV4_ADDR");
        ID_TYPE_MAP.put(2, "ID_FQDN");
        ID_TYPE_MAP.put(3, "ID_RFC822_ADDR");
        ID_TYPE_MAP.put(5, "ID_IPV6_ADDR");
        ID_TYPE_MAP.put(9, "ID_DER_ASN1_DN");
        ID_TYPE_MAP.put(10, "ID_DER_ASN1_GN");
        ID_TYPE_MAP.put(11, "ID_KEY_ID");

        NOTIFY_TYPE_MAP.put(1, "UNSUPPORTED_CRITICAL_PAYLOAD");
        NOTIFY_TYPE_MAP.put(4, "INVALID_IKE_SPI");
        NOTIFY_TYPE_MAP.put(5, "INVALID_MAJOR_VERSION");
        NOTIFY_TYPE_MAP.put(7, "INVALID_SYNTAX");
        NOTIFY_TYPE_MAP.put(8, "INVALID_MESSAGE_ID");
        NOTIFY_TYPE_MAP.put(9, "INVALID_SPI");
        NOTIFY_TYPE_MAP.put(11, "INVALID_KE_PAYLOAD");
        NOTIFY_TYPE_MAP.put(14, "NO_ADDITIONAL_SAS");
        NOTIFY_TYPE_MAP.put(15, "INTERNAL_ADDRESS_FAILURE");
        NOTIFY_TYPE_MAP.put(16, "FAILED_CP_REQUIRED");
        NOTIFY_TYPE_MAP.put(17, "TS_UNACCEPTABLE");
        NOTIFY_TYPE_MAP.put(18, "INVALID_SELECTORS");
        NOTIFY_TYPE_MAP.put(23, "NAT_DETECTION_SOURCE_IP");
        NOTIFY_TYPE_MAP.put(24, "NAT_DETECTION_DESTINATION_IP");
        NOTIFY_TYPE_MAP.put(25, "COOKIE");
        NOTIFY_TYPE_MAP.put(26, "USE_TRANSPORT_MODE");
        NOTIFY_TYPE_MAP.put(27, "HTTP_CERT_LOOKUP_SUPPORTED");
        NOTIFY_TYPE_MAP.put(28, "REKEY_SA");
        NOTIFY_TYPE_MAP.put(29, "ESP_TFC_PADDING_NOT_SUPPORTED");
        NOTIFY_TYPE_MAP.put(30, "NON_FIRST_FRAGMENTS_ALSO");
        NOTIFY_TYPE_MAP.put(16385, "IKE_SA_ESTABLISHED");

        PROTOCOL_ID_MAP.put(1, "ISAKMP/IKE");
        PROTOCOL_ID_MAP.put(2, "AH");
        PROTOCOL_ID_MAP.put(3, "ESP");
    }
}
