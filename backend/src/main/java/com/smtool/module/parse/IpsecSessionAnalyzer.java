package com.smtool.module.parse;

import com.smtool.module.cert.CertCheckService;
import com.smtool.util.CodecUtil;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
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
    private final CertCheckService certCheckService;

    public IpsecSessionAnalyzer(IpsecParseService ipsecParseService, CertCheckService certCheckService) {
        this.ipsecParseService = ipsecParseService;
        this.certCheckService = certCheckService;
    }

    /**
     * 分析一个会话分组内的所有 UDP 包，返回填充后的 IpsecSession。
     */
    public IpsecSession analyze(String sessionKey, List<PcapPacket> packets) {
        return analyze(sessionKey, packets, null);
    }

    /**
     * 分析一个会话分组内的所有 UDP 包，支持使用 IKE 解密密钥日志解密加密载荷。
     */
    public IpsecSession analyze(String sessionKey, List<PcapPacket> packets, List<IpsecKeyLogEntry> keyLogs) {
        IpsecSession session = new IpsecSession();
        session.setSessionKey(sessionKey);

        if (packets == null || packets.isEmpty()) {
            return session;
        }

        DecryptionContext decryptCtx = null;
        if (keyLogs != null && !keyLogs.isEmpty()) {
            decryptCtx = buildDecryptionContext(sessionKey, keyLogs);
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
            parsed.put("timestampMicros", pkt.getTimestampMicros());
            session.getMessages().add(parsed);

            if (header != null) {
                processHeader(session, header);
                List<Map<String, Object>> payloads = (List<Map<String, Object>>) parsed.get("payloads");
                if (payloads != null) {
                    if (decryptCtx != null && isEncryptedHeader(header)) {
                        processEncryptedPayloads(session, direction, payloads, decryptCtx, pkt);
                    } else {
                        for (Map<String, Object> p : payloads) {
                            processPayload(session, direction, p);
                        }
                    }
                }
            }
        }

        deriveSelectedAlgorithms(session);
        session.setGm(detectGm(session));

        // 若会话中仅含加密后的 IKE 消息且未提取到任何协商参数，给出提示便于前端展示
        if (session.getSelectedEncryption() == null
                && session.getSelectedIntegrity() == null
                && session.getSelectedDhGroup() == null
                && session.getMessages() != null
                && !session.getMessages().isEmpty()
                && hasOnlyEncryptedMessages(session)) {
            session.getNotes().add("该会话仅包含加密后的 IKE 消息，无法提取协商参数（需要解密密钥才能进一步解析）");
        }
        return session;
    }

    private boolean hasOnlyEncryptedMessages(IpsecSession session) {
        for (Map<String, Object> msg : session.getMessages()) {
            Map<String, Object> header = (Map<String, Object>) msg.get("header");
            if (header == null) {
                continue;
            }
            String flags = (String) header.get("flags");
            if (flags == null || !flags.contains("Encryption")) {
                return false;
            }
        }
        return true;
    }

    private boolean isEncryptedHeader(Map<String, Object> header) {
        String flags = header != null ? (String) header.get("flags") : null;
        return flags != null && flags.contains("Encryption");
    }

    private DecryptionContext buildDecryptionContext(String sessionKey, List<IpsecKeyLogEntry> keyLogs) {
        String[] parts = sessionKey.split(":");
        if (parts.length < 3) {
            return null;
        }
        String initSpi = parts[1].toLowerCase();
        String respSpi = parts.length > 2 ? parts[2].toLowerCase() : null;
        for (IpsecKeyLogEntry entry : keyLogs) {
            if (entry.matches(initSpi, respSpi)) {
                return new DecryptionContext(entry);
            }
        }
        return null;
    }

    private void processEncryptedPayloads(IpsecSession session, String direction,
                                          List<Map<String, Object>> payloads,
                                          DecryptionContext ctx, PcapPacket pkt) {
        if (payloads.isEmpty()) {
            return;
        }
        Map<String, Object> first = payloads.get(0);
        String dataHex = (String) first.get("data");
        if (dataHex == null) {
            return;
        }
        byte[] encryptedPayload;
        try {
            encryptedPayload = CodecUtil.fromHex(dataHex);
        } catch (Exception e) {
            return;
        }
        if (encryptedPayload.length < 4 + ctx.iv.length + 16) {
            return;
        }

        byte[] plaintext = ctx.decryptor.decrypt(encryptedPayload, ctx.key, ctx.iv);
        if (plaintext == null) {
            session.getNotes().add("Encrypted IKE message decryption failed for packet at " + pkt.getTimestampMicros());
            return;
        }

        // 解析解密后的明文 payload 链
        List<Map<String, Object>> innerPayloads = ipsecParseService.parsePayloadChain(plaintext);
        if (innerPayloads != null) {
            for (Map<String, Object> p : innerPayloads) {
                processPayload(session, direction, p);
            }
        }

        // 更新 CBC IV：当前密文的最后一个分组
        ctx.updateIv(encryptedPayload);
    }

    private static class DecryptionContext {
        final byte[] key;
        byte[] iv;
        final IpsecIkeDecryptor decryptor = new IpsecIkeDecryptor();

        DecryptionContext(IpsecKeyLogEntry entry) {
            this.key = entry.getSkeyidE();
            this.iv = entry.getIv() != null && entry.getIv().length > 0
                    ? entry.getIv().clone()
                    : new byte[16];
        }

        void updateIv(byte[] encryptedPayload) {
            if (encryptedPayload.length >= 4 + 16) {
                // 跳过 generic header，取 ciphertext 的最后一个分组作为下一条消息的 IV
                this.iv = java.util.Arrays.copyOfRange(encryptedPayload,
                        encryptedPayload.length - 16, encryptedPayload.length);
            }
        }
    }

    /** 从 UDP payload 中提取 ISAKMP 消息（处理 NAT-T Non-ESP Marker）。 */
    private byte[] extractIsakmpPayload(PcapPacket pkt) {
        return IpsecParseService.stripNattMarker(pkt.getPayload(), pkt.getSrcPort(), pkt.getDstPort());
    }

    private void processHeader(IpsecSession session, Map<String, Object> header) {
        String version = (String) header.get("version");
        if (version != null && session.getIkeVersion() == null) {
            if (version.contains("IKEv2")) {
                session.setIkeVersion("IKEv2");
            } else if (version.contains("ISAKMP 1.1")) {
                session.setIkeVersion("ISAKMP 1.1");
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
                processKePayload(body, session, isInitiator, isV2);
            }
            case 35 -> { // IDi (IKEv2)
                processIdPayload(body, session, true, isV2);
            }
            case 36 -> { // IDr (IKEv2)
                processIdPayload(body, session, false, isV2);
            }
            case 5 -> { // ID (IKEv1)
                // IKEv1 ID payload 没有 IDi/IDr 之分，根据方向判断
                processIdPayload(body, session, isInitiator, isV2);
            }
            case 39 -> { // IKEv2 AUTH
                processAuthPayload(body, session, isInitiator, true);
            }
            case 8, 9 -> { // IKEv1 HASH / SIG
                processAuthPayload(body, session, isInitiator, false);
            }
            case 40, 10 -> { // IKEv2 / IKEv1 Nonce
                processNoncePayload(body, session, isInitiator);
            }
            case 37, 6, 128 -> { // CERT or private certificate payload
                processCertPayload(body, session, isInitiator);
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
                byte[] attrs = attrLen > 0 ? r.bytes(attrLen) : new byte[0];
                transformBytesRead += tLen;
                String name = resolveTransformName(tType, tId);
                addAlgorithm(session, isInitiator, tType, name);
                applyAttribute(session, tType, name, attrs);
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
        // IKEv1 SA payload body 前 8 字节为 DOI(4) + Situation(4)
        if (r.has(8)) {
            r.bytes(8);
        }
        // 之后内嵌 Proposal (2) / Transform (3) 子结构
        while (r.has(8)) {
            int next = r.u8();
            r.u8(); // reserved
            int length = r.u16();
            if (length < 8 || !r.has(length - 4)) {
                break;
            }
            int proposalNumber = r.u8();
            int protocolId = r.u8();
            int spiSize = r.u8();
            int transformCount = r.u8();
            // ISAKMP/IKE SA proposal (protocolId=1) 没有 SPI，某些实现仍会错误设置 spiSize
            int effectiveSpiSize = (protocolId == 1) ? 0 : spiSize;
            if (effectiveSpiSize > 0 && r.has(effectiveSpiSize)) {
                r.bytes(effectiveSpiSize);
            }
            int innerRead = 0;
            int innerMax = length - 8 - effectiveSpiSize;
            for (int i = 0; i < transformCount && innerRead < innerMax; i++) {
                int tNext = r.u8();
                r.u8();
                int tLen = r.u16();
                if (tLen < 8) {
                    break;
                }
                int tType = r.u8();
                r.u8();
                int tId = r.u16();
                int attrLen = tLen - 8;
                byte[] attrs = attrLen > 0 ? r.bytes(attrLen) : new byte[0];
                innerRead += tLen;
                int extractedAlgId = -1;
                // IKEv1 ISAKMP SA 中 transformId 常为 0，实际算法由属性指定
                if (tId == 0) {
                    extractedAlgId = extractAttributeValue(attrs, tType);
                    // 某些厂商将加密/杂凑/认证/DH 等所有算法属性打包到一个 transform 中
                    if (protocolId == 1) {
                        for (int attrType = 1; attrType <= 4; attrType++) {
                            if (attrType == tType) {
                                continue;
                            }
                            int packedAlgId = extractAttributeValue(attrs, attrType);
                            if (packedAlgId > 0) {
                                addIkev1Algorithm(session, isInitiator, attrType, packedAlgId);
                            }
                        }
                    }
                }
                // 根据实际算法 ID 归类到加密/PRF/完整性/DH/认证方式
                if (tId == 0 && extractedAlgId > 0) {
                    addIkev1Algorithm(session, isInitiator, tType, extractedAlgId);
                } else if (tId != 0) {
                    addIkev1Algorithm(session, isInitiator, tType, tId);
                }
                String name = (tId == 0 && extractedAlgId > 0)
                        ? resolveIkev1AttributeAlgorithm(tType, extractedAlgId)
                        : resolveTransformName(tType, tId);
                applyAttribute(session, tType, name, attrs);
            }
            if (next == 0) {
                break;
            }
        }
    }

    /** 从 IKEv1 Transform 属性中提取指定类型的值（Type/Value 格式）。 */
    private int extractAttributeValue(byte[] attrs, int targetType) {
        if (attrs == null || attrs.length < 4) {
            return -1;
        }
        int pos = 0;
        while (pos + 4 <= attrs.length) {
            int attrType = ((attrs[pos] & 0xff) << 8) | (attrs[pos + 1] & 0xff);
            boolean afBit = (attrType & 0x8000) != 0;
            int type = attrType & 0x7fff;
            if (afBit) {
                int value = ((attrs[pos + 2] & 0xff) << 8) | (attrs[pos + 3] & 0xff);
                if (type == targetType) {
                    return value;
                }
                pos += 4;
            } else {
                int valueLen = ((attrs[pos + 2] & 0xff) << 8) | (attrs[pos + 3] & 0xff);
                pos += 4 + valueLen;
            }
        }
        return -1;
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

    /**
     * 将 IKEv1 Transform/属性中的算法按类型写入对应提案列表。
     * 注意：type=2（Hash/PRF）会同时加入 PRF 与完整性算法；type=3 是认证方式，不混入完整性。
     */
    private void addIkev1Algorithm(IpsecSession session, boolean isInitiator, int type, int id) {
        switch (type) {
            case 1 -> addAlgorithm(session, isInitiator, 1, ENCR_MAP.getOrDefault(id, "ENCR_" + id));
            case 2 -> {
                addAlgorithm(session, isInitiator, 2, PRF_MAP.getOrDefault(id, "PRF_" + id));
                addAlgorithm(session, isInitiator, 3, INTEG_MAP.getOrDefault(id, "AUTH_" + id));
            }
            case 3 -> {
                String name = AUTH_METHOD_V1_MAP.getOrDefault(id, "AUTH_" + id);
                session.setAuthMethod(name);
                session.setSelectedAuthMethod(name);
            }
            case 4 -> addAlgorithm(session, isInitiator, 4, DH_MAP.getOrDefault(id, "DH_" + id));
        }
    }

    /**
     * 从 Transform 属性中提取密钥长度与生命周期，并更新会话。
     */
    private void applyAttribute(IpsecSession session, int transformType, String transformName, byte[] attrs) {
        if (attrs == null || attrs.length < 4) {
            return;
        }
        int pos = 0;
        while (pos + 4 <= attrs.length) {
            int attrType = ((attrs[pos] & 0xff) << 8) | (attrs[pos + 1] & 0xff);
            boolean afBit = (attrType & 0x8000) != 0;
            int type = attrType & 0x7fff;
            if (afBit) {
                // Type/Value 格式：type(2) + value(2)
                int value = ((attrs[pos + 2] & 0xff) << 8) | (attrs[pos + 3] & 0xff);
                if (type == 14 && transformType == 1 && session.getSelectedEncryptionKeyLength() == null) {
                    session.setSelectedEncryptionKeyLength(value);
                } else if (type == 5 && transformType == 1 && session.getSelectedEncryptionKeyLength() == null) {
                    // IKEv1 密钥长度
                    session.setSelectedEncryptionKeyLength(value);
                } else if ((type == 12 || type == 13) && session.getKeyLifetimeSeconds() == null) {
                    // 生命周期（秒），type==12 为 Life Duration，type==13 为 Life Duration (IKEv2)
                    if (value > 0) {
                        session.setKeyLifetimeSeconds((long) value);
                    }
                }
                pos += 4;
            } else {
                // Type/Length 格式：type(2) + length(2) + value(variable)
                int valueLen = ((attrs[pos + 2] & 0xff) << 8) | (attrs[pos + 3] & 0xff);
                if (type == 14 && transformType == 1 && session.getSelectedEncryptionKeyLength() == null && valueLen == 2 && pos + 6 <= attrs.length) {
                    session.setSelectedEncryptionKeyLength(((attrs[pos + 4] & 0xff) << 8) | (attrs[pos + 5] & 0xff));
                } else if (type == 5 && transformType == 1 && session.getSelectedEncryptionKeyLength() == null && valueLen == 2 && pos + 6 <= attrs.length) {
                    session.setSelectedEncryptionKeyLength(((attrs[pos + 4] & 0xff) << 8) | (attrs[pos + 5] & 0xff));
                } else if ((type == 12 || type == 13) && session.getKeyLifetimeSeconds() == null) {
                    long value = 0;
                    for (int i = 0; i < valueLen && pos + 4 + i < attrs.length; i++) {
                        value = (value << 8) | (attrs[pos + 4 + i] & 0xff);
                    }
                    if (value > 0) {
                        session.setKeyLifetimeSeconds(value);
                    }
                }
                pos += 4 + valueLen;
            }
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

    private String resolveIkev1AttributeAlgorithm(int type, int id) {
        return switch (type) {
            case 1 -> ENCR_MAP.getOrDefault(id, "ENCR_" + id);
            case 2 -> PRF_MAP.getOrDefault(id, "PRF_" + id);
            case 3 -> AUTH_METHOD_V1_MAP.getOrDefault(id, "AUTH_" + id);
            case 4 -> DH_MAP.getOrDefault(id, "DH_" + id);
            default -> "Transform(" + type + "/" + id + ")";
        };
    }

    private void processKePayload(byte[] body, IpsecSession session, boolean isInitiator, boolean isV2) {
        if (body.length < 2) {
            return;
        }
        int group = ((body[0] & 0xff) << 8) | (body[1] & 0xff);
        String name = DH_MAP.getOrDefault(group, "DH_" + group);
        if (isInitiator) addUnique(session.getInitiatorProposalsDhGroup(), name);
        else addUnique(session.getResponderProposalsDhGroup(), name);

        // 提取 DH 公钥数据（SK）
        int dataOffset = isV2 ? 4 : 2;
        if (body.length > dataOffset) {
            byte[] keData = new byte[body.length - dataOffset];
            System.arraycopy(body, dataOffset, keData, 0, keData.length);
            String keHex = CodecUtil.toHex(keData);
            if (isInitiator) {
                session.setInitiatorKeData(keHex);
            } else {
                session.setResponderKeData(keHex);
            }
        }
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

    private void processAuthPayload(byte[] body, IpsecSession session, boolean isInitiator, boolean isV2) {
        if (body.length < 1) {
            return;
        }
        if (isV2) {
            int method = body[0] & 0xff;
            session.setAuthMethod(AUTH_METHOD_MAP.getOrDefault(method, "Auth_" + method));
            session.setSelectedAuthMethod(session.getAuthMethod());
            if (body.length > 4) {
                byte[] sig = new byte[body.length - 4];
                System.arraycopy(body, 4, sig, 0, sig.length);
                String sigHex = CodecUtil.toHex(sig);
                if (isInitiator) {
                    session.setInitiatorSignature(sigHex);
                } else {
                    session.setResponderSignature(sigHex);
                }
            }
        } else {
            String sigHex = CodecUtil.toHex(body);
            if (isInitiator) {
                session.setInitiatorSignature(sigHex);
            } else {
                session.setResponderSignature(sigHex);
            }
        }
    }

    private void processNoncePayload(byte[] body, IpsecSession session, boolean isInitiator) {
        String nonceHex = CodecUtil.toHex(body);
        if (isInitiator) {
            session.setInitiatorNonce(nonceHex);
        } else {
            session.setResponderNonce(nonceHex);
        }
    }

    private void processCertPayload(byte[] body, IpsecSession session, boolean isInitiator) {
        if (body.length < 1) {
            return;
        }

        // 第一层：按 RFC 2408 切出 DER 字节流（含国密私有载荷 fallback）
        IsakmpCertificateExtractor.ExtractResult extractResult =
                IsakmpCertificateExtractor.extractFromCertPayloadBody(body);
        if (extractResult == null || extractResult.getDer() == null || extractResult.getDer().length == 0) {
            session.getNotes().add("Certificate payload body too short to extract DER");
            return;
        }

        byte[] der = extractResult.getDer();
        int encoding = extractResult.getEncoding();
        boolean parseable = IsakmpCertificateExtractor.isParseableX509Encoding(encoding);

        // 第二层：用 X.509 库解析标准证书
        if (parseable) {
            try {
                IpsecCertificateInfo cert = parseX509Certificate(der);
                cert.setIndex(nextCertIndex(session, isInitiator));
                addCertificate(session, cert, isInitiator);
                return;
            } catch (Exception e) {
                // 标准 X.509 解析失败，可能是国密私有载荷伪装成 RAW DER，继续尝试 GM 私有结构
                session.getNotes().add("Certificate payload encoding=" + extractResult.getEncodingName()
                        + " len=" + der.length + " X.509 parse failed: " + e.getMessage());
            }
        }

        // 国密私有证书载荷：SEQUENCE { INTEGER r, INTEGER s, OCTET STRING pubKey/identifier, OCTET STRING certId }
        IpsecCertificateInfo gmCert = tryParseGmPrivateCertificate(der);
        if (gmCert != null) {
            gmCert.setIndex(nextCertIndex(session, isInitiator));
            addCertificate(session, gmCert, isInitiator);
            session.getNotes().add("Parsed GM private certificate payload (encoding="
                    + extractResult.getEncodingName() + ", len=" + der.length + ")");
            return;
        }

        // 无法识别为证书，但保留原始 DER 供导出
        String derBase64 = Base64.getEncoder().encodeToString(der);
        session.getCertificateDerBase64().add(derBase64);
        IpsecCertificateInfo fallback = new IpsecCertificateInfo();
        fallback.setIndex(nextCertIndex(session, isInitiator));
        fallback.setSubject("ISAKMP Certificate Payload（无法解析为 X.509，原始数据可导出；编码="
                + extractResult.getEncodingName() + "）");
        fallback.setSerialNumber("-（未携带 X.509 序列号）");
        fallback.setPublicKeyAlgorithm("未知");
        fallback.setSignatureAlgorithm("未知");
        fallback.setKeyUsage("-");
        fallback.setDerBase64(derBase64);
        addCertificate(session, fallback, isInitiator);
        session.getNotes().add("Certificate payload (encoding=" + extractResult.getEncodingName()
                + ", len=" + der.length + ") not parsed as X.509 certificate");
    }

    private IpsecCertificateInfo parseX509Certificate(byte[] der) throws Exception {
        Map<String, Object> certInfo = certCheckService.check(der);
        IpsecCertificateInfo cert = new IpsecCertificateInfo();
        cert.setVersion((String) certInfo.get("version"));
        cert.setSerialNumber((String) certInfo.get("serialNumber"));
        cert.setSubject((String) certInfo.get("subject"));
        cert.setIssuer((String) certInfo.get("issuer"));
        cert.setNotBefore((String) certInfo.get("notBefore"));
        cert.setNotAfter((String) certInfo.get("notAfter"));
        Map<String, Object> sigAlg = (Map<String, Object>) certInfo.get("signatureAlgorithm");
        cert.setSignatureAlgorithm(sigAlg != null ? (String) sigAlg.get("name") : null);
        cert.setPublicKeyAlgorithm((String) certInfo.get("publicKeyAlgorithm"));
        List<Map<String, Object>> extensions = (List<Map<String, Object>>) certInfo.get("extensions");
        if (extensions != null) {
            for (Map<String, Object> ext : extensions) {
                String extOid = (String) ext.get("oid");
                String extName = (String) ext.get("name");
                if ("2.5.29.15".equals(extOid) || "keyUsage".equals(extName) || "密钥用法".equals(extName)) {
                    cert.setKeyUsage((String) ext.get("description"));
                    break;
                }
            }
        }
        cert.setDerBase64(Base64.getEncoder().encodeToString(der));
        return cert;
    }

    private int nextCertIndex(IpsecSession session, boolean isInitiator) {
        return isInitiator ? session.getInitiatorCertificates().size() : session.getResponderCertificates().size();
    }

    private void addCertificate(IpsecSession session, IpsecCertificateInfo cert, boolean isInitiator) {
        if (isInitiator) {
            session.getInitiatorCertificates().add(cert);
        } else {
            session.getResponderCertificates().add(cert);
        }
    }

    /**
     * 尝试解析国密 IKE 私有证书载荷（SEQUENCE { INTEGER, INTEGER, OCTET STRING, OCTET STRING }）。
     * 这种结构常见于 GMT 0022 扩展：前两个 INTEGER 为 SM2 签名 (r, s)，后两个 OCTET STRING
     * 分别为公钥/标识与证书标识。解析成功后返回可导出的证书信息对象。
     */
    private IpsecCertificateInfo tryParseGmPrivateCertificate(byte[] der) {
        try {
            ASN1Primitive obj = ASN1Primitive.fromByteArray(der);
            if (!(obj instanceof ASN1Sequence seq) || seq.size() != 4) {
                return null;
            }
            ASN1Encodable e0 = seq.getObjectAt(0);
            ASN1Encodable e1 = seq.getObjectAt(1);
            ASN1Encodable e2 = seq.getObjectAt(2);
            ASN1Encodable e3 = seq.getObjectAt(3);
            if (!(e0 instanceof ASN1Integer) || !(e1 instanceof ASN1Integer)
                    || !(e2 instanceof ASN1OctetString) || !(e3 instanceof ASN1OctetString)) {
                return null;
            }
            byte[] pubKeyOrId = ((ASN1OctetString) e2).getOctets();
            byte[] certId = ((ASN1OctetString) e3).getOctets();
            IpsecCertificateInfo cert = new IpsecCertificateInfo();
            cert.setSubject("国密 IKE 私有证书签名载荷（证书标识：" + CodecUtil.toHex(certId) + "）");
            cert.setSerialNumber("-（私有载荷未携带 X.509 序列号）");
            cert.setPublicKeyAlgorithm("SM2（国密）");
            cert.setSignatureAlgorithm("SM2 Digital Signature");
            cert.setKeyUsage("数字签名/密钥交换；公钥标识：" + CodecUtil.toHex(pubKeyOrId));
            cert.setDerBase64(Base64.getEncoder().encodeToString(der));
            return cert;
        } catch (Exception e) {
            return null;
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
        // 国密 IKE 主模式未携带 DH 组属性时，根据 SM2/SM3/SM4 推断使用 SM2-256
        if (session.getSelectedDhGroup() == null && isGmAlgorithmSet(session)) {
            session.setSelectedDhGroup("SM2-256（国密）");
            addUnique(session.getInitiatorProposalsDhGroup(), "SM2-256（国密）");
        }
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

    private boolean isGmAlgorithmSet(IpsecSession session) {
        return containsGm(session.getSelectedEncryption())
                || containsGm(session.getSelectedIntegrity())
                || containsGm(session.getSelectedPrf())
                || containsGm(session.getSelectedDhGroup())
                || containsGm(session.getInitiatorIdentity())
                || containsGm(session.getResponderIdentity())
                || anyGm(session.getInitiatorProposalsEncryption())
                || anyGm(session.getInitiatorProposalsIntegrity())
                || anyGm(session.getInitiatorProposalsPrf())
                || anyGm(session.getInitiatorProposalsDhGroup())
                || anyGm(session.getResponderProposalsEncryption())
                || anyGm(session.getResponderProposalsIntegrity())
                || anyGm(session.getResponderProposalsPrf())
                || anyGm(session.getResponderProposalsDhGroup());
    }

    private boolean anyGm(List<String> list) {
        if (list == null) {
            return false;
        }
        for (String s : list) {
            if (containsGm(s)) {
                return true;
            }
        }
        return false;
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
    private static final Map<Integer, String> AUTH_METHOD_V1_MAP = new LinkedHashMap<>();
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
        ENCR_MAP.put(129, "SM4-CBC（国密）");
        ENCR_MAP.put(130, "SM4-CTR（国密）");

        PRF_MAP.put(1, "PRF-HMAC-SHA1");
        PRF_MAP.put(2, "PRF-HMAC-SHA256");
        PRF_MAP.put(3, "PRF-HMAC-SHA384");
        PRF_MAP.put(4, "PRF-HMAC-SHA512");
        PRF_MAP.put(5, "PRF-HMAC-MD5");
        PRF_MAP.put(6, "PRF-HMAC-TIGER");
        PRF_MAP.put(7, "PRF-AES128-XCBC");
        PRF_MAP.put(8, "PRF-SM3（国密）");
        PRF_MAP.put(20, "PRF-SM3（国密）");

        INTEG_MAP.put(1, "AUTH-HMAC-SHA1-96");
        INTEG_MAP.put(2, "AUTH-HMAC-SHA1-128");
        INTEG_MAP.put(3, "AUTH-HMAC-SHA256-128");
        INTEG_MAP.put(4, "AUTH-HMAC-SHA384-192");
        INTEG_MAP.put(5, "AUTH-HMAC-SHA512-256");
        INTEG_MAP.put(6, "AUTH-HMAC-MD5-96");
        INTEG_MAP.put(7, "AUTH-HMAC-SHA256-128");
        INTEG_MAP.put(8, "AUTH-SM3-96（国密）");
        INTEG_MAP.put(20, "AUTH-SM3-96（国密）");
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

        AUTH_METHOD_V1_MAP.put(1, "Pre-shared Key");
        AUTH_METHOD_V1_MAP.put(2, "DSS Digital Signature");
        AUTH_METHOD_V1_MAP.put(3, "RSA Digital Signature");
        AUTH_METHOD_V1_MAP.put(4, "RSA Encryption");
        AUTH_METHOD_V1_MAP.put(5, "Revised RSA Encryption");
        AUTH_METHOD_V1_MAP.put(6, "ECDSA with SHA-256");
        AUTH_METHOD_V1_MAP.put(7, "ECDSA with SHA-384");
        AUTH_METHOD_V1_MAP.put(8, "ECDSA with SHA-512");
        AUTH_METHOD_V1_MAP.put(10, "SM2 Digital Signature");
        AUTH_METHOD_V1_MAP.put(64221, "Hybrid Mode");
        AUTH_METHOD_V1_MAP.put(65001, "XAUTH Initiator Pre-shared Key");
        AUTH_METHOD_V1_MAP.put(65003, "XAUTH Responder Pre-shared Key");
        AUTH_METHOD_V1_MAP.put(65005, "XAUTH Initiator RSA");
        AUTH_METHOD_V1_MAP.put(65007, "XAUTH Responder RSA");
        AUTH_METHOD_V1_MAP.put(65009, "XAUTH Initiator ECDSA");
        AUTH_METHOD_V1_MAP.put(65011, "XAUTH Responder ECDSA");

        ID_TYPE_MAP.put(1, "ID_IPV4_ADDR");
        ID_TYPE_MAP.put(2, "ID_FQDN");
        ID_TYPE_MAP.put(3, "ID_RFC822_ADDR");
        ID_TYPE_MAP.put(5, "ID_IPV6_ADDR");
        ID_TYPE_MAP.put(9, "ID_DER_ASN1_DN");
        ID_TYPE_MAP.put(10, "ID_DER_ASN1_GN");
        ID_TYPE_MAP.put(11, "ID_KEY_ID");
        ID_TYPE_MAP.put(158, "ID_GM（国密标识）");

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
