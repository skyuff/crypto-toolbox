package com.smtool.module.parse;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * IPSec / IKE (ISAKMP) 报文结构化解析服务：
 * 解析 ISAKMP 头部（发起方/响应方 SPI、版本、交换类型、标志、消息 ID、长度），
 * 并遍历 payload 链，映射各 payload 类型名（按 IKEv2 payload type 编号）。解析健壮，字段不足时标注 truncated。
 */
@Service
public class IpsecParseService {

    /** IKEv2 交换类型映射 */
    private static final Map<Integer, String> EXCHANGE_TYPES_V2 = new LinkedHashMap<>();
    /** IKEv1 交换类型映射 */
    private static final Map<Integer, String> EXCHANGE_TYPES_V1 = new LinkedHashMap<>();
    /** IKEv2 payload 类型映射 */
    private static final Map<Integer, String> PAYLOAD_TYPES_V2 = new LinkedHashMap<>();
    /** IKEv1 payload 类型映射 */
    private static final Map<Integer, String> PAYLOAD_TYPES_V1 = new LinkedHashMap<>();

    static {
        EXCHANGE_TYPES_V2.put(34, "IKE_SA_INIT");
        EXCHANGE_TYPES_V2.put(35, "IKE_AUTH");
        EXCHANGE_TYPES_V2.put(36, "CREATE_CHILD_SA");
        EXCHANGE_TYPES_V2.put(37, "INFORMATIONAL");

        EXCHANGE_TYPES_V1.put(0, "NONE");
        EXCHANGE_TYPES_V1.put(1, "Base");
        EXCHANGE_TYPES_V1.put(2, "Identity Protection (Main Mode)");
        EXCHANGE_TYPES_V1.put(3, "Authentication Only");
        EXCHANGE_TYPES_V1.put(4, "Aggressive");
        EXCHANGE_TYPES_V1.put(5, "Informational");
        EXCHANGE_TYPES_V1.put(32, "Quick Mode");

        // IKEv2 payload 类型（RFC 7296）
        PAYLOAD_TYPES_V2.put(0, "No Next Payload");
        PAYLOAD_TYPES_V2.put(33, "SA (Security Association)");
        PAYLOAD_TYPES_V2.put(34, "KE (Key Exchange)");
        PAYLOAD_TYPES_V2.put(35, "IDi (Identification - Initiator)");
        PAYLOAD_TYPES_V2.put(36, "IDr (Identification - Responder)");
        PAYLOAD_TYPES_V2.put(37, "CERT (Certificate)");
        PAYLOAD_TYPES_V2.put(38, "CERTREQ (Certificate Request)");
        PAYLOAD_TYPES_V2.put(39, "AUTH (Authentication)");
        PAYLOAD_TYPES_V2.put(40, "Nonce (Ni, Nr)");
        PAYLOAD_TYPES_V2.put(41, "N (Notify)");
        PAYLOAD_TYPES_V2.put(42, "D (Delete)");
        PAYLOAD_TYPES_V2.put(43, "V (Vendor ID)");
        PAYLOAD_TYPES_V2.put(44, "TSi (Traffic Selector - Initiator)");
        PAYLOAD_TYPES_V2.put(45, "TSr (Traffic Selector - Responder)");
        PAYLOAD_TYPES_V2.put(46, "SK (Encrypted and Authenticated)");
        PAYLOAD_TYPES_V2.put(47, "CP (Configuration)");
        PAYLOAD_TYPES_V2.put(48, "EAP (Extensible Authentication)");

        // IKEv1 payload 类型（RFC 2408）
        PAYLOAD_TYPES_V1.put(0, "No Next Payload");
        PAYLOAD_TYPES_V1.put(1, "SA (Security Association)");
        PAYLOAD_TYPES_V1.put(2, "P (Proposal)");
        PAYLOAD_TYPES_V1.put(3, "T (Transform)");
        PAYLOAD_TYPES_V1.put(4, "KE (Key Exchange)");
        PAYLOAD_TYPES_V1.put(5, "ID (Identification)");
        PAYLOAD_TYPES_V1.put(6, "CERT (Certificate)");
        PAYLOAD_TYPES_V1.put(7, "CR (Certificate Request)");
        PAYLOAD_TYPES_V1.put(8, "HASH");
        PAYLOAD_TYPES_V1.put(9, "SIG (Signature)");
        PAYLOAD_TYPES_V1.put(10, "NONCE");
        PAYLOAD_TYPES_V1.put(11, "N (Notification)");
        PAYLOAD_TYPES_V1.put(12, "D (Delete)");
        PAYLOAD_TYPES_V1.put(13, "VID (Vendor ID)");
    }

    /** 解析入口（单条报文） */
    public Map<String, Object> parse(IpsecParseRequest req) {
        byte[] data = CodecUtil.decode(req.getInput(), req.getFormat() == null ? "hex" : req.getFormat());
        Map<String, Object> result = parseMessage(data);
        result.put("srcIp", req.getSrcIp());
        result.put("dstIp", req.getDstIp());
        return result;
    }

    /** 直接解析 ISAKMP 消息（byte[] 入参），供流量解析复用 */
    public Map<String, Object> parseMessage(byte[] data) {
        ByteReader r = new ByteReader(data);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("totalBytes", data.length);

        // ===== ISAKMP 头部 =====
        Map<String, Object> header = new LinkedHashMap<>();
        byte[] initiatorSpi = r.bytes(8);
        header.put("initiatorSpi", CodecUtil.toHex(initiatorSpi));
        byte[] responderSpi = r.bytes(8);
        header.put("responderSpi", CodecUtil.toHex(responderSpi));

        int nextPayload = r.u8();
        int version = r.u8();
        int major = version < 0 ? -1 : (version >> 4) & 0x0F;
        int minor = version < 0 ? -1 : version & 0x0F;
        boolean isV2 = major == 2;
        String versionText;
        if (version < 0) {
            versionText = null;
        } else if (isV2) {
            versionText = String.format("0x%02x", version) + " (IKEv2)";
        } else if (major == 1) {
            versionText = String.format("0x%02x", version) + " (ISAKMP " + major + "." + minor + " / IKEv1)";
        } else {
            versionText = String.format("0x%02x", version) + " (ISAKMP " + major + "." + minor + ")";
        }
        header.put("version", versionText);

        int exchangeType = r.u8();
        Map<Integer, String> exTable = isV2 ? EXCHANGE_TYPES_V2 : EXCHANGE_TYPES_V1;
        header.put("exchangeType", exchangeType < 0 ? null
                : exchangeType + " (" + exTable.getOrDefault(exchangeType, "未知") + ")");

        int flags = r.u8();
        header.put("flags", flags < 0 ? null : describeFlags(flags, isV2));

        long messageId = r.u32();
        header.put("messageId", messageId < 0 ? null : String.format("0x%08x", messageId));
        long length = r.u32();
        header.put("length", length < 0 ? null : length);

        // 校验 ISAKMP 长度字段
        if (length >= 0 && length > data.length) {
            result.put("truncated", true);
            result.put("note", "ISAKMP header length 字段（" + length + "）超过实际数据长度（" + data.length + "）");
        }

        // 头部的 next payload 是 payload 链第一个 payload 的类型
        Map<Integer, String> plTable = isV2 ? PAYLOAD_TYPES_V2 : PAYLOAD_TYPES_V1;
        header.put("nextPayload", nextPayload < 0 ? null
                : nextPayload + " (" + plTable.getOrDefault(nextPayload, "未知") + ")");
        result.put("header", header);

        // ===== payload 链 =====
        List<Map<String, Object>> payloads = new ArrayList<>();
        int curType = nextPayload;
        int guard = 0;
        while (curType > 0 && r.has(4) && guard++ < 64) {
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("payloadType", curType + " (" + plTable.getOrDefault(curType, "未知") + ")");
            p.put("payloadTypeCode", curType);
            int next = r.u8();
            int critReserved = r.u8();
            p.put("critical", critReserved < 0 ? null : ((critReserved & 0x80) != 0));
            int payloadLength = r.u16();
            p.put("payloadLength", payloadLength);
            // payload 数据部分 = payloadLength - 4（通用头 4 字节）
            int dataLen = payloadLength < 4 ? 0 : payloadLength - 4;
            byte[] body = r.bytes(dataLen);
            p.put("data", CodecUtil.toHex(body));
            payloads.add(p);

            if (next <= 0 || payloadLength < 4) {
                break;
            }
            curType = next;
        }
        result.put("payloads", payloads);

        if (r.isTruncated()) {
            result.put("truncated", true);
        }
        return result;
    }

    /**
     * 解析一段字节中的 payload 链（不含 ISAKMP 头部）。
     * 用于解密后的 IKE 明文载荷二次解析。
     */
    public List<Map<String, Object>> parsePayloadChain(byte[] data) {
        return parsePayloadChain(data, false);
    }

    /**
     * 解析一段字节中的 payload 链（不含 ISAKMP 头部）。
     *
     * @param data 明文 payload 字节
     * @param isV2 是否按 IKEv2 payload 类型映射
     */
    public List<Map<String, Object>> parsePayloadChain(byte[] data, boolean isV2) {
        List<Map<String, Object>> payloads = new ArrayList<>();
        if (data == null || data.length < 4) {
            return payloads;
        }
        Map<Integer, String> plTable = isV2 ? PAYLOAD_TYPES_V2 : PAYLOAD_TYPES_V1;
        ByteReader r = new ByteReader(data);
        // 第一个字节是 payload 链中第一个 payload 的类型
        int curType = r.u8();
        int guard = 0;
        while (curType > 0 && r.has(3) && guard++ < 64) {
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("payloadType", curType + " (" + plTable.getOrDefault(curType, "未知") + ")");
            p.put("payloadTypeCode", curType);
            int next = r.u8();
            int critReserved = r.u8();
            p.put("critical", critReserved < 0 ? null : ((critReserved & 0x80) != 0));
            int plen = r.u16();
            p.put("payloadLength", plen);
            int dataLen = plen < 4 ? 0 : plen - 4;
            byte[] body = r.bytes(dataLen);
            p.put("data", CodecUtil.toHex(body));
            payloads.add(p);
            if (next <= 0 || plen < 4) {
                break;
            }
            curType = next;
        }
        return payloads;
    }

    /** 解析 flags 字段 */
    private String describeFlags(int flags, boolean isV2) {
        List<String> set = new ArrayList<>();
        if (isV2) {
            // IKEv2: bit3=Initiator, bit4=Version, bit5=Response
            if ((flags & 0x08) != 0) {
                set.add("Initiator");
            }
            if ((flags & 0x10) != 0) {
                set.add("Version");
            }
            if ((flags & 0x20) != 0) {
                set.add("Response");
            }
        } else {
            // IKEv1: bit0=Encryption, bit1=Commit, bit2=Authentication Only
            if ((flags & 0x01) != 0) {
                set.add("Encryption");
            }
            if ((flags & 0x02) != 0) {
                set.add("Commit");
            }
            if ((flags & 0x04) != 0) {
                set.add("Authentication Only");
            }
        }
        return String.format("0x%02x", flags) + (set.isEmpty() ? "" : " (" + String.join(", ", set) + ")");
    }

    /**
     * 从 UDP payload 中提取 ISAKMP 消息，处理 NAT-T Non-ESP Marker。
     * <p>
     * UDP/4500 的 IKE 消息前 4 字节为 0x00 00 00 00（Non-ESP Marker）；
     * Marker-only 包返回空字节数组而不是被跳过。
     */
    public static byte[] stripNattMarker(byte[] payload, int srcPort, int dstPort) {
        if (payload == null) {
            return new byte[0];
        }
        if (srcPort == 4500 || dstPort == 4500) {
            if (payload.length >= 4 && payload[0] == 0 && payload[1] == 0 && payload[2] == 0 && payload[3] == 0) {
                if (payload.length == 4) {
                    return new byte[0];
                }
                return Arrays.copyOfRange(payload, 4, payload.length);
            }
        }
        return payload;
    }
}
