package com.smtool.module.parse;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * TLS 报文结构化解析服务：
 * 解析一个 TLS Record 层 + Handshake（重点支持 ClientHello / ServerHello），
 * 逐字段还原并映射常见/国密密码套件、扩展类型。解析健壮，字段不足时返回已解析部分并标注 truncated。
 */
@Service
public class TlsParseService {

    /** TLS record contentType 映射 */
    private static final Map<Integer, String> CONTENT_TYPES = new LinkedHashMap<>();
    /** TLS/SSL 版本号映射 */
    private static final Map<Integer, String> VERSIONS = new LinkedHashMap<>();
    /** handshake 类型映射 */
    private static final Map<Integer, String> HANDSHAKE_TYPES = new LinkedHashMap<>();
    /** 密码套件映射（含标准套件与国密 TLCP 套件） */
    private static final Map<Integer, String> CIPHER_SUITES = new LinkedHashMap<>();
    /** 扩展类型映射 */
    private static final Map<Integer, String> EXTENSIONS = new LinkedHashMap<>();

    static {
        CONTENT_TYPES.put(20, "change_cipher_spec");
        CONTENT_TYPES.put(21, "alert");
        CONTENT_TYPES.put(22, "handshake");
        CONTENT_TYPES.put(23, "application_data");
        CONTENT_TYPES.put(24, "heartbeat");

        VERSIONS.put(0x0300, "SSL 3.0");
        VERSIONS.put(0x0301, "TLS 1.0");
        VERSIONS.put(0x0302, "TLS 1.1");
        VERSIONS.put(0x0303, "TLS 1.2");
        VERSIONS.put(0x0304, "TLS 1.3");
        VERSIONS.put(0x0101, "GM/T TLCP 1.1（国密）");

        HANDSHAKE_TYPES.put(0, "hello_request");
        HANDSHAKE_TYPES.put(1, "client_hello");
        HANDSHAKE_TYPES.put(2, "server_hello");
        HANDSHAKE_TYPES.put(11, "certificate");
        HANDSHAKE_TYPES.put(12, "server_key_exchange");
        HANDSHAKE_TYPES.put(13, "certificate_request");
        HANDSHAKE_TYPES.put(14, "server_hello_done");
        HANDSHAKE_TYPES.put(15, "certificate_verify");
        HANDSHAKE_TYPES.put(16, "client_key_exchange");
        HANDSHAKE_TYPES.put(20, "finished");

        // 国密 TLCP / GM 套件
        CIPHER_SUITES.put(0xe011, "ECC_SM4_SM3（国密）");
        CIPHER_SUITES.put(0xe013, "ECDHE_SM4_SM3（国密）");
        CIPHER_SUITES.put(0xe015, "ECC_SM4_GCM_SM3（国密）");
        CIPHER_SUITES.put(0xe019, "IBSDH_SM4_SM3（国密）");
        CIPHER_SUITES.put(0xe01c, "RSA_SM4_SM3（国密）");
        CIPHER_SUITES.put(0x00c6, "TLS_SM4_GCM_SM3（国密, TLS1.3）");
        CIPHER_SUITES.put(0x00c7, "TLS_SM4_CCM_SM3（国密, TLS1.3）");
        // 常见标准套件
        CIPHER_SUITES.put(0x0000, "TLS_NULL_WITH_NULL_NULL");
        CIPHER_SUITES.put(0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA");
        CIPHER_SUITES.put(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA");
        CIPHER_SUITES.put(0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256");
        CIPHER_SUITES.put(0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384");
        CIPHER_SUITES.put(0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        CIPHER_SUITES.put(0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        CIPHER_SUITES.put(0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        CIPHER_SUITES.put(0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
        CIPHER_SUITES.put(0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        CIPHER_SUITES.put(0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        CIPHER_SUITES.put(0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
        CIPHER_SUITES.put(0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
        CIPHER_SUITES.put(0x1301, "TLS_AES_128_GCM_SHA256（TLS1.3）");
        CIPHER_SUITES.put(0x1302, "TLS_AES_256_GCM_SHA384（TLS1.3）");
        CIPHER_SUITES.put(0x1303, "TLS_CHACHA20_POLY1305_SHA256（TLS1.3）");
        CIPHER_SUITES.put(0x00ff, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV");

        EXTENSIONS.put(0, "server_name");
        EXTENSIONS.put(1, "max_fragment_length");
        EXTENSIONS.put(5, "status_request");
        EXTENSIONS.put(10, "supported_groups");
        EXTENSIONS.put(11, "ec_point_formats");
        EXTENSIONS.put(13, "signature_algorithms");
        EXTENSIONS.put(14, "use_srtp");
        EXTENSIONS.put(15, "heartbeat");
        EXTENSIONS.put(16, "application_layer_protocol_negotiation");
        EXTENSIONS.put(18, "signed_certificate_timestamp");
        EXTENSIONS.put(21, "padding");
        EXTENSIONS.put(23, "extended_master_secret");
        EXTENSIONS.put(35, "session_ticket");
        EXTENSIONS.put(41, "pre_shared_key");
        EXTENSIONS.put(43, "supported_versions");
        EXTENSIONS.put(45, "psk_key_exchange_modes");
        EXTENSIONS.put(51, "key_share");
        EXTENSIONS.put(65281, "renegotiation_info");
    }

    /** 解析入口 */
    public Map<String, Object> parse(TlsParseRequest req) {
        byte[] data = CodecUtil.decode(req.getInput(), req.getFormat() == null ? "hex" : req.getFormat());
        ByteReader r = new ByteReader(data);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("srcIp", req.getSrcIp());
        result.put("dstIp", req.getDstIp());
        result.put("totalBytes", data.length);

        // ===== TLS Record 层 =====
        Map<String, Object> record = new LinkedHashMap<>();
        int contentType = r.u8();
        record.put("contentType", describe(contentType, CONTENT_TYPES));
        int recordVersion = r.u16();
        record.put("version", describeVersion(recordVersion));
        int recordLength = r.u16();
        record.put("length", recordLength);
        result.put("record", record);

        // 仅当为 handshake(22) 时解析握手层
        if (contentType == 22) {
            result.put("handshake", parseHandshake(r, result));
        } else if (contentType >= 0) {
            result.put("note", "非 handshake 报文（contentType=" + contentType + "），仅解析 Record 层");
        }

        if (r.isTruncated()) {
            result.put("truncated", true);
        }
        return result;
    }

    /** 解析 Handshake 层（ClientHello / ServerHello 重点） */
    private Map<String, Object> parseHandshake(ByteReader r, Map<String, Object> root) {
        Map<String, Object> hs = new LinkedHashMap<>();
        int hsType = r.u8();
        hs.put("handshakeType", describe(hsType, HANDSHAKE_TYPES));
        int hsLength = r.u24();
        hs.put("length", hsLength);

        // client_version / server_version（ClientHello、ServerHello 均以 2 字节版本开头）
        int hsVersion = r.u16();
        hs.put(hsType == 2 ? "server_version" : "client_version", describeVersion(hsVersion));

        // random(32B)
        byte[] random = r.bytes(32);
        hs.put("random", CodecUtil.toHex(random));

        // sessionId
        int sidLen = r.u8();
        hs.put("sessionIdLength", sidLen);
        byte[] sid = r.bytes(sidLen < 0 ? 0 : sidLen);
        hs.put("sessionId", CodecUtil.toHex(sid));

        boolean isGmSuite = false;

        if (hsType == 1) {
            // ===== ClientHello：cipherSuites 是列表 =====
            int csBytes = r.u16();
            hs.put("cipherSuitesLength", csBytes);
            List<Map<String, Object>> suites = new ArrayList<>();
            int count = csBytes < 0 ? 0 : csBytes / 2;
            for (int i = 0; i < count; i++) {
                int cs = r.u16();
                if (cs < 0) {
                    break;
                }
                Map<String, Object> s = new LinkedHashMap<>();
                s.put("value", String.format("0x%04x", cs));
                s.put("name", CIPHER_SUITES.getOrDefault(cs, "未知套件"));
                boolean gm = isGmSuite(cs);
                s.put("gm", gm);
                isGmSuite = isGmSuite || gm;
                suites.add(s);
            }
            hs.put("cipherSuites", suites);

            // compressionMethods
            int cmLen = r.u8();
            hs.put("compressionMethodsLength", cmLen);
            byte[] cm = r.bytes(cmLen < 0 ? 0 : cmLen);
            hs.put("compressionMethods", CodecUtil.toHex(cm));
        } else if (hsType == 2) {
            // ===== ServerHello：单个 cipher_suite =====
            int cs = r.u16();
            Map<String, Object> s = new LinkedHashMap<>();
            s.put("value", String.format("0x%04x", cs));
            s.put("name", CIPHER_SUITES.getOrDefault(cs, "未知套件"));
            boolean gm = isGmSuite(cs);
            s.put("gm", gm);
            isGmSuite = gm;
            hs.put("cipherSuite", s);
            // compressionMethod（单字节）
            int cm = r.u8();
            hs.put("compressionMethod", cm < 0 ? null : String.format("0x%02x", cm));
        }

        // ===== extensions（ClientHello / ServerHello 通用）=====
        if (r.has(2)) {
            int extTotal = r.u16();
            hs.put("extensionsLength", extTotal);
            List<Map<String, Object>> exts = new ArrayList<>();
            int endLimit = r.position() + (extTotal < 0 ? 0 : extTotal);
            while (r.position() < endLimit && r.has(4)) {
                int extType = r.u16();
                int extLen = r.u16();
                Map<String, Object> ext = new LinkedHashMap<>();
                ext.put("type", String.format("0x%04x", extType)
                        + " (" + EXTENSIONS.getOrDefault(extType, "未知扩展") + ")");
                ext.put("length", extLen);
                byte[] extData = r.bytes(extLen < 0 ? 0 : extLen);
                ext.put("data", CodecUtil.toHex(extData));
                exts.add(ext);
            }
            hs.put("extensions", exts);
        }

        // 将国密套件标记提升到顶层
        root.put("isGmSuite", isGmSuite);
        return hs;
    }

    /** 判断是否为国密 / TLCP 套件（0xe0xx 区间或已知 GM 套件编号） */
    public boolean isGmSuite(int cs) {
        if (cs < 0) {
            return false;
        }
        if ((cs & 0xff00) == 0xe000) {
            return true;
        }
        return cs == 0x00c6 || cs == 0x00c7;
    }

    /** 通用整型映射描述：返回 "0xNN (名称)" */
    private String describe(int value, Map<Integer, String> table) {
        if (value < 0) {
            return null;
        }
        return String.format("0x%02x", value) + " (" + table.getOrDefault(value, "未知") + ")";
    }

    /** 版本号描述：返回 "0x0303 (TLS 1.2)" */
    public String describeVersion(int value) {
        if (value < 0) {
            return null;
        }
        return String.format("0x%04x", value) + " (" + VERSIONS.getOrDefault(value, "未知版本") + ")";
    }

    /**
     * 构建密码套件描述对象。
     */
    public Map<String, Object> buildCipherSuite(int cs) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("value", String.format("0x%04x", cs));
        s.put("name", CIPHER_SUITES.getOrDefault(cs, "未知套件"));
        s.put("gm", isGmSuite(cs));
        return s;
    }

    /**
     * 解析 ClientHello（不含 record 头，含 handshake 头）。
     */
    public Map<String, Object> parseClientHello(ByteReader r) {
        return parseHandshake(r, new LinkedHashMap<>());
    }

    /**
     * 解析 ServerHello（不含 record 头，含 handshake 头）。
     */
    public Map<String, Object> parseServerHello(ByteReader r) {
        return parseHandshake(r, new LinkedHashMap<>());
    }
}
