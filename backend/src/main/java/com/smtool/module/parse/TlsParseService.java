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

        // 校验 record length 与实际字节数
        int recordBodyAvailable = r.remaining();
        if (recordLength > recordBodyAvailable) {
            record.put("truncated", true);
            result.put("note", "Record 声明长度 " + recordLength + " 超过实际剩余字节 " + recordBodyAvailable);
            result.put("truncated", true);
            return result;
        }

        // 仅当为 handshake(22) 时解析握手层，使用限定范围的 Reader 防止越界
        if (contentType == 22) {
            int handshakeBytes = Math.min(recordLength, recordBodyAvailable);
            byte[] hsData = r.bytes(handshakeBytes);
            ByteReader hr = new ByteReader(hsData);
            result.put("handshake", parseHandshake(hr, result));
            if (hr.isTruncated()) {
                result.put("truncated", true);
            }
        } else if (contentType >= 0) {
            // 跳过当前 record 的 payload 字节
            r.bytes(recordLength);
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

        // 按 hsLength 限制子 Reader，避免越界或读取到下一条消息
        byte[] hsBody = r.bytes(hsLength < 0 ? 0 : hsLength);
        ByteReader br = new ByteReader(hsBody);

        // client_version / server_version（ClientHello、ServerHello 均以 2 字节版本开头）
        int hsVersion = br.u16();
        hs.put(hsType == 2 ? "server_version" : "client_version", describeVersion(hsVersion));
        hs.put(hsType == 2 ? "server_version_value" : "client_version_value", hsVersion);

        // random(32B)
        byte[] random = br.bytes(32);
        hs.put("random", CodecUtil.toHex(random));

        // sessionId
        int sidLen = br.u8();
        hs.put("sessionIdLength", sidLen);
        byte[] sid = br.bytes(sidLen < 0 ? 0 : sidLen);
        hs.put("sessionId", CodecUtil.toHex(sid));

        boolean isGmSuite = false;

        if (hsType == 1) {
            // ===== ClientHello：cipherSuites 是列表 =====
            int csBytes = br.u16();
            hs.put("cipherSuitesLength", csBytes);
            List<Map<String, Object>> suites = new ArrayList<>();
            if (csBytes < 0) {
                // 已截断，不解析
            } else if ((csBytes & 0x01) != 0) {
                hs.put("cipherSuitesError", "密码套件长度为奇数（" + csBytes + "），停止解析套件列表");
                root.put("truncated", true);
            } else {
                int count = csBytes / 2;
                for (int i = 0; i < count; i++) {
                    int cs = br.u16();
                    if (cs < 0) {
                        break;
                    }
                    Map<String, Object> s = buildCipherSuite(cs);
                    suites.add(s);
                    boolean gm = Boolean.TRUE.equals(s.get("gm"));
                    isGmSuite = isGmSuite || gm;
                }
            }
            hs.put("cipherSuites", suites);

            // compressionMethods
            int cmLen = br.u8();
            hs.put("compressionMethodsLength", cmLen);
            byte[] cm = br.bytes(cmLen < 0 ? 0 : cmLen);
            hs.put("compressionMethods", CodecUtil.toHex(cm));
        } else if (hsType == 2) {
            // ===== ServerHello：单个 cipher_suite =====
            int cs = br.u16();
            Map<String, Object> s = buildCipherSuite(cs);
            isGmSuite = Boolean.TRUE.equals(s.get("gm"));
            hs.put("cipherSuite", s);
            // compressionMethod（单字节）
            int cm = br.u8();
            hs.put("compressionMethod", cm < 0 ? null : String.format("0x%02x", cm));
        }

        // ===== extensions（ClientHello / ServerHello 通用）=====
        if (br.has(2)) {
            int extTotal = br.u16();
            hs.put("extensionsLength", extTotal);
            List<Map<String, Object>> exts = new ArrayList<>();
            if (extTotal < 0 || extTotal > br.remaining()) {
                hs.put("extensionsError", "extensions 总长度越界（" + extTotal + " > 剩余 " + br.remaining() + "）");
                root.put("truncated", true);
            } else {
                int extEnd = br.position() + extTotal;
                while (br.position() < extEnd && br.has(4)) {
                    int extType = br.u16();
                    int extLen = br.u16();
                    int remainingInExtensions = extEnd - br.position();
                    if (extLen < 0 || extLen > remainingInExtensions) {
                        hs.put("extensionsError", "扩展 0x" + String.format("%04x", extType)
                                + " 长度越界（" + extLen + "）");
                        root.put("truncated", true);
                        br.bytes(br.remaining()); // 消费剩余，避免死循环
                        break;
                    }
                    Map<String, Object> ext = new LinkedHashMap<>();
                    ext.put("type", String.format("0x%04x", extType)
                            + " (" + EXTENSIONS.getOrDefault(extType, "未知扩展") + ")");
                    ext.put("length", extLen);
                    byte[] extData = br.bytes(extLen);
                    ext.put("data", CodecUtil.toHex(extData));
                    // supported_versions 扩展做语义化解析
                    if (extType == 43 && extData.length >= 2) {
                        parseSupportedVersions(ext, extData, hsType);
                    }
                    exts.add(ext);
                }
            }
            hs.put("extensions", exts);
        }

        if (br.isTruncated()) {
            root.put("truncated", true);
            hs.put("truncated", true);
        }
        // 将国密套件标记提升到顶层
        root.put("isGmSuite", isGmSuite);
        return hs;
    }

    /** 判断是否为国密 / TLCP 套件 */
    public boolean isGmSuite(int cs) {
        return TlsCipherSuites.isGmSuite(cs);
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
     * 解析 supported_versions 扩展。
     * <ul>
     *     <li>ClientHello: versions_len(1) + [version(2)...]</li>
     *     <li>ServerHello: selected_version(2)</li>
     * </ul>
     */
    private void parseSupportedVersions(Map<String, Object> ext, byte[] data, int hsType) {
        if (hsType == 2) {
            // ServerHello: 单个 selected_version
            int version = ((data[0] & 0xff) << 8) | (data[1] & 0xff);
            ext.put("selectedVersion", describeVersion(version));
            ext.put("selectedVersionValue", version);
        } else {
            // ClientHello: 版本列表
            int listLen = data[0] & 0xff;
            List<String> versions = new ArrayList<>();
            for (int i = 0; i < listLen / 2 && 1 + i * 2 + 1 < data.length; i++) {
                int v = ((data[1 + i * 2] & 0xff) << 8) | (data[1 + i * 2 + 1] & 0xff);
                versions.add(describeVersion(v));
            }
            ext.put("supportedVersions", versions);
        }
    }

    /**
     * 构建密码套件描述对象。
     */
    public Map<String, Object> buildCipherSuite(int cs) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("value", String.format("0x%04x", cs));
        s.put("name", TlsCipherSuites.getName(cs));
        s.put("gm", TlsCipherSuites.isGmSuite(cs));
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
