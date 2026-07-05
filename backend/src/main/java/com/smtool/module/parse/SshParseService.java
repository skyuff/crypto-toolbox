package com.smtool.module.parse;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * SSH 报文结构化解析服务：
 * 1) 若输入以 "SSH-" 开头，按版本标识串（banner）解析；
 * 2) 否则按 SSH Binary Packet Protocol 解析，若 payload 首字节为 SSH_MSG_KEXINIT(20) 则进一步解析算法协商列表。
 * 解析健壮，字段不足时返回已解析部分并标注 truncated。
 */
@Service
public class SshParseService {

    /** SSH 消息码映射 */
    private static final Map<Integer, String> MSG_CODES = new LinkedHashMap<>();

    static {
        MSG_CODES.put(1, "SSH_MSG_DISCONNECT");
        MSG_CODES.put(2, "SSH_MSG_IGNORE");
        MSG_CODES.put(3, "SSH_MSG_UNIMPLEMENTED");
        MSG_CODES.put(4, "SSH_MSG_DEBUG");
        MSG_CODES.put(5, "SSH_MSG_SERVICE_REQUEST");
        MSG_CODES.put(6, "SSH_MSG_SERVICE_ACCEPT");
        MSG_CODES.put(20, "SSH_MSG_KEXINIT");
        MSG_CODES.put(21, "SSH_MSG_NEWKEYS");
        MSG_CODES.put(30, "SSH_MSG_KEXDH_INIT / KEX_ECDH_INIT");
        MSG_CODES.put(31, "SSH_MSG_KEXDH_REPLY / KEX_ECDH_REPLY");
        MSG_CODES.put(50, "SSH_MSG_USERAUTH_REQUEST");
        MSG_CODES.put(51, "SSH_MSG_USERAUTH_FAILURE");
        MSG_CODES.put(52, "SSH_MSG_USERAUTH_SUCCESS");
    }

    /** KEXINIT 的 name-list 字段顺序（RFC 4253） */
    private static final String[] KEXINIT_NAMELISTS = {
            "kex_algorithms",
            "server_host_key_algorithms",
            "encryption_algorithms_client_to_server",
            "encryption_algorithms_server_to_client",
            "mac_algorithms_client_to_server",
            "mac_algorithms_server_to_client",
            "compression_algorithms_client_to_server",
            "compression_algorithms_server_to_client",
            "languages_client_to_server",
            "languages_server_to_client"
    };

    /** 解析入口 */
    public Map<String, Object> parse(SshParseRequest req) {
        byte[] data = CodecUtil.decode(req.getInput(), req.getFormat() == null ? "hex" : req.getFormat());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("srcIp", req.getSrcIp());
        result.put("dstIp", req.getDstIp());
        result.put("dstPort", req.getDstPort());
        result.put("totalBytes", data.length);

        // 判断是否为 banner 文本（以 "SSH-" 开头）
        if (startsWithSsh(data)) {
            result.put("kind", "banner");
            result.putAll(parseBanner(data));
            return result;
        }

        // 二进制包协议
        result.put("kind", "binary_packet");
        result.putAll(parseBinaryPacket(data));
        return result;
    }

    /** 判断报文是否以 ASCII "SSH-" 开头 */
    private boolean startsWithSsh(byte[] data) {
        byte[] prefix = "SSH-".getBytes(StandardCharsets.US_ASCII);
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    /** 解析 SSH 版本标识串 banner，例如 "SSH-2.0-OpenSSH_8.9" */
    private Map<String, Object> parseBanner(byte[] data) {
        Map<String, Object> m = new LinkedHashMap<>();
        // banner 以 CR LF 结尾，去除
        String line = new String(data, StandardCharsets.UTF_8).replaceAll("[\r\n]+$", "");
        m.put("identificationString", line);
        // 格式：SSH-protoversion-softwareversion SP comments
        String[] parts = line.split("-", 3);
        if (parts.length >= 3) {
            m.put("protoVersion", parts[1]);
            String rest = parts[2];
            int sp = rest.indexOf(' ');
            if (sp >= 0) {
                m.put("softwareVersion", rest.substring(0, sp));
                m.put("comments", rest.substring(sp + 1));
            } else {
                m.put("softwareVersion", rest);
            }
        } else {
            m.put("note", "版本标识串格式不完整");
        }
        return m;
    }

    /** 解析 SSH 二进制包协议 */
    private Map<String, Object> parseBinaryPacket(byte[] data) {
        Map<String, Object> m = new LinkedHashMap<>();
        ByteReader r = new ByteReader(data);

        long packetLength = r.u32();
        m.put("packetLength", packetLength);
        int paddingLength = r.u8();
        m.put("paddingLength", paddingLength);

        // payload 长度 = packet_length - padding_length - 1
        int payloadLen = -1;
        if (packetLength > 0 && paddingLength >= 0) {
            payloadLen = (int) (packetLength - paddingLength - 1);
        }
        byte[] payload;
        if (payloadLen >= 0) {
            payload = r.bytes(payloadLen);
        } else {
            // 无法确定 payload 长度，取剩余全部
            payload = r.bytes(r.remaining());
        }
        m.put("payloadLength", payload.length);

        if (payload.length > 0) {
            int msgCode = payload[0] & 0xFF;
            m.put("messageCode", String.format("0x%02x", msgCode) + " ("
                    + MSG_CODES.getOrDefault(msgCode, "未知消息") + ")");

            // 若为 KEXINIT(20)，解析算法协商列表
            if (msgCode == 20) {
                m.put("kexInit", parseKexInit(payload));
            }
        } else {
            m.put("note", "payload 为空或数据不足");
        }

        if (r.isTruncated()) {
            m.put("truncated", true);
        }
        return m;
    }

    /** 解析 SSH_MSG_KEXINIT payload */
    private Map<String, Object> parseKexInit(byte[] payload) {
        Map<String, Object> m = new LinkedHashMap<>();
        // 跳过首字节 msg code
        ByteReader r = new ByteReader(Arrays.copyOfRange(payload, 1, payload.length));

        // cookie(16B)
        byte[] cookie = r.bytes(16);
        m.put("cookie", CodecUtil.toHex(cookie));

        // 依次解析 10 个 name-list
        for (String field : KEXINIT_NAMELISTS) {
            m.put(field, readNameList(r));
        }

        // first_kex_packet_follows(1B) + reserved(4B)
        int follows = r.u8();
        m.put("firstKexPacketFollows", follows < 0 ? null : (follows != 0));
        long reserved = r.u32();
        m.put("reserved", reserved < 0 ? null : reserved);

        if (r.isTruncated()) {
            m.put("truncated", true);
        }
        return m;
    }

    /** 读取一个 SSH name-list：4 字节长度 + 逗号分隔字符串，返回字符串列表 */
    private List<String> readNameList(ByteReader r) {
        long len = r.u32();
        if (len <= 0) {
            return new ArrayList<>();
        }
        byte[] raw = r.bytes((int) len);
        String s = new String(raw, StandardCharsets.US_ASCII);
        if (s.isEmpty()) {
            return new ArrayList<>();
        }
        return new ArrayList<>(Arrays.asList(s.split(",")));
    }
}
