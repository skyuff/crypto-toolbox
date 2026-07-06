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
 * 从重组后的单向 TCP 字节流中解析 SSH 消息。
 */
@Service
public class SshStreamParser {

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
        MSG_CODES.put(30, "SSH_MSG_KEXDH_INIT / SSH_MSG_KEX_ECDH_INIT");
        MSG_CODES.put(31, "SSH_MSG_KEXDH_REPLY / SSH_MSG_KEX_ECDH_REPLY");
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

    /**
     * 解析一条单向字节流，返回 banner（如有）以及所有 SSH 消息列表。
     */
    public List<SshMessage> parseStream(byte[] data) {
        List<SshMessage> messages = new ArrayList<>();
        if (data == null || data.length == 0) {
            return messages;
        }

        int pos = 0;

        // 尝试提取 banner（可能有多行以 \r\n 结尾的文本行）
        while (pos < data.length) {
            // 查找行尾
            int lineEnd = findLineEnd(data, pos);
            if (lineEnd < 0) {
                break;
            }
            byte[] lineBytes = Arrays.copyOfRange(data, pos, lineEnd);
            String line = new String(lineBytes, StandardCharsets.UTF_8);
            if (line.startsWith("SSH-")) {
                SshMessage msg = new SshMessage();
                msg.type = -1;
                msg.typeName = "banner";
                msg.payload = lineBytes;
                msg.banner = line;
                messages.add(msg);
                pos = lineEnd + (lineEnd + 1 < data.length && data[lineEnd + 1] == '\n' ? 2 : 1);
                continue;
            }
            // 非 SSH banner 行，可能是协议前导注释，也收集
            if (line.trim().length() > 0) {
                SshMessage msg = new SshMessage();
                msg.type = -2;
                msg.typeName = "comment";
                msg.payload = lineBytes;
                messages.add(msg);
            }
            pos = lineEnd + (lineEnd + 1 < data.length && data[lineEnd + 1] == '\n' ? 2 : 1);
            // 如果下一字节不是文本，退出 banner 扫描
            if (pos < data.length && data[pos] < 0x20 && data[pos] != '\r' && data[pos] != '\n') {
                break;
            }
        }

        // 解析二进制包协议
        while (pos < data.length) {
            int startPos = pos;
            // 需要至少 4 字节包长度
            if (pos + 4 > data.length) {
                break;
            }
            long packetLength = readU32(data, pos);
            if (packetLength < 1 || packetLength > 0x100000) { // 最大 1MB
                break;
            }
            pos += 4;
            if (pos + packetLength > data.length) {
                break;
            }
            int paddingLength = data[pos] & 0xff;
            pos++;
            int payloadLen = (int) (packetLength - paddingLength - 1);
            if (payloadLen < 0 || payloadLen > packetLength) {
                break;
            }
            byte[] payload = Arrays.copyOfRange(data, pos, pos + payloadLen);
            pos += payloadLen;
            pos += paddingLength; // 跳过 padding

            SshMessage msg = new SshMessage();
            msg.type = payload.length > 0 ? payload[0] & 0xff : -1;
            msg.typeName = MSG_CODES.getOrDefault(msg.type, "UNKNOWN_" + msg.type);
            msg.payload = payload;
            messages.add(msg);
        }

        return messages;
    }

    private int findLineEnd(byte[] data, int start) {
        for (int i = start; i < data.length; i++) {
            if (data[i] == '\r') {
                return i;
            }
            if (data[i] == '\n') {
                return i;
            }
            // 如果看到二进制内容，说明 banner 结束
            if (data[i] < 0x20 && data[i] != '\t') {
                return -1;
            }
        }
        return -1;
    }

    private long readU32(byte[] data, int offset) {
        return ((data[offset] & 0xffL) << 24)
                | ((data[offset + 1] & 0xffL) << 16)
                | ((data[offset + 2] & 0xffL) << 8)
                | (data[offset + 3] & 0xffL);
    }

    /**
     * 解析 KEXINIT payload（去掉第一个字节消息码后的 payload）。
     */
    public Map<String, Object> parseKexInit(byte[] payload) {
        Map<String, Object> result = new LinkedHashMap<>();
        ByteReader r = new ByteReader(Arrays.copyOfRange(payload, 1, payload.length));

        byte[] cookie = r.bytes(16);
        result.put("cookie", CodecUtil.toHex(cookie));

        for (String field : KEXINIT_NAMELISTS) {
            result.put(field, readNameList(r));
        }

        int follows = r.u8();
        result.put("firstKexPacketFollows", follows >= 0 && follows != 0);
        long reserved = r.u32();
        result.put("reserved", reserved >= 0 ? reserved : null);
        result.put("truncated", r.isTruncated());

        return result;
    }

    private List<String> readNameList(ByteReader r) {
        long len = r.u32();
        if (len <= 0 || len > 0x10000) {
            return new ArrayList<>();
        }
        byte[] raw = r.bytes((int) len);
        String s = new String(raw, StandardCharsets.US_ASCII);
        if (s.isEmpty()) {
            return new ArrayList<>();
        }
        return new ArrayList<>(Arrays.asList(s.split(",")));
    }

    /**
     * 解析客户端 KEXDH_INIT / KEX_ECDH_INIT payload。
     */
    public byte[] parseKexDhInit(byte[] payload) {
        // 跳过第一个字节消息码，后面是 mpint（字符串类型）
        if (payload.length < 5) {
            return new byte[0];
        }
        ByteReader r = new ByteReader(Arrays.copyOfRange(payload, 1, payload.length));
        return readString(r);
    }

    /**
     * 解析服务端 KEXDH_REPLY / KEX_ECDH_REPLY payload。
     */
    public KexDhReply parseKexDhReply(byte[] payload) {
        KexDhReply reply = new KexDhReply();
        if (payload.length < 5) {
            return reply;
        }
        ByteReader r = new ByteReader(Arrays.copyOfRange(payload, 1, payload.length));
        reply.publicKeyBlob = readString(r);
        reply.signature = readSignature(r);
        reply.hasMore = r.remaining() > 0;
        return reply;
    }

    private byte[] readString(ByteReader r) {
        long len = r.u32();
        if (len < 0 || len > 0x100000) {
            return new byte[0];
        }
        return r.bytes((int) len);
    }

    private SshSignature readSignature(ByteReader r) {
        byte[] sigBlob = readString(r);
        SshSignature s = new SshSignature();
        s.value = sigBlob;
        if (sigBlob.length < 4) {
            return s;
        }
        ByteReader sr = new ByteReader(sigBlob);
        byte[] type = readString(sr);
        String typeStr = type.length > 0 ? new String(type, StandardCharsets.US_ASCII) : null;
        s.type = typeStr;
        s.value = readString(sr);
        return s;
    }

    /**
     * 读取 SSH 公钥 blob 开头的类型字符串（如 ssh-rsa、ecdsa-sha2-nistp256 等）。
     */
    public String parsePublicKeyType(byte[] publicKeyBlob) {
        if (publicKeyBlob == null || publicKeyBlob.length < 4) {
            return null;
        }
        ByteReader r = new ByteReader(publicKeyBlob);
        byte[] type = readString(r);
        if (type == null || type.length == 0) {
            return null;
        }
        return new String(type, StandardCharsets.US_ASCII);
    }

    public static class SshMessage {
        public int type;
        public String typeName;
        public byte[] payload;
        public String banner;
    }

    public static class KexDhReply {
        public byte[] publicKeyBlob;
        public SshSignature signature;
        public boolean hasMore;
    }

    public static class SshSignature {
        public String type;
        public byte[] value;
    }
}
