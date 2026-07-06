package com.smtool.module.parse;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 在重组后的 TCP 字节流上切分 TLS Record 层，并提取 handshake 消息。
 */
@Service
public class TlsStreamParser {

    public static class HandshakeMessage {
        private final int type;
        private final byte[] payload;

        public HandshakeMessage(int type, byte[] payload) {
            this.type = type;
            this.payload = payload;
        }

        public int getType() {
            return type;
        }

        public byte[] getPayload() {
            return payload;
        }
    }

    /**
     * 从 TCP 字节流中提取所有 handshake 消息。
     */
    public List<HandshakeMessage> extractHandshakes(byte[] data) {
        List<HandshakeMessage> messages = new ArrayList<>();
        if (data == null || data.length < 5) {
            return messages;
        }
        int pos = 0;
        while (pos + 5 <= data.length) {
            int contentType = data[pos] & 0xff;
            int version = ((data[pos + 1] & 0xff) << 8) | (data[pos + 2] & 0xff);
            int length = ((data[pos + 3] & 0xff) << 8) | (data[pos + 4] & 0xff);
            if (contentType != 22) {
                // 非 handshake record，跳过该 record
                pos += 5 + length;
                continue;
            }
            if (pos + 5 + length > data.length) {
                break;
            }
            // 解析 handshake payload
            int hsStart = pos + 5;
            int hsEnd = hsStart + length;
            int hsPos = hsStart;
            while (hsPos + 4 <= hsEnd) {
                int hsType = data[hsPos] & 0xff;
                int hsLength = ((data[hsPos + 1] & 0xff) << 16)
                        | ((data[hsPos + 2] & 0xff) << 8)
                        | (data[hsPos + 3] & 0xff);
                if (hsPos + 4 + hsLength > hsEnd) {
                    break;
                }
                byte[] hsPayload = new byte[hsLength];
                System.arraycopy(data, hsPos + 4, hsPayload, 0, hsLength);
                messages.add(new HandshakeMessage(hsType, hsPayload));
                hsPos += 4 + hsLength;
            }
            pos = hsEnd;
        }
        return messages;
    }

    /**
     * 简单判断该字节流是否包含 TLS handshake 特征。
     */
    public boolean looksLikeTls(byte[] data) {
        if (data == null || data.length < 6) {
            return false;
        }
        int contentType = data[0] & 0xff;
        int version = ((data[1] & 0xff) << 8) | (data[2] & 0xff);
        int length = ((data[3] & 0xff) << 8) | (data[4] & 0xff);
        if (contentType != 22) {
            return false;
        }
        if (version != 0x0301 && version != 0x0302 && version != 0x0303
                && version != 0x0101 && version != 0x0300) {
            return false;
        }
        return data.length >= 5 + length && data[5] == 0x01; // ClientHello
    }
}
