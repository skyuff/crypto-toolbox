package com.smtool.module.parse;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
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
     * 单向 TCP 流上的 TLS Record 特征：handshake 消息、是否出现 ChangeCipherSpec、Application Data。
     */
    public static class StreamFeatures {
        private final List<HandshakeMessage> handshakes = new ArrayList<>();
        private boolean sawChangeCipherSpec;
        private boolean sawApplicationData;

        public List<HandshakeMessage> getHandshakes() {
            return handshakes;
        }

        public boolean isSawChangeCipherSpec() {
            return sawChangeCipherSpec;
        }

        public void setSawChangeCipherSpec(boolean sawChangeCipherSpec) {
            this.sawChangeCipherSpec = sawChangeCipherSpec;
        }

        public boolean isSawApplicationData() {
            return sawApplicationData;
        }

        public void setSawApplicationData(boolean sawApplicationData) {
            this.sawApplicationData = sawApplicationData;
        }
    }

    /**
     * 从 TCP 字节流中提取 handshake 消息，并记录 ChangeCipherSpec / Application Data 出现情况。
     */
    public StreamFeatures extractFeatures(byte[] data) {
        StreamFeatures features = new StreamFeatures();
        List<HandshakeMessage> messages = features.getHandshakes();
        if (data == null || data.length < 5) {
            return features;
        }
        int pos = 0;
        // 跨 record 的 handshake 字节缓冲
        byte[] pending = new byte[0];
        while (pos + 5 <= data.length) {
            int contentType = data[pos] & 0xff;
            int version = ((data[pos + 1] & 0xff) << 8) | (data[pos + 2] & 0xff);
            int length = ((data[pos + 3] & 0xff) << 8) | (data[pos + 4] & 0xff);
            if (length < 0 || pos + 5 + length > data.length) {
                break;
            }
            if (contentType == 20) {
                features.setSawChangeCipherSpec(true);
                pos += 5 + length;
                continue;
            }
            if (contentType == 23) {
                features.setSawApplicationData(true);
                pos += 5 + length;
                continue;
            }
            if (contentType != 22) {
                // 非 handshake / CCS / app_data record，跳过该 record
                pos += 5 + length;
                continue;
            }
            // 累积当前 record 的 handshake payload
            int recordStart = pos + 5;
            pending = concat(pending, data, recordStart, length);
            // 从 pending 中切出完整的 handshake 消息
            int p = 0;
            while (p + 4 <= pending.length) {
                int hsType = pending[p] & 0xff;
                int hsLength = ((pending[p + 1] & 0xff) << 16)
                        | ((pending[p + 2] & 0xff) << 8)
                        | (pending[p + 3] & 0xff);
                if (hsLength < 0 || p + 4 + hsLength > pending.length) {
                    break;
                }
                byte[] hsPayload = new byte[hsLength];
                System.arraycopy(pending, p + 4, hsPayload, 0, hsLength);
                messages.add(new HandshakeMessage(hsType, hsPayload));
                p += 4 + hsLength;
            }
            if (p > 0) {
                pending = Arrays.copyOfRange(pending, p, pending.length);
            }
            pos += 5 + length;
        }
        return features;
    }

    /**
     * 兼容旧接口：仅返回 handshake 消息列表。
     */
    public List<HandshakeMessage> extractHandshakes(byte[] data) {
        return extractFeatures(data).getHandshakes();
    }

    private byte[] concat(byte[] prefix, byte[] data, int start, int len) {
        if (len <= 0) {
            return prefix;
        }
        byte[] out = new byte[prefix.length + len];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(data, start, out, prefix.length, len);
        return out;
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
        if (!isPlausibleTlsVersion(version)) {
            return false;
        }
        if (data.length < 5 + length) {
            return false;
        }
        int hsType = data[5] & 0xff;
        // ClientHello / ServerHello / HelloRetryRequest
        return hsType == 0x01 || hsType == 0x02 || hsType == 0x06;
    }

    private boolean isPlausibleTlsVersion(int version) {
        int major = (version >>> 8) & 0xff;
        // TLS 1.x / SSL 3.0 记录层、GM/T TLCP 1.1、TLS 1.3 草案
        return major == 0x03 || major == 0x01 || (version & 0xff00) == 0x7f00;
    }
}
