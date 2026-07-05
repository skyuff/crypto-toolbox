package com.smtool.module.parse;

import java.util.Arrays;

/**
 * 二进制报文顺序读取器：为 TLS / SSH / IKE / APDU 等报文解析提供健壮的字节读取能力。
 * 越界读取时不抛异常，而是通过 {@link #isTruncated()} 标记，便于「已解析部分 + truncated」的解析策略。
 */
class ByteReader {

    private final byte[] data;
    private int pos;
    private boolean truncated;

    ByteReader(byte[] data) {
        this.data = data == null ? new byte[0] : data;
    }

    /** 剩余可读字节数 */
    int remaining() {
        return data.length - pos;
    }

    /** 当前读取位置 */
    int position() {
        return pos;
    }

    /** 是否发生过越界（数据不足）读取 */
    boolean isTruncated() {
        return truncated;
    }

    /** 是否还能读取 n 个字节 */
    boolean has(int n) {
        return remaining() >= n;
    }

    /** 读取 1 字节无符号整数，不足则标记 truncated 并返回 -1 */
    int u8() {
        if (!has(1)) {
            truncated = true;
            return -1;
        }
        return data[pos++] & 0xFF;
    }

    /** 读取 2 字节大端无符号整数，不足则标记 truncated 并返回 -1 */
    int u16() {
        if (!has(2)) {
            truncated = true;
            pos = data.length;
            return -1;
        }
        int v = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
        pos += 2;
        return v;
    }

    /** 读取 3 字节大端无符号整数，不足则标记 truncated 并返回 -1 */
    int u24() {
        if (!has(3)) {
            truncated = true;
            pos = data.length;
            return -1;
        }
        int v = ((data[pos] & 0xFF) << 16) | ((data[pos + 1] & 0xFF) << 8) | (data[pos + 2] & 0xFF);
        pos += 3;
        return v;
    }

    /** 读取 4 字节大端无符号整数，不足则标记 truncated 并返回 -1 */
    long u32() {
        if (!has(4)) {
            truncated = true;
            pos = data.length;
            return -1;
        }
        long v = ((long) (data[pos] & 0xFF) << 24) | ((data[pos + 1] & 0xFF) << 16)
                | ((data[pos + 2] & 0xFF) << 8) | (data[pos + 3] & 0xFF);
        pos += 4;
        return v;
    }

    /**
     * 读取 n 个字节；若不足则读取剩余全部并标记 truncated。
     */
    byte[] bytes(int n) {
        if (n < 0) {
            n = 0;
        }
        if (!has(n)) {
            truncated = true;
            byte[] out = Arrays.copyOfRange(data, pos, data.length);
            pos = data.length;
            return out;
        }
        byte[] out = Arrays.copyOfRange(data, pos, pos + n);
        pos += n;
        return out;
    }
}
