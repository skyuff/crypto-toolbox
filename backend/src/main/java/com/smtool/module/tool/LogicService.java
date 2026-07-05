package com.smtool.module.tool;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 逻辑运算服务：字节数组的 xor/and/or/not 及比特循环位移。
 * 支持十六进制与 Base64 编码输入输出。
 * xor/and/or 在两操作数不等长时，以较短长度按字节对齐处理。
 */
@Service
public class LogicService {

    public Map<String, Object> calc(LogicRequest req) {
        byte[] a = decodeNormalized(req.getA(), req.getFormatA());
        String op = req.getOp() == null ? "" : req.getOp().trim().toLowerCase();

        byte[] result;
        switch (op) {
            case "xor", "and", "or" -> {
                byte[] b = decodeNormalized(req.getB(), req.getFormatB());
                // 不等长时以较短长度按字节对齐处理
                int len = Math.min(a.length, b.length);
                result = new byte[len];
                for (int i = 0; i < len; i++) {
                    result[i] = switch (op) {
                        case "xor" -> (byte) (a[i] ^ b[i]);
                        case "and" -> (byte) (a[i] & b[i]);
                        default -> (byte) (a[i] | b[i]);
                    };
                }
            }
            case "not" -> {
                result = new byte[a.length];
                for (int i = 0; i < a.length; i++) {
                    result[i] = (byte) (~a[i]);
                }
            }
            case "shl" -> result = rotateLeft(a, req.getShift());
            case "shr" -> result = rotateRight(a, req.getShift());
            default -> throw new IllegalArgumentException("不支持的运算: " + req.getOp());
        }

        String output = CodecUtil.encode(result, req.getFormatOut());
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("result", output);
        map.put("byteLength", result.length);
        return map;
    }

    /**
     * 将输入按指定格式解码为字节数组；十六进制长度为奇数时自动前面补 0。
     */
    private byte[] decodeNormalized(String input, String format) {
        if (input == null || input.isBlank()) {
            return new byte[0];
        }
        String normalized = input;
        if ("hex".equalsIgnoreCase(format)) {
            normalized = normalizeHex(input);
        }
        return CodecUtil.decode(normalized, format);
    }

    /**
     * 规整十六进制字符串：移除空白、冒号、0x 前缀；长度为奇数时前面补 0。
     */
    private String normalizeHex(String hex) {
        String s = hex.replaceAll("[\\s:,]", "").replaceAll("(?i)^0x", "");
        if (s.length() % 2 == 1) {
            s = "0" + s;
        }
        return s;
    }

    /**
     * 对整个字节数组做比特级循环左移。
     */
    private byte[] rotateLeft(byte[] data, int shift) {
        int totalBits = data.length * 8;
        if (totalBits == 0) {
            return data.clone();
        }
        int s = ((shift % totalBits) + totalBits) % totalBits;
        byte[] out = new byte[data.length];
        for (int i = 0; i < totalBits; i++) {
            int bit = getBit(data, (i + s) % totalBits);
            setBit(out, i, bit);
        }
        return out;
    }

    /**
     * 对整个字节数组做比特级循环右移。
     */
    private byte[] rotateRight(byte[] data, int shift) {
        return rotateLeft(data, -shift);
    }

    /**
     * 读取第 index 个比特（从最高位字节的最高位开始计数）。
     */
    private int getBit(byte[] data, int index) {
        int byteIdx = index / 8;
        int bitIdx = 7 - (index % 8);
        return (data[byteIdx] >> bitIdx) & 1;
    }

    /**
     * 设置第 index 个比特。
     */
    private void setBit(byte[] data, int index, int value) {
        int byteIdx = index / 8;
        int bitIdx = 7 - (index % 8);
        if (value != 0) {
            data[byteIdx] |= (byte) (1 << bitIdx);
        } else {
            data[byteIdx] &= (byte) ~(1 << bitIdx);
        }
    }
}
