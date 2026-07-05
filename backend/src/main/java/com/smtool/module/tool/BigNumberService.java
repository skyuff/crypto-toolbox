package com.smtool.module.tool;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 大数运算服务：基于 java.math.BigInteger。
 * 支持对十六进制或 Base64 编码的无符号大整数进行加、减、乘运算。
 * 减法按较长操作数的字节长度取模，结果始终为非负数。
 */
@Service
public class BigNumberService {

    public Map<String, Object> calc(BigNumberRequest req) {
        BigInteger a = parseUnsigned(req.getA(), req.getFormatA());
        BigInteger b = parseUnsigned(req.getB(), req.getFormatB());
        String op = req.getOp() == null ? "" : req.getOp().trim().toLowerCase();

        BigInteger result = switch (op) {
            case "add" -> a.add(b);
            case "sub" -> {
                int maxBytes = Math.max(unsignedByteLength(a), unsignedByteLength(b));
                BigInteger modulus = BigInteger.ONE.shiftLeft(maxBytes * 8);
                yield a.subtract(b).mod(modulus);
            }
            case "mul" -> a.multiply(b);
            default -> throw new IllegalArgumentException("不支持的运算: " + req.getOp());
        };

        String output = encodeResult(result, req.getFormatOut());
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("result", output);
        map.put("byteLength", resultByteLength(result));
        return map;
    }

    /**
     * 将输入按指定格式解码为字节数组后，解释为非负大整数。
     * 十六进制长度为奇数时自动在前面补 0，避免解码失败。
     */
    private BigInteger parseUnsigned(String input, String format) {
        if (input == null || input.isBlank()) {
            return BigInteger.ZERO;
        }
        String normalized = input;
        if ("hex".equalsIgnoreCase(format)) {
            normalized = normalizeHex(input);
        }
        byte[] bytes = CodecUtil.decode(normalized, format);
        if (bytes.length == 0) {
            return BigInteger.ZERO;
        }
        return new BigInteger(1, bytes);
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
     * 计算无符号大整数的字节长度（至少 1 字节）。
     */
    private int unsignedByteLength(BigInteger value) {
        if (value.signum() == 0) {
            return 1;
        }
        return (value.bitLength() + 7) / 8;
    }

    /**
     * 将运算结果按指定格式编码输出，十六进制不带 0x 前缀。
     */
    private String encodeResult(BigInteger value, String format) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            bytes = trimmed;
        }
        return CodecUtil.encode(bytes, format);
    }

    /**
     * 计算结果的字节长度。
     */
    private int resultByteLength(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return bytes.length - 1;
        }
        return bytes.length;
    }
}
