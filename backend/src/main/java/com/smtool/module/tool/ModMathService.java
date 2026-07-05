package com.smtool.module.tool;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 取模运算服务：模加 / 模减 / 模乘 / 模逆 / 模幂。
 * 支持十六进制与 Base64 编码的无符号大整数输入输出。
 */
@Service
public class ModMathService {

    public Map<String, Object> calc(ModMathRequest req) {
        BigInteger a = parseUnsigned(req.getA(), req.getFormatA(), "a");
        BigInteger b = parseUnsigned(req.getB(), req.getFormatB(), "b");
        BigInteger m = parseUnsigned(req.getM(), req.getFormatM(), "m");

        if (m.signum() <= 0) {
            throw new IllegalArgumentException("模数 m 必须为正整数");
        }

        String op = req.getOp() == null ? "" : req.getOp().trim().toLowerCase();
        BigInteger result;
        try {
            result = switch (op) {
                case "add" -> a.add(b).mod(m);
                case "sub" -> a.subtract(b).mod(m);
                case "mul" -> a.multiply(b).mod(m);
                case "inv" -> a.modInverse(m);
                case "pow" -> a.modPow(b, m);
                default -> throw new IllegalArgumentException("不支持的运算: " + req.getOp());
            };
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("模逆不存在：" + e.getMessage());
        }

        String output = encodeResult(result, req.getFormatOut());
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("result", output);
        map.put("byteLength", resultByteLength(result));
        return map;
    }

    /**
     * 将输入按指定格式解码为字节数组后，解释为非负大整数。
     * 十六进制长度为奇数时自动在前面补 0。
     */
    private BigInteger parseUnsigned(String input, String format, String name) {
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
