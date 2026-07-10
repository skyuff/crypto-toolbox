package com.smtool.util;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;

/**
 * 通用编码转换工具：支持 hex / base64 / utf8 与字节数组互转。
 * 大部分密码模块的输入输出都基于此工具做统一编码处理。
 */
public final class CodecUtil {

    private CodecUtil() {
    }

    public enum Format {
        HEX, BASE64, UTF8
    }

    public static Format parseFormat(String name) {
        if (name == null || name.isBlank()) {
            return Format.HEX;
        }
        return switch (name.trim().toLowerCase()) {
            case "hex" -> Format.HEX;
            case "base64" -> Format.BASE64;
            case "utf8", "utf-8", "text", "str" -> Format.UTF8;
            default -> throw new IllegalArgumentException("不支持的编码格式: " + name);
        };
    }

    /**
     * 按指定格式将字符串解码为字节数组。
     */
    public static byte[] decode(String input, String format) {
        return decode(input, parseFormat(format));
    }

    public static byte[] decode(String input, Format format) {
        if (input == null) {
            return new byte[0];
        }
        return switch (format) {
            case HEX -> Hex.decode(cleanHex(input));
            case BASE64 -> Base64.decode(input.trim());
            case UTF8 -> input.getBytes(StandardCharsets.UTF_8);
        };
    }

    /**
     * 按指定格式将字节数组编码为字符串。
     */
    public static String encode(byte[] data, String format) {
        return encode(data, parseFormat(format));
    }

    public static String encode(byte[] data, Format format) {
        if (data == null) {
            return "";
        }
        return switch (format) {
            case HEX -> Hex.toHexString(data);
            case BASE64 -> Base64.toBase64String(data);
            case UTF8 -> new String(data, StandardCharsets.UTF_8);
        };
    }

    public static String toHex(byte[] data) {
        return Hex.toHexString(data);
    }

    public static byte[] fromHex(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex 字符串不能为 null");
        }
        return Hex.decode(cleanHex(hex));
    }

    private static String cleanHex(String hex) {
        return hex.replaceAll("[\\s:,]", "").replaceAll("(?i)^0x", "");
    }
}
