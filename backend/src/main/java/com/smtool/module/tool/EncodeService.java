package com.smtool.module.tool;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 编码转换服务：支持 utf8/hex/base64/base64url/url/base58/binary/decimal/bytes 之间的互转，
 * 以及字符集转换、简单算法识别。
 */
@Service
public class EncodeService {

    /** Base58（Bitcoin）字母表 */
    private static final String BASE58_ALPHABET =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger BASE58 = BigInteger.valueOf(58);

    /**
     * 单向编码转换：input(fromFormat) -> byte[] -> output(toFormat)。
     */
    public Map<String, Object> convert(EncodeRequest req) {
        byte[] data = decode(req.getInput(), req.getFromFormat());
        String output = encode(data, req.getToFormat());
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("output", output);
        result.put("byteLength", data.length);
        result.put("bitLength", data.length * 8L);
        return result;
    }

    /**
     * 一次性多向展示：把输入解析为 byte[] 后，同时输出字符串/十六进制/Base64/二进制表示，
     * 并给出基于长度的简单算法识别结果。
     */
    public Map<String, Object> all(EncodeRequest req) {
        byte[] data = decode(req.getInput(), req.getFromFormat());
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("byteLength", data.length);
        map.put("bitLength", data.length * 8L);
        map.put("string", encode(data, "utf8"));
        map.put("hex", encode(data, "hex"));
        map.put("base64", encode(data, "base64"));
        map.put("binary", encode(data, "binary"));
        map.put("detections", detectAlgorithms(data));
        return map;
    }

    /**
     * 字符集转换：按源字符集编码为字节，再按目标字符集解码为字符串。
     */
    public Map<String, Object> charsetConvert(CharsetConvertRequest req) {
        String input = req.getInput() == null ? "" : req.getInput();
        String from = req.getFromCharset() == null ? "UTF-8" : req.getFromCharset();
        String to = req.getToCharset() == null ? "GBK" : req.getToCharset();

        Charset fromCs = Charset.forName(from);
        Charset toCs = Charset.forName(to);

        byte[] bytes = input.getBytes(fromCs);
        String output = new String(bytes, toCs);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("output", output);
        result.put("byteLength", bytes.length);
        result.put("fromCharset", fromCs.name());
        result.put("toCharset", toCs.name());
        return result;
    }

    /**
     * 按指定格式将字符串解析为 byte[]。
     */
    public byte[] decode(String input, String format) {
        if (input == null) {
            input = "";
        }
        String fmt = format == null ? "utf8" : format.trim().toLowerCase();
        return switch (fmt) {
            case "utf8", "utf-8", "text", "str", "hex", "base64" -> CodecUtil.decode(input, fmt);
            case "binary" -> binaryDecode(input);
            case "base64url" -> base64UrlDecode(input);
            case "url" -> urlDecode(input);
            case "base58" -> base58Decode(input.trim());
            case "decimal" -> decimalDecode(input.trim());
            case "bytes" -> bytesDecode(input);
            default -> throw new IllegalArgumentException("不支持的编码格式: " + format);
        };
    }

    /**
     * 按指定格式将 byte[] 编码为字符串。
     */
    public String encode(byte[] data, String format) {
        String fmt = format == null ? "hex" : format.trim().toLowerCase();
        return switch (fmt) {
            case "utf8", "utf-8", "text", "str", "hex", "base64" -> CodecUtil.encode(data, fmt);
            case "binary" -> binaryEncode(data);
            case "base64url" -> base64UrlEncode(data);
            case "url" -> urlEncode(data);
            case "base58" -> base58Encode(data);
            case "decimal" -> new BigInteger(1, data).toString(10);
            case "bytes" -> bytesEncode(data);
            default -> throw new IllegalArgumentException("不支持的编码格式: " + format);
        };
    }

    // ==================== binary ====================

    private String binaryEncode(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(data.length * 8);
        for (byte b : data) {
            sb.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }
        return sb.toString();
    }

    private byte[] binaryDecode(String input) {
        String s = input.replaceAll("\\s", "");
        if (s.isEmpty()) {
            return new byte[0];
        }
        if (!s.matches("[01]+")) {
            throw new IllegalArgumentException("二进制格式只能包含 0 和 1");
        }
        // 不足 8 位时右侧补 0
        int pad = (8 - s.length() % 8) % 8;
        if (pad > 0) {
            s = s + "0".repeat(pad);
        }
        byte[] out = new byte[s.length() / 8];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 8, i * 8 + 8), 2);
        }
        return out;
    }

    // ==================== URL / Base64URL ====================

    private String urlEncode(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        return URLEncoder.encode(new String(data, StandardCharsets.UTF_8), StandardCharsets.UTF_8);
    }

    private byte[] urlDecode(String input) {
        String s = input.trim();
        if (s.isEmpty()) {
            return new byte[0];
        }
        String decoded = URLDecoder.decode(s, StandardCharsets.UTF_8);
        return decoded.getBytes(StandardCharsets.UTF_8);
    }

    private String base64UrlEncode(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private byte[] base64UrlDecode(String input) {
        String s = input.trim();
        if (s.isEmpty()) {
            return new byte[0];
        }
        // Base64URL 解码器需要正确的填充
        int pad = (4 - s.length() % 4) % 4;
        if (pad > 0) {
            s = s + "=".repeat(pad);
        }
        return java.util.Base64.getUrlDecoder().decode(s);
    }

    // ==================== base58 ====================

    private String base58Encode(byte[] data) {
        if (data.length == 0) {
            return "";
        }
        int zeros = 0;
        while (zeros < data.length && data[zeros] == 0) {
            zeros++;
        }
        BigInteger num = new BigInteger(1, data);
        StringBuilder sb = new StringBuilder();
        while (num.signum() > 0) {
            BigInteger[] qr = num.divideAndRemainder(BASE58);
            sb.append(BASE58_ALPHABET.charAt(qr[1].intValue()));
            num = qr[0];
        }
        for (int i = 0; i < zeros; i++) {
            sb.append(BASE58_ALPHABET.charAt(0));
        }
        return sb.reverse().toString();
    }

    private byte[] base58Decode(String input) {
        if (input.isEmpty()) {
            return new byte[0];
        }
        BigInteger num = BigInteger.ZERO;
        for (int i = 0; i < input.length(); i++) {
            int digit = BASE58_ALPHABET.indexOf(input.charAt(i));
            if (digit < 0) {
                throw new IllegalArgumentException("非法的 Base58 字符: " + input.charAt(i));
            }
            num = num.multiply(BASE58).add(BigInteger.valueOf(digit));
        }
        byte[] body = stripSignByte(num.toByteArray());
        int zeros = 0;
        while (zeros < input.length() && input.charAt(zeros) == BASE58_ALPHABET.charAt(0)) {
            zeros++;
        }
        byte[] out = new byte[zeros + body.length];
        System.arraycopy(body, 0, out, zeros, body.length);
        return out;
    }

    // ==================== decimal / bytes ====================

    private byte[] decimalDecode(String input) {
        if (input.isEmpty()) {
            return new byte[0];
        }
        return stripSignByte(new BigInteger(input, 10).toByteArray());
    }

    private byte[] bytesDecode(String input) {
        String trimmed = input.trim();
        if (trimmed.isEmpty()) {
            return new byte[0];
        }
        String[] parts = trimmed.split("[,\\s]+");
        byte[] out = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i].trim();
            if (p.isEmpty()) {
                continue;
            }
            int v;
            if (p.regionMatches(true, 0, "0x", 0, 2)) {
                v = Integer.parseInt(p.substring(2), 16);
            } else {
                v = Integer.parseInt(p, 10);
            }
            out[i] = (byte) v;
        }
        return out;
    }

    private String bytesEncode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(String.format("0x%02X", data[i] & 0xFF));
        }
        return sb.toString();
    }

    // ==================== helpers ====================

    private byte[] stripSignByte(byte[] arr) {
        if (arr.length > 1 && arr[0] == 0) {
            byte[] out = new byte[arr.length - 1];
            System.arraycopy(arr, 1, out, 0, out.length);
            return out;
        }
        return arr;
    }

    /**
     * 基于数据长度做简单的算法识别，仅作参考。
     */
    private Map<String, String> detectAlgorithms(byte[] data) {
        Map<String, String> map = new LinkedHashMap<>();
        int len = data.length;

        String hash = switch (len) {
            case 16 -> "MD5 / MD4 / MD2";
            case 20 -> "SHA-1 / RIPEMD-160";
            case 28 -> "SHA-224";
            case 32 -> "SHA-256 / SM3";
            case 48 -> "SHA-384";
            case 64 -> "SHA-512";
            default -> null;
        };
        map.put("hash", hash != null ? hash : "无");

        String symmetric = switch (len) {
            case 8 -> "DES";
            case 16 -> "AES-128 / SM4";
            case 24 -> "AES-192 / 3DES-168";
            case 32 -> "AES-256";
            default -> null;
        };
        map.put("symmetric", symmetric != null ? symmetric : "无");

        String asymmetric = "无";
        if (len > 0 && (data[0] & 0xFF) == 0x30) {
            asymmetric = "可能是 DER 编码的密钥/证书（需进一步解析）";
        }
        map.put("asymmetric", asymmetric);
        return map;
    }
}
