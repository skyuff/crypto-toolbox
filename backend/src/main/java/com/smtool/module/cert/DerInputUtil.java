package com.smtool.module.cert;

import com.smtool.util.CodecUtil;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.StringReader;
import java.security.PrivateKey;

/**
 * 证书 / CRL / ASN.1 输入的统一解析工具：
 * 支持 PEM（含 -----BEGIN...）、base64、hex 三种形式，最终统一转为 DER 字节数组。
 */
public final class DerInputUtil {

    private DerInputUtil() {
    }

    /**
     * 自动识别输入格式并返回 DER 字节。
     * 优先级：含 "-----BEGIN" 当作 PEM；否则尝试 hex；hex 失败再尝试 base64。
     */
    public static byte[] toDer(String input) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("输入内容为空");
        }
        String trimmed = input.trim();
        if (trimmed.contains("-----BEGIN")) {
            return readPem(trimmed);
        }
        // 优先尝试 hex（仅由十六进制字符组成时）
        String compact = trimmed.replaceAll("\\s", "");
        if (compact.matches("(?i)^(0x)?[0-9a-f]+$") && compact.replaceAll("(?i)^0x", "").length() % 2 == 0) {
            try {
                return CodecUtil.fromHex(compact);
            } catch (Exception ignore) {
                // 继续尝试 base64
            }
        }
        return CodecUtil.decode(trimmed, "base64");
    }

    /**
     * 按指定格式解析：pem / base64 / hex；为空或 auto 时自动识别。
     */
    public static byte[] toDer(String input, String format) {
        if (format == null || format.isBlank() || "auto".equalsIgnoreCase(format)) {
            return toDer(input);
        }
        return switch (format.trim().toLowerCase()) {
            case "pem" -> readPem(input.trim());
            case "base64" -> CodecUtil.decode(input.trim(), "base64");
            case "hex" -> CodecUtil.fromHex(input.trim());
            default -> throw new IllegalArgumentException("不支持的格式: " + format);
        };
    }

    /** 读取 PEM 文本，返回其内部 DER 内容 */
    public static byte[] readPem(String pem) {
        try (PemReader reader = new PemReader(new StringReader(pem))) {
            PemObject obj = reader.readPemObject();
            if (obj == null) {
                throw new IllegalArgumentException("PEM 内容无法解析，未找到有效的 -----BEGIN 块");
            }
            return obj.getContent();
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("PEM 解析失败: " + e.getMessage(), e);
        }
    }

    /** 解析 PEM / base64 DER PKCS#8 或 PKCS#1 私钥为 PrivateKey */
    public static PrivateKey parsePrivateKey(String input) throws Exception {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("私钥内容为空");
        }
        String trimmed = input.trim();
        if (!trimmed.contains("-----BEGIN")) {
            // base64 / hex DER，先转 PEM 方便 PEMParser 解析
            byte[] der = toDer(input);
            trimmed = "-----BEGIN PRIVATE KEY-----\n" +
                    java.util.Base64.getEncoder().encodeToString(der) +
                    "\n-----END PRIVATE KEY-----";
        }
        try (PEMParser parser = new PEMParser(new StringReader(trimmed))) {
            Object obj = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo info) {
                return converter.getPrivateKey(info);
            }
            if (obj instanceof org.bouncycastle.openssl.PEMKeyPair pair) {
                return converter.getPrivateKey(pair.getPrivateKeyInfo());
            }
            if (obj instanceof java.security.KeyPair kp) {
                return kp.getPrivate();
            }
            throw new IllegalArgumentException("不支持的私钥格式: " + (obj == null ? "null" : obj.getClass().getName()));
        }
    }
}
