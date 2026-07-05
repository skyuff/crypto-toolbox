package com.smtool.module.operation;

import com.smtool.util.CodecUtil;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * TLS 1.2 PRF 运算服务。
 * PRF(secret, label, seed) = P_hash(secret, label || seed)。
 * 支持 SM3 / SHA-224 / SHA-256 / SHA-384 / SHA-512 / SHA3 系列 / SHA-1 / MD5。
 */
@Service
public class PrfService {

    /** 执行 PRF 计算 */
    public Map<String, Object> compute(PrfRequest req) throws Exception {
        byte[] secret = decode(req.getSecret(), req.getSecretFormat());
        byte[] labelBytes = req.getLabel() == null
                ? new byte[0] : req.getLabel().getBytes(StandardCharsets.UTF_8);
        byte[] seed = decode(req.getSeed(), req.getSeedFormat());

        // seed' = label_bytes + seed_bytes
        byte[] labelSeed = concat(labelBytes, seed);

        Digest digest = newDigest(req.getHash());
        int hashLen = digest.getDigestSize();
        int length = req.getIterations() > 0
                ? req.getIterations() * hashLen
                : req.getOutputLength();
        if (length <= 0) {
            throw new IllegalArgumentException("迭代轮数或输出长度必须大于 0");
        }

        byte[] output = pHash(digest, secret, labelSeed, length);

        String outputEncoded = CodecUtil.encode(output, req.getFormatOut());
        Map<String, Object> result = new HashMap<>();
        result.put("output", outputEncoded);
        result.put("byteLength", output.length);
        result.put("hash", req.getHash());
        result.put("iterations", req.getIterations());
        return result;
    }

    /**
     * 标准 TLS 1.2 P_hash 实现（供 PRF 与 TLS 密钥派生共用）。
     * A(0) = seed'（即 label||seed）；A(i) = HMAC(secret, A(i-1))。
     * 输出块 = HMAC(secret, A(i) || seed')，拼接直到够长后截断。
     *
     * @param digest   底层摘要算法（每次调用应传入全新实例）
     * @param secret   HMAC 密钥
     * @param seed     seed'（label||seed）
     * @param length   期望输出字节数
     */
    public static byte[] pHash(Digest digest, byte[] secret, byte[] seed, int length) {
        HMac hmac = new HMac(digest);
        hmac.init(new KeyParameter(secret));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // A(1) = HMAC(secret, seed')
        byte[] a = hmac(hmac, seed);
        while (out.size() < length) {
            // 结果块 = HMAC(secret, A(i) || seed')
            byte[] block = hmac(hmac, concat(a, seed));
            out.write(block, 0, block.length);
            // A(i+1) = HMAC(secret, A(i))
            a = hmac(hmac, a);
        }
        byte[] full = out.toByteArray();
        byte[] result = new byte[length];
        System.arraycopy(full, 0, result, 0, length);
        return result;
    }

    /** 计算一次 HMAC（复用同一 HMac 实例，内部会 reset） */
    private static byte[] hmac(HMac hmac, byte[] input) {
        hmac.reset();
        hmac.update(input, 0, input.length);
        byte[] out = new byte[hmac.getMacSize()];
        hmac.doFinal(out, 0);
        return out;
    }

    /** 根据名称构造摘要引擎 */
    public static Digest newDigest(String hash) {
        String h = hash == null ? "SHA256" : hash.trim().toUpperCase().replace("-", "");
        return switch (h) {
            case "SHA224" -> new SHA224Digest();
            case "SHA256" -> new SHA256Digest();
            case "SHA384" -> new SHA384Digest();
            case "SHA512" -> new SHA512Digest();
            case "SHA3224" -> new SHA3Digest(224);
            case "SHA3256" -> new SHA3Digest(256);
            case "SHA3384" -> new SHA3Digest(384);
            case "SHA3512" -> new SHA3Digest(512);
            case "SHA1" -> new SHA1Digest();
            case "MD5" -> new MD5Digest();
            case "SM3" -> new SM3Digest();
            default -> throw new IllegalArgumentException("不支持的哈希算法: " + hash);
        };
    }

    /** 按指定格式解码输入；字符串格式直接取 UTF-8 字节 */
    private byte[] decode(String input, String format) {
        if (input == null || input.isBlank()) {
            return new byte[0];
        }
        if ("string".equalsIgnoreCase(format) || "utf8".equalsIgnoreCase(format)) {
            return input.getBytes(StandardCharsets.UTF_8);
        }
        String normalized = input;
        if ("hex".equalsIgnoreCase(format)) {
            normalized = normalizeHex(input);
        }
        return CodecUtil.decode(normalized, format);
    }

    /** 规整十六进制字符串：移除空白、冒号、0x 前缀；长度为奇数时前面补 0 */
    private String normalizeHex(String hex) {
        String s = hex.replaceAll("[\\s:,]", "").replaceAll("(?i)^0x", "");
        if (s.length() % 2 == 1) {
            s = "0" + s;
        }
        return s;
    }

    /** 字节数组拼接 */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}
