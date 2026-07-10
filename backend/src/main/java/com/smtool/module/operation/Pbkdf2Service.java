package com.smtool.module.operation;

import com.smtool.util.CodecUtil;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 口令密钥派生 PBKDF2 服务。
 * 基于 BouncyCastle 的 PKCS5S2ParametersGenerator 实现，
 * 支持 SM3 / SHA-224 / SHA-256 / SHA-384 / SHA-512 / SHA3-224 / SHA3-256 / SHA3-384 / SHA3-512 / SHA-1 / MD5 多种摘要算法。
 */
@Service
public class Pbkdf2Service {

    /** 执行 PBKDF2 派生 */
    public Map<String, Object> derive(Pbkdf2Request req) {
        int iterations = req.getIterations() <= 0 ? 100000 : req.getIterations();
        int keyLength = req.getKeyLength() <= 0 ? 32 : req.getKeyLength();
        String prf = normalizePrf(req.getPrf());
        String outputFmt = normalizeFormat(req.getOutputFormat(), "hex");

        // 解析口令与盐值字节
        byte[] password = CodecUtil.decode(req.getPassword(),
                req.getPasswordFormat() == null || req.getPasswordFormat().isBlank()
                        ? "utf8" : req.getPasswordFormat());
        byte[] salt = CodecUtil.decode(req.getSalt(),
                req.getSaltFormat() == null || req.getSaltFormat().isBlank()
                        ? "hex" : req.getSaltFormat());

        // 构造 PBKDF2 生成器并派生密钥
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(newDigest(prf));
        generator.init(password, salt, iterations);
        KeyParameter keyParam = (KeyParameter) generator.generateDerivedParameters(keyLength * 8);
        byte[] key = keyParam.getKey();

        Map<String, Object> map = new LinkedHashMap<>();
        map.put("key", CodecUtil.encode(key, outputFmt));
        map.put("keyLength", keyLength);
        map.put("iterations", iterations);
        map.put("prf", prf);
        return map;
    }

    /** 根据 PRF 名称构造底层摘要引擎 */
    private Digest newDigest(String prf) {
        String p = normalizePrf(prf);
        return switch (p) {
            case "SM3" -> new SM3Digest();
            case "SHA-224" -> new SHA224Digest();
            case "SHA-256" -> new SHA256Digest();
            case "SHA-384" -> new SHA384Digest();
            case "SHA-512" -> new SHA512Digest();
            case "SHA3-224" -> new SHA3Digest(224);
            case "SHA3-256" -> new SHA3Digest(256);
            case "SHA3-384" -> new SHA3Digest(384);
            case "SHA3-512" -> new SHA3Digest(512);
            case "SHA-1" -> new SHA1Digest();
            case "MD5" -> new MD5Digest();
            default -> throw new IllegalArgumentException("不支持的 PRF: " + prf);
        };
    }

    /** 统一 PRF 名称 */
    private static String normalizePrf(String prf) {
        if (prf == null || prf.isBlank()) {
            return "SHA-256";
        }
        String p = prf.trim().toUpperCase().replace("_", "-");
        // 去掉 HMAC- 前缀
        if (p.startsWith("HMAC-")) {
            p = p.substring(5);
        }
        return p;
    }

    private static String normalizeFormat(String format, String defaultValue) {
        if (format == null || format.isBlank()) {
            return defaultValue;
        }
        return format.trim().toLowerCase();
    }
}
