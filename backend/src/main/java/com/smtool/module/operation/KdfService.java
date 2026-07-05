package com.smtool.module.operation;

import com.smtool.util.CodecUtil;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.*;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * GM/T（SM2/SM9）规范的 KDF 服务：基于哈希的计数器模式。
 * 对 i = 1..ceil(klen/vlen)：Ha_i = Hash(Z || ct)，ct 为 4 字节大端计数器；
 * 拼接所有 Ha_i 后取前 keyLength 字节。
 * 支持 SM3 / SHA-224 / SHA-256 / SHA-384 / SHA-512 / SHA3 系列 / SHA-1 / MD5。
 */
@Service
public class KdfService {

    /** 执行 KDF 计算 */
    public Map<String, Object> compute(KdfRequest req) throws Exception {
        String zFormat = req.getZFormat() == null || req.getZFormat().isBlank() ? "hex" : req.getZFormat();
        String normalizedZ = req.getZ();
        if ("hex".equalsIgnoreCase(zFormat) && normalizedZ != null) {
            normalizedZ = normalizeHex(normalizedZ);
        }
        byte[] z = CodecUtil.decode(normalizedZ, zFormat);
        byte[] key = kdf(newDigest(req.getHash()), z, req.getKeyLength());

        String output = CodecUtil.encode(key, req.getFormatOut());
        Map<String, Object> result = new HashMap<>();
        result.put("key", output);
        result.put("byteLength", key.length);
        result.put("keyLength", req.getKeyLength());
        result.put("hash", req.getHash());
        return result;
    }

    /**
     * GM/T KDF 计算（供 SM2 加密等场景复用）。
     *
     * @param digest 摘要引擎实例
     * @param z      共享秘密 Z
     * @param klen   期望密钥字节长度
     */
    public static byte[] kdf(Digest digest, byte[] z, int klen) {
        int vlen = digest.getDigestSize();
        int n = (klen + vlen - 1) / vlen; // ceil(klen / vlen)
        byte[] result = new byte[klen];
        int offset = 0;
        for (int i = 1; i <= n; i++) {
            digest.reset();
            digest.update(z, 0, z.length);
            // ct：4 字节大端计数器
            digest.update((byte) (i >>> 24));
            digest.update((byte) (i >>> 16));
            digest.update((byte) (i >>> 8));
            digest.update((byte) i);
            byte[] ha = new byte[vlen];
            digest.doFinal(ha, 0);

            int copy = Math.min(vlen, klen - offset);
            System.arraycopy(ha, 0, result, offset, copy);
            offset += copy;
        }
        return result;
    }

    /** 根据名称构造摘要引擎，默认 SM3 */
    public static Digest newDigest(String hash) {
        String h = hash == null ? "SM3" : hash.trim().toUpperCase().replace("-", "");
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

    /** 规整十六进制字符串：移除空白、冒号、0x 前缀；长度为奇数时前面补 0 */
    private String normalizeHex(String hex) {
        String s = hex.replaceAll("[\\s:,]", "").replaceAll("(?i)^0x", "");
        if (s.length() % 2 == 1) {
            s = "0" + s;
        }
        return s;
    }
}
