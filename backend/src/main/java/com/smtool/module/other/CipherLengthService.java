package com.smtool.module.other;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 常见密文长度分析服务。
 *
 * <p>根据用户输入数据的长度（字节/比特），匹配可能对应的哈希算法、对称算法和非对称算法，
 * 并返回完整算法分组与安全强度表。</p>
 */
@Service
public class CipherLengthService {

    /** 算法分类 */
    public enum Category {
        HASH("哈希算法"),
        SYMMETRIC("对称算法"),
        ASYMMETRIC("非对称算法");

        public final String label;

        Category(String label) {
            this.label = label;
        }
    }

    /** 算法元信息 */
    public record AlgorithmInfo(Category category, String name, int lengthBits,
                                 String lengthDescription, Integer securityBits) {
    }

    private static final List<AlgorithmInfo> ALGORITHMS = new ArrayList<>();

    static {
        // 哈希算法：输出长度固定
        addHash("MD5", 128, 64);
        addHash("SHA-1", 160, 80);
        addHash("SHA-224", 224, 112);
        addHash("SHA-256", 256, 128);
        addHash("SHA-384", 384, 192);
        addHash("SHA-512", 512, 256);
        addHash("SHA-512/224", 224, 112);
        addHash("SHA-512/256", 256, 128);
        addHash("SHA3-224", 224, 112);
        addHash("SHA3-256", 256, 128);
        addHash("SHA3-384", 384, 192);
        addHash("SHA3-512", 512, 256);
        addHash("SM3", 256, 128);
        addHash("RIPEMD-160", 160, 80);
        addHash("Whirlpool", 512, 256);
        addHash("BLAKE2b-256", 256, 128);
        addHash("BLAKE2b-512", 512, 256);
        addHash("BLAKE2s-256", 256, 128);

        // 对称分组算法：密文长度为分组长度的整数倍
        addSymmetricBlock("AES-128", 128, 128);
        addSymmetricBlock("AES-192", 128, 192);
        addSymmetricBlock("AES-256", 128, 256);
        addSymmetricBlock("SM4", 128, 128);
        addSymmetricBlock("SM1", 128, 128);
        addSymmetricBlock("SEED", 128, 128);
        addSymmetricBlock("ARIA-128", 128, 128);
        addSymmetricBlock("ARIA-192", 128, 192);
        addSymmetricBlock("ARIA-256", 128, 256);
        addSymmetricBlock("Camellia-128", 128, 128);
        addSymmetricBlock("Camellia-192", 128, 192);
        addSymmetricBlock("Camellia-256", 128, 256);
        addSymmetricBlock("Twofish-256", 128, 256);
        addSymmetricBlock("CAST6", 128, 256);
        addSymmetricBlock("Kuznyechik", 128, 256);
        addSymmetricBlock("DES", 64, 56);
        addSymmetricBlock("3DES-2key", 64, 80);
        addSymmetricBlock("3DES-3key", 64, 112);
        addSymmetricBlock("IDEA", 64, 128);
        addSymmetricBlock("RC2", 64, null);
        addSymmetricBlock("Blowfish", 64, null);
        addSymmetricBlock("CAST5", 64, null);
        addSymmetricBlock("Magma", 64, 256);

        // 对称流式算法：密文长度与明文长度相同，任意长度都可能
        addSymmetricStream("RC4-40", 40);
        addSymmetricStream("RC4-128", 128);
        addSymmetricStream("ChaCha20", 256);
        addSymmetricStream("Salsa20", 256);
        addSymmetricStream("Salsa20/12", 128);
        addSymmetricStream("HC-128", 128);
        addSymmetricStream("Rabbit", 128);
        addSymmetricStream("ZUC-128", 128);
        addSymmetricStream("ZUC-256", 256);

        // 非对称算法：签名/模数长度为固定值
        addAsymmetric("RSA-512", 512, 0);
        addAsymmetric("RSA-1024", 1024, 80);
        addAsymmetric("RSA-2048", 2048, 112);
        addAsymmetric("RSA-3072", 3072, 128);
        addAsymmetric("RSA-4096", 4096, 140);
        addAsymmetric("RSA-8192", 8192, 192);
        addAsymmetric("ECDSA-secp192r1", 48 * 8, 96);
        addAsymmetric("ECDSA-secp224r1", 56 * 8, 112);
        addAsymmetric("ECDSA-secp256r1", 64 * 8, 128);
        addAsymmetric("ECDSA-secp384r1", 96 * 8, 192);
        addAsymmetric("ECDSA-secp521r1", 132 * 8, 256);
        addAsymmetric("ECDSA-brainpoolP256r1", 64 * 8, 128);
        addAsymmetric("ECDSA-brainpoolP384r1", 96 * 8, 192);
        addAsymmetric("ECDSA-brainpoolP512r1", 128 * 8, 256);
        addAsymmetric("SM2-签名", 64 * 8, 128);
        addAsymmetric("Ed25519", 64 * 8, 128);
        addAsymmetric("Ed448", 114 * 8, 224);
        addAsymmetric("DSA-1024", 40 * 8, 80);
        addAsymmetric("DSA-2048", 56 * 8, 112);
        addAsymmetric("DSA-3072", 64 * 8, 128);
    }

    private static void addHash(String name, int lengthBits, int securityBits) {
        ALGORITHMS.add(new AlgorithmInfo(Category.HASH, name, lengthBits,
                lengthBits + " bit (" + (lengthBits / 8) + " 字节)", securityBits));
    }

    private static void addSymmetricBlock(String name, int blockBits, Integer securityBits) {
        ALGORITHMS.add(new AlgorithmInfo(Category.SYMMETRIC, name, blockBits,
                "分组 " + blockBits + " bit (" + (blockBits / 8) + " 字节)", securityBits));
    }

    private static void addSymmetricStream(String name, Integer securityBits) {
        ALGORITHMS.add(new AlgorithmInfo(Category.SYMMETRIC, name, 0,
                "流式算法（密文长度 = 明文长度）", securityBits));
    }

    private static void addAsymmetric(String name, int lengthBits, Integer securityBits) {
        ALGORITHMS.add(new AlgorithmInfo(Category.ASYMMETRIC, name, lengthBits,
                lengthBits + " bit (" + (lengthBits / 8) + " 字节)", securityBits));
    }

    /** 执行长度分析。 */
    public Map<String, Object> analyze(CipherLengthRequest req) {
        byte[] data = CodecUtil.decode(req.getInput(), req.getFormat());
        int bytes = data.length;
        int bits = bytes * 8;

        List<Map<String, Object>> hashMatches = new ArrayList<>();
        List<Map<String, Object>> symmetricMatches = new ArrayList<>();
        List<Map<String, Object>> asymmetricMatches = new ArrayList<>();

        for (AlgorithmInfo info : ALGORITHMS) {
            boolean matched = isMatched(info, bytes, bits);
            if (matched) {
                Map<String, Object> item = toMap(info, true);
                switch (info.category) {
                    case HASH -> hashMatches.add(item);
                    case SYMMETRIC -> symmetricMatches.add(item);
                    case ASYMMETRIC -> asymmetricMatches.add(item);
                }
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("inputLengthBytes", bytes);
        result.put("inputLengthBits", bits);
        result.put("matches", Map.of(
                "hash", hashMatches,
                "symmetric", symmetricMatches,
                "asymmetric", asymmetricMatches
        ));
        return result;
    }

    /** 返回全部算法清单（不含匹配标记）。 */
    public List<Map<String, Object>> algorithms() {
        List<Map<String, Object>> list = new ArrayList<>();
        for (AlgorithmInfo info : ALGORITHMS) {
            list.add(toMap(info, false));
        }
        return list;
    }

    private boolean isMatched(AlgorithmInfo info, int bytes, int bits) {
        return switch (info.category) {
            case HASH -> bits == info.lengthBits;
            case SYMMETRIC -> {
                if (info.lengthBits == 0) {
                    yield true; // 流式算法任意长度都可能
                }
                // 分组算法：密文长度应为分组长度的正整数倍
                yield bits > 0 && bits % info.lengthBits == 0;
            }
            case ASYMMETRIC -> bits == info.lengthBits;
        };
    }

    private Map<String, Object> toMap(AlgorithmInfo info, boolean matched) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("category", info.category.name().toLowerCase());
        map.put("categoryLabel", info.category.label);
        map.put("name", info.name);
        map.put("lengthBits", info.lengthBits);
        map.put("lengthDescription", info.lengthDescription);
        map.put("securityBits", info.securityBits);
        map.put("matched", matched);
        return map;
    }
}
