package com.smtool.module.hash;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.util.*;

/**
 * 哈希（杂凑）算法服务。
 * 支持 SM3、MD5、SHA-1/224/256/384/512、SHA-512/224、SHA-512/256、SHA3 系列。
 */
@Service
public class HashService {

    /** 展示名 -> JCA 算法名 */
    private static final Map<String, String> ALG_MAP = new LinkedHashMap<>();

    static {
        ALG_MAP.put("SM3", "SM3");
        ALG_MAP.put("MD5", "MD5");
        ALG_MAP.put("SHA-1", "SHA-1");
        ALG_MAP.put("SHA-224", "SHA-224");
        ALG_MAP.put("SHA-256", "SHA-256");
        ALG_MAP.put("SHA-384", "SHA-384");
        ALG_MAP.put("SHA-512", "SHA-512");
        ALG_MAP.put("SHA-512/224", "SHA-512/224");
        ALG_MAP.put("SHA-512/256", "SHA-512/256");
        ALG_MAP.put("SHA3-224", "SHA3-224");
        ALG_MAP.put("SHA3-256", "SHA3-256");
        ALG_MAP.put("SHA3-384", "SHA3-384");
        ALG_MAP.put("SHA3-512", "SHA3-512");
    }

    public Map<String, Object> digest(HashRequest req) throws Exception {
        String algName = resolve(req.getAlgorithm());
        byte[] data = CodecUtil.decode(req.getInput(), req.getInputFormat());

        // 盐值处理：前置 salt+data，后置 data+salt
        byte[] salt = (req.getSalt() == null || req.getSalt().isEmpty())
                ? new byte[0] : CodecUtil.decode(req.getSalt(), req.getSaltFormat());
        byte[] message;
        if (salt.length == 0) {
            message = data;
        } else if ("post".equalsIgnoreCase(req.getSaltPosition())) {
            message = concat(data, salt);
        } else {
            message = concat(salt, data);
        }

        int iterations = Math.max(1, req.getIterations());
        MessageDigest md = MessageDigest.getInstance(algName, "BC");
        byte[] out = md.digest(message);
        for (int i = 1; i < iterations; i++) {
            out = md.digest(out);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("algorithm", req.getAlgorithm());
        result.put("hex", CodecUtil.toHex(out));
        result.put("base64", CodecUtil.encode(out, "base64"));
        result.put("bitLength", out.length * 8);
        return result;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    /**
     * 计算全部支持算法的哈希值，便于批量对比。
     */
    public List<Map<String, Object>> digestAll(HashRequest req) throws Exception {
        byte[] data = CodecUtil.decode(req.getInput(), req.getInputFormat());
        List<Map<String, Object>> list = new ArrayList<>();
        for (Map.Entry<String, String> e : ALG_MAP.entrySet()) {
            MessageDigest md = MessageDigest.getInstance(e.getValue(), "BC");
            byte[] out = md.digest(data);
            Map<String, Object> item = new HashMap<>();
            item.put("algorithm", e.getKey());
            item.put("hex", CodecUtil.toHex(out));
            item.put("bitLength", out.length * 8);
            list.add(item);
        }
        return list;
    }

    /**
     * 根据哈希值长度猜测可能的算法。
     */
    public Map<String, Object> guess(String hashHex) {
        byte[] value = CodecUtil.fromHex(hashHex);
        int bits = value.length * 8;
        List<String> candidates = switch (bits) {
            case 128 -> List.of("MD5");
            case 160 -> List.of("SHA-1");
            case 224 -> List.of("SHA-224", "SHA3-224", "SHA-512/224");
            case 256 -> List.of("SM3", "SHA-256", "SHA3-256", "SHA-512/256");
            case 384 -> List.of("SHA-384", "SHA3-384");
            case 512 -> List.of("SHA-512", "SHA3-512");
            default -> List.of();
        };
        Map<String, Object> result = new HashMap<>();
        result.put("bitLength", bits);
        result.put("byteLength", value.length);
        result.put("candidates", candidates);
        return result;
    }

    public Collection<String> supportedAlgorithms() {
        return ALG_MAP.keySet();
    }

    private String resolve(String name) {
        if (name == null) {
            throw new IllegalArgumentException("哈希算法不能为空");
        }
        String key = name.trim().toUpperCase().replace("SHA", "SHA-").replace("SHA--", "SHA-");
        // 直接命中优先
        for (Map.Entry<String, String> e : ALG_MAP.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name.trim())) {
                return e.getValue();
            }
        }
        String v = ALG_MAP.get(key);
        if (v == null) {
            throw new IllegalArgumentException("不支持的哈希算法: " + name);
        }
        return v;
    }
}
