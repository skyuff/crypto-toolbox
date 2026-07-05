package com.smtool.module.symmetric;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * GCM 模式加解密服务，支持 SM4-GCM / AES-GCM，自定义 AAD 并校验/生成 Tag。
 */
@Service
public class GcmCipherService {

    public Map<String, Object> crypt(SymmetricRequest req) throws Exception {
        String rawAlg = req.getAlgorithm();
        String algorithm = normalizeAlgorithm(rawAlg);
        int tagLen = req.getTagLength() == null ? 128 : req.getTagLength();
        if (tagLen != 128 && tagLen != 96 && tagLen != 64 && tagLen != 32) {
            throw new IllegalArgumentException("GCM Tag 长度只能为 128/96/64/32 bit（16/12/8/4 字节）");
        }

        byte[] key = CodecUtil.decode(req.getKey(), req.getKeyFormat());
        byte[] iv = CodecUtil.decode(req.getIv(), req.getIvFormat());
        validateKeyLength(rawAlg, key.length);
        boolean encrypt = "encrypt".equalsIgnoreCase(req.getOperation());

        Cipher cipher = Cipher.getInstance(algorithm + "/GCM/NoPadding", "BC");
        SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLen, iv);
        cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        if (req.getAad() != null && !req.getAad().isBlank()) {
            cipher.updateAAD(CodecUtil.decode(req.getAad(), req.getAadFormat()));
        }

        Map<String, Object> result = new HashMap<>();
        int tagBytes = tagLen / 8;

        if (encrypt) {
            byte[] input = CodecUtil.decode(req.getInput(), req.getInputFormat());
            byte[] full = cipher.doFinal(input);
            // GCM 输出末尾包含 tag，拆分为密文与 tag 便于展示
            int cipherLen = full.length - tagBytes;
            byte[] cipherText = new byte[cipherLen];
            byte[] tag = new byte[tagBytes];
            System.arraycopy(full, 0, cipherText, 0, cipherLen);
            System.arraycopy(full, cipherLen, tag, 0, tagBytes);

            result.put("output", CodecUtil.encode(cipherText, req.getOutputFormat()));
            result.put("tag", CodecUtil.encode(tag, req.getTagFormat()));
            result.put("tagLength", tagBytes);
        } else {
            // 解密：密文与 tag 拼接后交给 cipher 校验
            byte[] cipherText = CodecUtil.decode(req.getInput(), req.getInputFormat());
            byte[] tag = CodecUtil.decode(req.getTag(), req.getTagFormat());
            byte[] combined = new byte[cipherText.length + tag.length];
            System.arraycopy(cipherText, 0, combined, 0, cipherText.length);
            System.arraycopy(tag, 0, combined, cipherText.length, tag.length);

            byte[] plain = cipher.doFinal(combined);
            result.put("output", CodecUtil.encode(plain, req.getOutputFormat()));
            result.put("verified", true);
        }
        result.put("transformation", algorithm + "/GCM/NoPadding");
        return result;
    }

    private String normalizeAlgorithm(String alg) {
        if (alg == null) {
            throw new IllegalArgumentException("算法不能为空");
        }
        return switch (alg.trim().toUpperCase().replace("_", "-")) {
            case "SM4" -> "SM4";
            case "AES", "AES-128", "AES-192", "AES-256" -> "AES";
            default -> throw new IllegalArgumentException("GCM 仅支持 SM4/AES: " + alg);
        };
    }

    /** 校验密钥字节长度是否与所选算法位数匹配。 */
    private void validateKeyLength(String rawAlg, int keyLen) {
        String a = rawAlg == null ? "" : rawAlg.trim().toUpperCase().replace("_", "-");
        switch (a) {
            case "SM4" -> {
                if (keyLen != 16) throw new IllegalArgumentException("SM4 密钥应为 16 字节，实际 " + keyLen);
            }
            case "AES-128" -> {
                if (keyLen != 16) throw new IllegalArgumentException("AES-128 密钥应为 16 字节，实际 " + keyLen);
            }
            case "AES-192" -> {
                if (keyLen != 24) throw new IllegalArgumentException("AES-192 密钥应为 24 字节，实际 " + keyLen);
            }
            case "AES-256" -> {
                if (keyLen != 32) throw new IllegalArgumentException("AES-256 密钥应为 32 字节，实际 " + keyLen);
            }
            case "AES" -> {
                if (keyLen != 16 && keyLen != 24 && keyLen != 32)
                    throw new IllegalArgumentException("AES 密钥应为 16/24/32 字节，实际 " + keyLen);
            }
            default -> { }
        }
    }
}
