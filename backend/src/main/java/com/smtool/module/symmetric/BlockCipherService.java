package com.smtool.module.symmetric;

import com.smtool.util.CodecUtil;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

/**
 * 分组密码加解密服务。
 * 算法：SM4 / AES-128 / AES-192 / AES-256 / DES / 3DES-2KEY / 3DES-3KEY。
 * 工作模式：ECB / CBC / CTR / OFB / CFB / XTS。
 * 填充：PKCS7 / ISO10126 / ISO7816-4 / ANSI X9.23 / ZERO / NO PADDING。
 */
@Service
public class BlockCipherService {

    public Map<String, Object> crypt(SymmetricRequest req) throws Exception {
        String rawAlg = req.getAlgorithm();
        String algorithm = normalizeAlgorithm(rawAlg);
        String mode = req.getMode() == null ? "ECB" : req.getMode().toUpperCase();
        String padding = normalizePadding(req.getPadding());

        byte[] key = CodecUtil.decode(req.getKey(), req.getKeyFormat());
        byte[] input = CodecUtil.decode(req.getInput(), req.getInputFormat());

        // 校验密钥长度是否与所选算法位数匹配
        validateKeyLength(rawAlg, algorithm, mode, key.length);

        int cipherMode = "encrypt".equalsIgnoreCase(req.getOperation())
                ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

        String transformation;
        Cipher cipher;

        if ("XTS".equals(mode)) {
            // XTS 模式：BC 的 JCE 层不提供 AES/XTS transformation，改用底层引擎 XTSBlockCipher
            transformation = algorithm + "/XTS/NoPadding";
            byte[] tweak = req.getIv() == null || req.getIv().isBlank()
                    ? new byte[16] : CodecUtil.decode(req.getIv(), req.getIvFormat());
            if (tweak.length != 16) {
                throw new IllegalArgumentException("XTS 的 tweak(IV) 必须为 16 字节");
            }
            if (input.length < 16) {
                throw new IllegalArgumentException("XTS 模式数据长度至少为 16 字节");
            }
            byte[] output = xts(algorithm, key, tweak, input,
                    "encrypt".equalsIgnoreCase(req.getOperation()));
            Map<String, Object> result = new HashMap<>();
            result.put("transformation", transformation);
            result.put("output", CodecUtil.encode(output, req.getOutputFormat()));
            result.put("outputLength", output.length);
            return result;
        }

        transformation = algorithm + "/" + mode + "/" + padding;
        cipher = Cipher.getInstance(transformation, "BC");
        SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
        if ("ECB".equals(mode)) {
            cipher.init(cipherMode, keySpec);
        } else {
            byte[] iv = CodecUtil.decode(req.getIv(), req.getIvFormat());
            AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(cipherMode, keySpec, ivSpec);
        }

        byte[] output = cipher.doFinal(input);

        Map<String, Object> result = new HashMap<>();
        result.put("transformation", transformation);
        result.put("output", CodecUtil.encode(output, req.getOutputFormat()));
        result.put("outputLength", output.length);
        return result;
    }

    /**
     * XTS 模式加解密（IEEE Std 1619-2007，XEX-based Tweaked-codebook with ciphertext Stealing）。
     * BC 1.78 未提供标准 XTS 的 JCE/底层实现，此处按标准手动实现：
     * 密钥拆为等长两半 K1(数据)/K2(tweak)；tweak = E_K2(i) 后在 GF(2^128) 上按块左移递推；
     * 每块做 C = E_K1(P ^ T) ^ T；不足整块时使用 CTS（密文挪用）。
     */
    private byte[] xts(String algorithm, byte[] key, byte[] iv, byte[] input, boolean forEncryption) {
        int half = key.length / 2;
        byte[] k1 = new byte[half];
        byte[] k2 = new byte[half];
        System.arraycopy(key, 0, k1, 0, half);
        System.arraycopy(key, half, k2, 0, half);

        BlockCipher dataCipher = newEngine(algorithm);
        BlockCipher tweakCipher = newEngine(algorithm);
        dataCipher.init(forEncryption, new KeyParameter(k1));
        tweakCipher.init(true, new KeyParameter(k2));

        // 初始 tweak = E_K2(iv)
        byte[] t = new byte[16];
        tweakCipher.processBlock(iv, 0, t, 0);

        int full = input.length / 16;        // 完整块数
        int rem = input.length % 16;          // 剩余字节
        // 若存在不足整块的尾部，最后一整块留给 CTS（密文挪用）处理
        int loopBlocks = (rem != 0) ? full - 1 : full;
        byte[] out = new byte[input.length];

        int off = 0;
        for (int i = 0; i < loopBlocks; i++) {
            xtsBlock(dataCipher, input, off, out, off, t);
            t = gfMulAlpha(t);
            off += 16;
        }

        if (rem == 0) {
            // 数据为整块，全部已在循环中处理完毕
            return out;
        }

        // 密文挪用 CTS：处理倒数第二整块与最后不足块
        if (forEncryption) {
            byte[] cc = new byte[16];
            xtsBlock(dataCipher, input, off, cc, 0, t);           // 加密倒数第二块 -> CC
            System.arraycopy(cc, 0, out, off + 16, rem);          // CC 前 rem 字节作为最后密文
            byte[] pp = new byte[16];
            System.arraycopy(input, off + 16, pp, 0, rem);        // 最后部分明文
            System.arraycopy(cc, rem, pp, rem, 16 - rem);         // 补 CC 尾部
            xtsBlock(dataCipher, pp, 0, out, off, gfMulAlpha(t)); // 用下一个 tweak 加密 -> 倒数第二密文块
        } else {
            byte[] tNext = gfMulAlpha(t);
            byte[] pp = new byte[16];
            xtsBlock(dataCipher, input, off, pp, 0, tNext);       // 用 next tweak 解密倒数第二块 -> PP
            System.arraycopy(pp, 0, out, off + 16, rem);          // PP 前 rem 作为最后明文
            byte[] cc = new byte[16];
            System.arraycopy(input, off + 16, cc, 0, rem);
            System.arraycopy(pp, rem, cc, rem, 16 - rem);
            xtsBlock(dataCipher, cc, 0, out, off, t);             // 用 t 解密 -> 倒数第二明文块
        }
        return out;
    }

    /** 单块 XTS：out = D/E(in ^ T) ^ T */
    private void xtsBlock(BlockCipher c, byte[] in, int inOff, byte[] out, int outOff, byte[] t) {
        byte[] x = new byte[16];
        for (int i = 0; i < 16; i++) x[i] = (byte) (in[inOff + i] ^ t[i]);
        byte[] y = new byte[16];
        c.processBlock(x, 0, y, 0);
        for (int i = 0; i < 16; i++) out[outOff + i] = (byte) (y[i] ^ t[i]);
    }

    /** GF(2^128) 上 tweak 乘以 alpha（x），即左移一位并按模多项式 0x87 约简（小端序）。 */
    private byte[] gfMulAlpha(byte[] in) {
        byte[] out = new byte[16];
        int carry = 0;
        for (int i = 0; i < 16; i++) {
            int b = in[i] & 0xff;
            out[i] = (byte) (((b << 1) | carry) & 0xff);
            carry = (b >>> 7) & 1;
        }
        if (carry != 0) out[0] ^= 0x87;
        return out;
    }

    private BlockCipher newEngine(String algorithm) {
        return "SM4".equals(algorithm) ? new SM4Engine() : AESEngine.newInstance();
    }

    /**
     * 归一化算法名。参考站将 AES/3DES 按密钥位数细分，这里映射到 JCE 标准算法名。
     */
    private String normalizeAlgorithm(String alg) {
        if (alg == null) {
            throw new IllegalArgumentException("算法不能为空");
        }
        return switch (alg.trim().toUpperCase().replace("_", "-")) {
            case "SM4" -> "SM4";
            case "AES", "AES-128", "AES-192", "AES-256", "AES128", "AES192", "AES256" -> "AES";
            case "DES" -> "DES";
            case "3DES", "DESEDE", "DES3", "3DES-2KEY", "3DES-3KEY", "3DES2KEY", "3DES3KEY" -> "DESede";
            default -> throw new IllegalArgumentException("不支持的分组算法: " + alg);
        };
    }

    /**
     * 校验密钥字节长度与所选算法位数是否匹配（XTS 模式密钥为双倍）。
     */
    private void validateKeyLength(String rawAlg, String jceAlg, String mode, int keyLen) {
        String a = rawAlg == null ? "" : rawAlg.trim().toUpperCase().replace("_", "-");
        int expect;
        switch (a) {
            case "SM4" -> expect = 16;
            case "AES-128", "AES128" -> expect = 16;
            case "AES-192", "AES192" -> expect = 24;
            case "AES-256", "AES256" -> expect = 32;
            case "AES" -> { // 未指定位数：允许 16/24/32
                if ("XTS".equals(mode)) { checkXts(keyLen); return; }
                if (keyLen != 16 && keyLen != 24 && keyLen != 32)
                    throw new IllegalArgumentException("AES 密钥应为 16/24/32 字节，实际 " + keyLen);
                return;
            }
            case "DES" -> expect = 8;
            case "3DES-2KEY", "3DES2KEY" -> expect = 16;
            case "3DES-3KEY", "3DES3KEY", "3DES", "DESEDE" -> expect = 24;
            default -> { return; }
        }
        if ("XTS".equals(mode)) {
            checkXts(keyLen);
            return;
        }
        if (keyLen != expect) {
            throw new IllegalArgumentException(rawAlg + " 密钥应为 " + expect + " 字节，实际 " + keyLen);
        }
    }

    private void checkXts(int keyLen) {
        // XTS 使用两个等长子密钥，AES-XTS 密钥总长应为 32 或 64 字节
        if (keyLen != 32 && keyLen != 64) {
            throw new IllegalArgumentException("XTS 模式密钥应为 32 或 64 字节（双倍密钥），实际 " + keyLen);
        }
    }

    /**
     * 归一化填充方式，映射到 BouncyCastle 支持的填充名。
     */
    private String normalizePadding(String padding) {
        if (padding == null || padding.isBlank()) {
            return "PKCS7Padding";
        }
        return switch (padding.trim().toUpperCase().replace(" ", "").replace(".", "").replace("-", "")) {
            case "PKCS5", "PKCS5PADDING" -> "PKCS5Padding";
            case "PKCS7", "PKCS7PADDING" -> "PKCS7Padding";
            case "NONE", "NOPADDING" -> "NoPadding";
            case "ISO10126", "ISO10126PADDING", "ISO101262", "ISO101262PADDING" -> "ISO10126Padding";
            case "ISO78164", "ISO78164PADDING" -> "ISO7816-4Padding";
            case "ANSIX923", "X923", "X923PADDING", "ANSIX923PADDING" -> "X9.23Padding";
            case "ZERO", "ZEROBYTE", "ZEROBYTEPADDING", "ZEROPADDING" -> "ZeroBytePadding";
            default -> throw new IllegalArgumentException("不支持的填充方式: " + padding);
        };
    }
}
