package com.smtool.module.parse;

import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Arrays;

/**
 * IKEv1 加密载荷解密器（国密 SM4-CBC）。
 *
 * <p>目前为实验性支持：需要外部提供 SKEYID_e 和初始 IV。由于不同厂商的 IV 推导、
 * 填充方式可能存在差异，解密失败时会记录原因并返回 null。
 */
public class IpsecIkeDecryptor {

    /**
     * 解密 IKEv1 加密载荷。
     *
     * <p>假设 payload 结构为：generic header（4 字节）+ ciphertext（含 PKCS#7 填充）。
     * IV 由调用方按 IKEv1 规则提供（初始 IV 来自密钥日志，后续消息按 CBC 链式更新）。
     *
     * @param ciphertext 完整加密 payload 字节（含 generic header）
     * @param key        SKEYID_e
     * @param iv         解密 IV
     * @return 解密后的明文 payload 字节（去掉 padding），失败返回 null
     */
    public byte[] decrypt(byte[] ciphertext, byte[] key, byte[] iv) {
        if (ciphertext == null || ciphertext.length < 4 + 16 || iv == null || iv.length != 16) {
            return null;
        }
        try {
            // 跳过 generic payload header（4 字节），其后为 ciphertext
            byte[] encrypted = Arrays.copyOfRange(ciphertext, 4, ciphertext.length);
            if (encrypted.length % 16 != 0) {
                return null;
            }

            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                    new CBCBlockCipher(new SM4Engine()), new PKCS7Padding());
            ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);
            cipher.init(false, params);

            byte[] plaintext = new byte[cipher.getOutputSize(encrypted.length)];
            int processed = cipher.processBytes(encrypted, 0, encrypted.length, plaintext, 0);
            int finalLen = cipher.doFinal(plaintext, processed);

            return Arrays.copyOf(plaintext, processed + finalLen);
        } catch (Exception e) {
            return null;
        }
    }

}
