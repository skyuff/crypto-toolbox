package com.smtool.module.hash;

import com.smtool.util.CodecUtil;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * MAC 服务。
 * <p>基于分组密码（SM4 / AES-128/192/256）的 MAC，对应 GB/T 15852.1（ISO/IEC 9797-1）：
 * CBC-MAC、CMAC、EMAC、ANSI-retail-MAC、MacDES、LMAC、CBCR、TrCBC。
 * <p>同时兼容哈希页调用的 HMAC（type=HMAC-xxx）。
 * <p>填充：method1（补 0，附录 C.2）/ method2（补 80 00…，附录 C.3）/ method3（前置长度块 + 补 0，附录 C.4）。
 */
@Service
public class MacService {

    private static final int BLOCK = 16;

    public Map<String, Object> compute(MacRequest req) throws Exception {
        byte[] key = CodecUtil.decode(req.getKey(), req.getKeyFormat());
        byte[] data = CodecUtil.decode(req.getInput(), req.getInputFormat());
        String type = req.getType() == null ? "" : req.getType().trim().toUpperCase();

        byte[] out;
        if (type.startsWith("HMAC")) {
            out = hmac(type, key, data);
        } else {
            out = blockMac(type, req, key, data);
        }

        // 输出截断（TrCBC 及通用 macSize）
        int macSize = req.getMacSize() <= 0 ? out.length : Math.min(req.getMacSize(), out.length);
        if (macSize < out.length) {
            out = Arrays.copyOf(out, macSize);
        }

        String fmt = "base64".equalsIgnoreCase(req.getOutputFormat()) ? "base64" : "hex";
        Map<String, Object> result = new HashMap<>();
        result.put("type", req.getType());
        result.put("hex", CodecUtil.toHex(out));
        result.put("base64", CodecUtil.encode(out, "base64"));
        result.put("output", CodecUtil.encode(out, fmt));
        result.put("bitLength", out.length * 8);
        result.put("byteLength", out.length);
        return result;
    }

    // ============ HMAC ============
    private byte[] hmac(String type, byte[] key, byte[] data) throws Exception {
        String hash = type.substring("HMAC".length()).replaceFirst("^-", "");
        String jceName = hash.toUpperCase().startsWith("SHA3")
                ? "Hmac" + hash
                : "Hmac" + hash.replace("-", "");
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance(jceName, "BC");
        mac.init(new javax.crypto.spec.SecretKeySpec(key, jceName));
        return mac.doFinal(data);
    }

    // ============ 分组密码 MAC ============
    private byte[] blockMac(String type, MacRequest req, byte[] key, byte[] data) {
        // CMAC 使用 BC 原生实现（内部自带 padding）
        if (type.equals("CMAC")) {
            return cmac(newEngine(req.getAlgorithm()), key, data);
        }
        // 其余模式：先填充，再按 CBC 链 + 末块变换
        byte[] padded = pad(data, req.getPadding());
        byte[][] blocks = split(padded);

        return switch (type) {
            case "CBC-MAC", "CBCMAC", "TRCBC" -> cbcMac(req.getAlgorithm(), key, blocks);
            case "EMAC" -> emac(req.getAlgorithm(), key, blocks);
            case "ANSI-RETAIL-MAC", "RETAIL-MAC", "RETAILMAC" -> retailMac(req.getAlgorithm(), key, blocks);
            case "MACDES" -> macDes(req.getAlgorithm(), key, blocks);
            case "LMAC" -> lmac(req.getAlgorithm(), key, blocks);
            case "CBCR" -> cbcr(req.getAlgorithm(), key, blocks);
            default -> throw new IllegalArgumentException("不支持的 MAC 模式: " + req.getType());
        };
    }

    private byte[] cmac(BlockCipher engine, byte[] key, byte[] data) {
        CMac cmac = new CMac(engine);
        return doMac(cmac, new KeyParameter(key), data);
    }

    private byte[] doMac(Mac mac, CipherParameters params, byte[] data) {
        mac.init(params);
        mac.update(data, 0, data.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    /** 算法 1：CBC-MAC —— 纯 CBC 链，取最后一块。TrCBC 在外层截断。 */
    private byte[] cbcMac(String alg, byte[] key, byte[][] blocks) {
        BlockCipher c = init(newEngine(alg), key, true);
        return cbcChain(c, blocks);
    }

    /** 算法 2：EMAC —— CBC-MAC 后用 K2 再加密一次末块。K2 由 K 派生。 */
    private byte[] emac(String alg, byte[] key, byte[][] blocks) {
        byte[] k1 = key;
        byte[] k2 = deriveKey(key, keyLen(alg), 2);
        byte[] h = cbcChain(init(newEngine(alg), k1, true), blocks);
        return encryptBlock(newEngine(alg), k2, h);
    }

    /** 算法 3：ANSI-retail-MAC —— CBC 链(K1) 后，末块做 Dec(K2) 再 Enc(K1)。 */
    private byte[] retailMac(String alg, byte[] key, byte[][] blocks) {
        byte[] k1 = key;
        byte[] k2 = deriveKey(key, keyLen(alg), 2);
        byte[] h = cbcChain(init(newEngine(alg), k1, true), blocks);
        byte[] d = decryptBlock(newEngine(alg), k2, h);
        return encryptBlock(newEngine(alg), k1, d);
    }

    /** 算法 4：MacDES —— 首块用 K1 加密后再用 K2 变换，其余 CBC(K1)，末块 Dec(K2)->Enc(K1)。 */
    private byte[] macDes(String alg, byte[] key, byte[][] blocks) {
        byte[] k1 = key;
        byte[] k2 = deriveKey(key, keyLen(alg), 2);
        BlockCipher e1 = init(newEngine(alg), k1, true);
        byte[] chain = new byte[BLOCK];
        for (int i = 0; i < blocks.length; i++) {
            byte[] x = xor(chain, blocks[i]);
            chain = process(e1, x);
            if (i == 0) {
                // 首块附加 K2 变换：H1 = Enc_K1(Dec_K2(Enc_K1(D1)))
                byte[] d = decryptBlock(newEngine(alg), k2, chain);
                chain = encryptBlock(newEngine(alg), k1, d);
            }
        }
        byte[] d = decryptBlock(newEngine(alg), k2, chain);
        return encryptBlock(newEngine(alg), k1, d);
    }

    /** 算法 5：LMAC —— 首块用派生密钥 K1'，其余用 K，末块无额外变换。 */
    private byte[] lmac(String alg, byte[] key, byte[][] blocks) {
        byte[] kStart = deriveKey(key, keyLen(alg), 3);
        byte[] chain = new byte[BLOCK];
        for (int i = 0; i < blocks.length; i++) {
            byte[] useKey = (i == 0) ? kStart : key;
            BlockCipher c = init(newEngine(alg), useKey, true);
            chain = process(c, xor(chain, blocks[i]));
        }
        return chain;
    }

    /** CBCR —— CBC-MAC 变体，末块加入由密钥派生的掩码后再加密。 */
    private byte[] cbcr(String alg, byte[] key, byte[][] blocks) {
        byte[] mask = deriveKey(key, BLOCK, 4);
        BlockCipher c = init(newEngine(alg), key, true);
        byte[] chain = new byte[BLOCK];
        for (int i = 0; i < blocks.length; i++) {
            byte[] blk = blocks[i];
            if (i == blocks.length - 1) {
                blk = xor(blk, mask);
            }
            chain = process(c, xor(chain, blk));
        }
        return chain;
    }

    // ============ 基础运算 ============
    private byte[] cbcChain(BlockCipher c, byte[][] blocks) {
        byte[] chain = new byte[BLOCK];
        for (byte[] b : blocks) {
            chain = process(c, xor(chain, b));
        }
        return chain;
    }

    private byte[] encryptBlock(BlockCipher engine, byte[] key, byte[] in) {
        return process(init(engine, key, true), in);
    }

    private byte[] decryptBlock(BlockCipher engine, byte[] key, byte[] in) {
        return process(init(engine, key, false), in);
    }

    private byte[] process(BlockCipher c, byte[] in) {
        byte[] out = new byte[BLOCK];
        c.processBlock(in, 0, out, 0);
        return out;
    }

    private BlockCipher init(BlockCipher c, byte[] key, boolean forEncryption) {
        c.init(forEncryption, new KeyParameter(key));
        return c;
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] r = new byte[a.length];
        for (int i = 0; i < a.length; i++) r[i] = (byte) (a[i] ^ b[i]);
        return r;
    }

    // ============ 填充 ============
    private byte[] pad(byte[] data, String method) {
        String m = method == null ? "method1" : method.trim().toLowerCase();
        return switch (m) {
            case "method2", "c.3", "c3" -> padMethod2(data);
            case "method3", "c.4", "c4" -> padMethod3(data);
            default -> padMethod1(data); // method1 / C.2
        };
    }

    /** method 1（C.2）：右补 0 至整块（数据为空则补一整块 0）。 */
    private byte[] padMethod1(byte[] data) {
        int len = data.length == 0 ? BLOCK : ((data.length + BLOCK - 1) / BLOCK) * BLOCK;
        return Arrays.copyOf(data, len);
    }

    /** method 2（C.3）：末尾加一个 0x80，再右补 0 至整块。 */
    private byte[] padMethod2(byte[] data) {
        int total = ((data.length + 1 + BLOCK - 1) / BLOCK) * BLOCK;
        byte[] r = Arrays.copyOf(data, total);
        r[data.length] = (byte) 0x80;
        return r;
    }

    /** method 3（C.4）：前置一个「数据比特长度」块，其后数据用 method 1 补 0。 */
    private byte[] padMethod3(byte[] data) {
        byte[] body = padMethod1(data);
        byte[] lengthBlock = new byte[BLOCK];
        long bitLen = (long) data.length * 8;
        for (int i = 0; i < 8; i++) {
            lengthBlock[BLOCK - 1 - i] = (byte) (bitLen >>> (8 * i));
        }
        byte[] r = new byte[BLOCK + body.length];
        System.arraycopy(lengthBlock, 0, r, 0, BLOCK);
        System.arraycopy(body, 0, r, BLOCK, body.length);
        return r;
    }

    private byte[][] split(byte[] padded) {
        int n = padded.length / BLOCK;
        byte[][] blocks = new byte[n][];
        for (int i = 0; i < n; i++) {
            blocks[i] = Arrays.copyOfRange(padded, i * BLOCK, (i + 1) * BLOCK);
        }
        return blocks;
    }

    // ============ 引擎 / 密钥 ============
    private BlockCipher newEngine(String algorithm) {
        String a = algorithm == null ? "SM4" : algorithm.trim().toUpperCase();
        if (a.startsWith("AES")) return AESEngine.newInstance();
        if (a.equals("SM4")) return new SM4Engine();
        throw new IllegalArgumentException("MAC 底层算法仅支持 SM4/AES: " + algorithm);
    }

    /** 密钥字节长度：AES-128/192/256 -> 16/24/32；SM4 -> 16。 */
    private int keyLen(String algorithm) {
        String a = algorithm == null ? "SM4" : algorithm.trim().toUpperCase();
        if (a.contains("192")) return 24;
        if (a.contains("256")) return 32;
        return 16;
    }

    /** 用 SM3(index || key) 派生指定长度的子密钥，保证单密钥输入可用于多密钥算法。 */
    private byte[] deriveKey(byte[] key, int len, int index) {
        SM3Digest d = new SM3Digest();
        d.update((byte) index);
        d.update(key, 0, key.length);
        byte[] out = new byte[len];
        int off = 0;
        int counter = 0;
        while (off < len) {
            SM3Digest dd = new SM3Digest(d);
            dd.update((byte) counter++);
            byte[] h = new byte[dd.getDigestSize()];
            dd.doFinal(h, 0);
            int copy = Math.min(h.length, len - off);
            System.arraycopy(h, 0, out, off, copy);
            off += copy;
        }
        return out;
    }
}
