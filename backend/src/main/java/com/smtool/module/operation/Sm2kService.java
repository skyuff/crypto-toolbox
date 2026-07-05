package com.smtool.module.operation;

import com.smtool.util.CodecUtil;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * SM2 加密 k 碰撞分析服务。
 * 支持在较小范围内穷举随机数 k，定位使 C1=[k]G 成立的 k，并进一步恢复明文。
 */
@Service
public class Sm2kService {

    private static final X9ECParameters CURVE = GMNamedCurves.getByName("sm2p256v1");
    private static final ECCurve EC_CURVE = CURVE.getCurve();
    private static final ECPoint G = CURVE.getG();

    /** C1 点字节长度：04(1) + x(32) + y(32) */
    private static final int C1_LEN = 65;
    /** SM3 摘要长度 */
    private static final int C3_LEN = 32;

    /**
     * 碰撞随机数 k：在 [1, kMax] 范围内搜索满足 C1 = [k]G 的 k。
     */
    public Map<String, Object> collide(Sm2kRequest req) throws Exception {
        byte[] inputBytes = decode(req.getInput(), req.getInputFormat());
        ECPoint c1Point = extractC1(inputBytes);

        long kMax = Math.min(req.getKMax(), 10_000_000L);
        if (kMax <= 0) {
            kMax = 1_000_000L;
        }

        BigInteger k = findK(c1Point, kMax);
        Map<String, Object> result = new HashMap<>();
        result.put("found", k != null);
        if (k != null) {
            result.put("k", k.toString(16));
            result.put("kDecimal", k.toString(10));
        } else {
            result.put("message", "在 1 ~ " + kMax + " 范围内未找到匹配的 k");
        }
        result.put("kMax", kMax);
        return result;
    }

    /**
     * 尝试恢复明文：先搜索 k，再用 k 推导共享秘密并解密 C2。
     * 默认按 C1C3C2 解析完整密文。
     */
    public Map<String, Object> recover(Sm2kRequest req) throws Exception {
        byte[] inputBytes = decode(req.getInput(), req.getInputFormat());
        String pubHex = normalizeHex(decodeToHex(req.getPublicKey(), req.getPublicKeyFormat()));
        if (pubHex.length() == 128) {
            pubHex = "04" + pubHex;
        }
        ECPoint pub = EC_CURVE.decodePoint(CodecUtil.fromHex(pubHex)).normalize();

        if (inputBytes.length < C1_LEN) {
            throw new IllegalArgumentException("输入数据过短，无法解析 C1");
        }

        ECPoint c1Point = EC_CURVE.decodePoint(copyOf(inputBytes, C1_LEN)).normalize();

        long kMax = Math.min(req.getKMax(), 10_000_000L);
        if (kMax <= 0) {
            kMax = 1_000_000L;
        }

        BigInteger k = findK(c1Point, kMax);
        if (k == null) {
            Map<String, Object> result = new HashMap<>();
            result.put("found", false);
            result.put("message", "在 1 ~ " + kMax + " 范围内未找到匹配的 k，无法恢复明文");
            result.put("kMax", kMax);
            return result;
        }

        boolean c1c2c3 = "C1C2C3".equalsIgnoreCase(req.getMode());
        byte[] c1 = copyOf(inputBytes, C1_LEN);
        byte[] remain = subArray(inputBytes, C1_LEN, inputBytes.length);

        if (remain.length < C3_LEN) {
            throw new IllegalArgumentException("密文缺少 C2/C3 部分");
        }

        byte[] c2;
        byte[] c3;
        if (c1c2c3) {
            // C1 || C2 || C3
            c2 = subArray(remain, 0, remain.length - C3_LEN);
            c3 = subArray(remain, remain.length - C3_LEN, remain.length);
        } else {
            // C1 || C3 || C2
            c3 = subArray(remain, 0, C3_LEN);
            c2 = subArray(remain, C3_LEN, remain.length);
        }

        // S = [k]P_B = (x2, y2)
        ECPoint s = pub.multiply(k).normalize();
        byte[] x2 = to32(s.getAffineXCoord().toBigInteger());
        byte[] y2 = to32(s.getAffineYCoord().toBigInteger());
        byte[] x2y2 = concat(x2, y2);

        // t = KDF(x2||y2, |C2|)
        byte[] t = KdfService.kdf(new SM3Digest(), x2y2, c2.length);

        // M = C2 xor t
        byte[] m = new byte[c2.length];
        for (int i = 0; i < c2.length; i++) {
            m[i] = (byte) (c2[i] ^ t[i]);
        }

        // C3' = Hash(x2 || M || y2)
        SM3Digest sm3 = new SM3Digest();
        sm3.update(x2, 0, x2.length);
        sm3.update(m, 0, m.length);
        sm3.update(y2, 0, y2.length);
        byte[] c3Cal = new byte[sm3.getDigestSize()];
        sm3.doFinal(c3Cal, 0);
        boolean c3Match = constantTimeEquals(c3, c3Cal);

        String plaintext = encodePlaintext(m, req.getFormatOut());

        Map<String, Object> result = new HashMap<>();
        result.put("found", true);
        result.put("k", k.toString(16));
        result.put("kDecimal", k.toString(10));
        result.put("plaintext", plaintext);
        result.put("byteLength", m.length);
        result.put("c3Match", c3Match);
        result.put("mode", c1c2c3 ? "C1C2C3" : "C1C3C2");
        return result;
    }

    /** 在 [1, kMax] 范围内搜索满足 [k]G == c1Point 的 k */
    private BigInteger findK(ECPoint c1Point, long kMax) {
        // 预计算：逐步累加 G，避免每次大整数乘法
        ECPoint current = G; // [1]G
        for (long i = 1; i <= kMax; i++) {
            if (current.equals(c1Point)) {
                return BigInteger.valueOf(i);
            }
            current = current.add(G).normalize();
        }
        return null;
    }

    /** 从输入字节数组中提取 C1 点 */
    private ECPoint extractC1(byte[] input) {
        if (input.length < C1_LEN) {
            // 可能是裸坐标 64 字节，补 04
            if (input.length == C1_LEN - 1) {
                byte[] withPrefix = new byte[C1_LEN];
                withPrefix[0] = 0x04;
                System.arraycopy(input, 0, withPrefix, 1, input.length);
                return EC_CURVE.decodePoint(withPrefix).normalize();
            }
            throw new IllegalArgumentException("输入数据过短，无法解析 C1 点");
        }
        return EC_CURVE.decodePoint(copyOf(input, C1_LEN)).normalize();
    }

    /** 将输入按指定格式解码为字节 */
    private byte[] decode(String input, String format) {
        if (input == null || input.isBlank()) {
            return new byte[0];
        }
        String normalized = input;
        if ("hex".equalsIgnoreCase(format)) {
            normalized = normalizeHex(input);
        }
        return CodecUtil.decode(normalized, format);
    }

    /** 将输入解码为十六进制字符串 */
    private String decodeToHex(String input, String format) {
        byte[] bytes = decode(input, format);
        return CodecUtil.toHex(bytes);
    }

    private String normalizeHex(String hex) {
        if (hex == null) return "";
        return hex.replaceAll("[\\s:,]", "").replaceAll("(?i)^0x", "");
    }

    private String encodePlaintext(byte[] m, String format) {
        if ("base64".equalsIgnoreCase(format) || "hex".equalsIgnoreCase(format)) {
            return CodecUtil.encode(m, format);
        }
        return new String(m, StandardCharsets.UTF_8);
    }

    private static byte[] to32(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] r = new byte[32];
        if (b.length >= 32) {
            System.arraycopy(b, b.length - 32, r, 0, 32);
        } else {
            System.arraycopy(b, 0, r, 32 - b.length, b.length);
        }
        return r;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    private static byte[] copyOf(byte[] src, int len) {
        byte[] r = new byte[len];
        System.arraycopy(src, 0, r, 0, Math.min(len, src.length));
        return r;
    }

    private static byte[] subArray(byte[] src, int start, int end) {
        int len = Math.max(0, Math.min(end, src.length) - start);
        byte[] r = new byte[len];
        System.arraycopy(src, start, r, 0, len);
        return r;
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int r = 0;
        for (int i = 0; i < a.length; i++) {
            r |= a[i] ^ b[i];
        }
        return r == 0;
    }
}
