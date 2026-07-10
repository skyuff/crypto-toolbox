package com.smtool.module.sm9;

import com.smtool.module.sm9.core.Fp12;
import com.smtool.module.sm9.core.Fp2;
import com.smtool.module.sm9.core.Fp4;
import com.smtool.module.sm9.core.PointG1;
import com.smtool.module.sm9.core.PointG2;
import com.smtool.module.sm9.core.SM9Pairing;
import com.smtool.module.sm9.core.SM9Params;
import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * SM9 标识密码算法服务（GM/T 0044-2016）。
 * 基于项目内置的 SM9 core 模块实现正确的 BN256 曲线、R-ate 双线性对及标准签名/验签、加解密、密钥封装/解封。
 */
@Service
public class SM9Service {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final BigInteger P = SM9Params.P;
    private static final BigInteger N = SM9Params.N;

    private static final PointG1 P1 = PointG1.G;
    private static final PointG2 P2 = PointG2.G;

    /** 签名方案 hid（GM/T 0044.2-2016）。 */
    private static final byte HID_SIGN = 0x01;
    /** 加密/密钥封装方案 hid（GM/T 0044.4-2016）。 */
    private static final byte HID_ENCRYPT = 0x03;
    /** 密钥协商方案 hid（GM/T 0044.3-2016）。 */
    private static final byte HID_KEY_AGREEMENT = 0x02;

    public Map<String, Object> curveParams() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("curveEquation", SM9Params.CURVE_EQUATION);
        result.put("t", formatHex(SM9Params.T));
        result.put("p", formatHex(P));
        result.put("q", formatHex(P));
        result.put("n", formatHex(N));
        result.put("g1X", formatHex(SM9Params.P1_X));
        result.put("g1Y", formatHex(SM9Params.P1_Y));
        result.put("g2X", formatHex(SM9Params.P2_X_1) + "\n" + formatHex(SM9Params.P2_X_0));
        result.put("g2Y", formatHex(SM9Params.P2_Y_1) + "\n" + formatHex(SM9Params.P2_Y_0));
        return result;
    }

    public Map<String, Object> generateMasterKeyPair(String type) {
        BigInteger s = randomScalar();
        PointG2 pk = P2.multiply(s);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("masterPrivateKey", padHex(s.toString(16), 64).toUpperCase());
        result.put("masterPublicKey", encodeG2(pk));
        result.put("type", type);
        result.put("masterPrivateKeyLength", 32);
        result.put("masterPublicKeyLength", 128);
        return result;
    }

    public Map<String, Object> deriveUserKey(String type, String masterPrivateKey, String userId) {
        validateNotBlank(masterPrivateKey, "主私钥");
        validateNotBlank(userId, "用户标识");
        BigInteger s = new BigInteger(cleanHex(masterPrivateKey), 16);
        boolean isSign = "sign".equalsIgnoreCase(type);
        byte hid = isSign ? HID_SIGN : HID_ENCRYPT;
        BigInteger h1 = h1(concat(new byte[]{hid}, userId.getBytes(StandardCharsets.UTF_8)));

        Map<String, Object> result = new LinkedHashMap<>();
        if (isSign) {
            PointG1 qid = P1.multiply(h1);
            PointG1 d = qid.multiply(s);
            result.put("userPrivateKey", encodeG1(d));
            result.put("userPrivateKeyLength", 64);
        } else {
            PointG2 qid = P2.multiply(h1);
            PointG2 d = qid.multiply(s);
            result.put("userPrivateKey", encodeG2(d));
            result.put("userPrivateKeyLength", 128);
        }
        result.put("userId", userId);
        result.put("type", type);
        return result;
    }

    public Map<String, Object> sign(String masterPublicKey, String userPrivateKey, String userId, String message) {
        validateNotBlank(masterPublicKey, "主公钥");
        validateNotBlank(userPrivateKey, "用户私钥");
        validateNotBlank(userId, "用户标识");
        validateNotBlank(message, "消息");

        PointG2 pPub = decodeG2(masterPublicKey);
        PointG1 ds = decodeG1(userPrivateKey);
        byte[] m = message.getBytes(StandardCharsets.UTF_8);

        Fp12 g = SM9Pairing.rate(P1, pPub);
        BigInteger h;
        PointG1 s;
        do {
            BigInteger r = randomScalar();
            Fp12 w = g.pow(r);
            h = h2(concat(m, fp12ToBytes(w)));
            BigInteger l = r.subtract(h).mod(N);
            if (l.signum() < 0) {
                l = l.add(N);
            }
            s = ds.multiply(l);
        } while (s.isInfinity());

        String signatureValue = padHex(h.toString(16), 64).toUpperCase() + encodeG1(s);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("signature", signatureValue);
        result.put("signatureFormat", "h||S");
        result.put("signatureLength", signatureValue.length() / 2);
        return result;
    }

    public Map<String, Object> verify(String masterPublicKey, String userId, String message, String signature) {
        validateNotBlank(masterPublicKey, "主公钥");
        validateNotBlank(userId, "用户标识");
        validateNotBlank(message, "消息");
        validateNotBlank(signature, "签名值");

        PointG2 pPub = decodeG2(masterPublicKey);
        byte[] m = message.getBytes(StandardCharsets.UTF_8);

        String sigHex = cleanHex(signature);
        if (sigHex.length() < 64) {
            return verifyResult(false, "签名值长度过短");
        }
        BigInteger h = new BigInteger(sigHex.substring(0, 64), 16);
        PointG1 s = decodeG1(sigHex.substring(64));

        if (h.signum() <= 0 || h.compareTo(N) >= 0 || s.isInfinity()) {
            return verifyResult(false, "签名值格式非法");
        }

        Fp12 g = SM9Pairing.rate(P1, pPub);
        Fp12 t = g.pow(h);
        BigInteger h1 = h1(concat(new byte[]{HID_SIGN}, userId.getBytes(StandardCharsets.UTF_8)));
        PointG2 p = P2.multiply(h1).add(pPub);
        Fp12 u = SM9Pairing.rate(s, p);
        Fp12 w = u.mul(t);
        BigInteger h2 = h2(concat(m, fp12ToBytes(w)));
        boolean verified = h2.equals(h);
        return verifyResult(verified, verified ? "签名验证通过" : "签名验证失败");
    }

    public Map<String, Object> encrypt(String masterPublicKey, String userId, String message, String mode) {
        validateNotBlank(masterPublicKey, "主公钥");
        validateNotBlank(userId, "用户标识");
        validateNotBlank(message, "消息");

        PointG1 pPub = decodeG1(masterPublicKey);
        BigInteger h1 = h1(concat(new byte[]{HID_ENCRYPT}, userId.getBytes(StandardCharsets.UTF_8)));
        PointG2 qB = P2.multiply(h1);
        byte[] m = message.getBytes(StandardCharsets.UTF_8);
        int klen = m.length * 8;

        Fp12 g = SM9Pairing.rate(pPub, qB);
        PointG1 c1;
        Fp12 w;
        byte[] k;
        do {
            BigInteger r = randomScalar();
            c1 = P1.multiply(r);
            w = g.pow(r);
            k = kdf(concat(c1.toBytes(), fp12ToBytes(w), userId.getBytes(StandardCharsets.UTF_8)), klen);
        } while (isAllZero(k));

        byte[] c2 = xor(m, k);
        byte[] c3 = sm3(concat(c1.toBytes(), m));

        String ciphertext = encodeG1(c1) + CodecUtil.toHex(c3).toUpperCase() + CodecUtil.toHex(c2).toUpperCase();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ciphertext", ciphertext);
        result.put("mode", mode);
        result.put("ciphertextLength", ciphertext.length() / 2);
        return result;
    }

    public Map<String, Object> decrypt(String userPrivateKey, String userId, String ciphertext, String mode) {
        validateNotBlank(userPrivateKey, "用户私钥");
        validateNotBlank(userId, "用户标识");
        validateNotBlank(ciphertext, "密文");

        PointG2 deB = decodeG2(userPrivateKey);
        String cipherHex = cleanHex(ciphertext);
        if (cipherHex.length() < 128 + 64) {
            throw new IllegalArgumentException("密文长度过短");
        }
        PointG1 c1 = decodeG1(cipherHex.substring(0, 128));
        byte[] c3 = CodecUtil.fromHex(cipherHex.substring(128, 128 + 64));
        byte[] c2 = CodecUtil.fromHex(cipherHex.substring(128 + 64));

        Fp12 w = SM9Pairing.rate(c1, deB);
        byte[] k = kdf(concat(c1.toBytes(), fp12ToBytes(w), userId.getBytes(StandardCharsets.UTF_8)), c2.length * 8);
        if (isAllZero(k)) {
            throw new IllegalArgumentException("派生密钥全 0");
        }
        byte[] plain = xor(c2, k);
        byte[] c3Check = sm3(concat(c1.toBytes(), plain));
        if (!Arrays.equals(c3, c3Check)) {
            throw new IllegalArgumentException("C3 校验失败，密文可能被篡改");
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("plaintext", new String(plain, StandardCharsets.UTF_8));
        result.put("mode", mode);
        return result;
    }

    public Map<String, Object> encapsulate(String masterPublicKey, String userId) {
        validateNotBlank(masterPublicKey, "主公钥");
        validateNotBlank(userId, "用户标识");

        PointG1 pPub = decodeG1(masterPublicKey);
        BigInteger h1 = h1(concat(new byte[]{HID_ENCRYPT}, userId.getBytes(StandardCharsets.UTF_8)));
        PointG2 qB = P2.multiply(h1);

        Fp12 g = SM9Pairing.rate(pPub, qB);
        PointG1 c;
        byte[] key;
        do {
            BigInteger r = randomScalar();
            c = P1.multiply(r);
            Fp12 w = g.pow(r);
            key = kdf(concat(c.toBytes(), fp12ToBytes(w), userId.getBytes(StandardCharsets.UTF_8)), 128);
        } while (isAllZero(key));

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("encapsulatedKey", encodeG1(c));
        result.put("sharedKey", CodecUtil.toHex(key).toUpperCase());
        result.put("keyLength", key.length);
        return result;
    }

    public Map<String, Object> decapsulate(String userPrivateKey, String userId, String encapsulatedKey) {
        validateNotBlank(userPrivateKey, "用户私钥");
        validateNotBlank(userId, "用户标识");
        validateNotBlank(encapsulatedKey, "封装密钥");

        PointG2 deB = decodeG2(userPrivateKey);
        PointG1 c = decodeG1(encapsulatedKey);
        Fp12 w = SM9Pairing.rate(c, deB);
        byte[] key = kdf(concat(c.toBytes(), fp12ToBytes(w), userId.getBytes(StandardCharsets.UTF_8)), 128);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("sharedKey", CodecUtil.toHex(key).toUpperCase());
        result.put("keyLength", key.length);
        return result;
    }

    public Map<String, Object> keyAgreement(String privateKeyA, String userIdA, String publicKeyB, String userIdB) {
        validateNotBlank(privateKeyA, "本方私钥");
        validateNotBlank(userIdA, "本方标识");
        validateNotBlank(publicKeyB, "对方主公钥");
        validateNotBlank(userIdB, "对方标识");

        PointG2 dA = decodeG2(privateKeyA);
        PointG1 pPubB = decodeG1(publicKeyB);

        BigInteger h1B = h1(concat(new byte[]{HID_KEY_AGREEMENT}, userIdB.getBytes(StandardCharsets.UTF_8)));
        PointG2 qB = P2.multiply(h1B);

        BigInteger r = randomScalar();
        PointG1 rA = P1.multiply(r);

        Fp12 g1 = SM9Pairing.rate(rA, dA);
        Fp12 g2 = SM9Pairing.rate(pPubB, qB);
        Fp12 u = g1.mul(g2.pow(r));

        byte[] key = kdf(concat(rA.toBytes(), fp12ToBytes(u), userIdA.getBytes(StandardCharsets.UTF_8), userIdB.getBytes(StandardCharsets.UTF_8)), 128);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("RA", encodeG1(rA));
        result.put("sharedKey", CodecUtil.toHex(key).toUpperCase());
        result.put("keyLength", key.length);
        return result;
    }

    // ---------------- 核心辅助方法 ----------------

    private static BigInteger randomScalar() {
        BigInteger r;
        do {
            r = new BigInteger(256, RANDOM);
        } while (r.signum() == 0 || r.compareTo(N) >= 0);
        return r;
    }

    private static void validateNotBlank(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + "不能为空");
        }
    }

    private static Map<String, Object> verifyResult(boolean verified, String message) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("verified", verified);
        result.put("message", message);
        return result;
    }

    /** H1 函数：GM/T 0044.2 第 5.4.2.2 节。 */
    private static BigInteger h1(byte[] z) {
        BigInteger h = new BigInteger(1, sm3(concat(new byte[]{0x01}, z))).mod(N);
        return h.signum() == 0 ? BigInteger.ONE : h;
    }

    /** H2 函数：GM/T 0044.2 第 5.4.2.3 节。 */
    private static BigInteger h2(byte[] z) {
        BigInteger h = new BigInteger(1, sm3(concat(new byte[]{0x02}, z))).mod(N);
        return h.signum() == 0 ? BigInteger.ONE : h;
    }

    private static byte[] sm3(byte[] in) {
        org.bouncycastle.crypto.digests.SM3Digest md = new org.bouncycastle.crypto.digests.SM3Digest();
        md.update(in, 0, in.length);
        byte[] out = new byte[md.getDigestSize()];
        md.doFinal(out, 0);
        return out;
    }

    /** KDF 按比特长度派生（klen 为比特数，输出 klen/8 字节）。 */
    private static byte[] kdf(byte[] z, int klenBits) {
        int klen = klenBits / 8;
        byte[] out = new byte[klen];
        int ct = 1;
        int off = 0;
        while (off < klen) {
            byte[] cnt = {(byte) (ct >>> 24), (byte) (ct >>> 16), (byte) (ct >>> 8), (byte) ct};
            byte[] h = sm3(concat(z, cnt));
            int copy = Math.min(h.length, klen - off);
            System.arraycopy(h, 0, out, off, copy);
            off += copy;
            ct++;
        }
        return out;
    }

    private static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new IllegalArgumentException("异或操作数长度不一致");
        }
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    private static boolean isAllZero(byte[] data) {
        for (byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    private static byte[] fp12ToBytes(Fp12 f) {
        byte[] out = new byte[384];
        int off = 0;
        off = putFp4(out, off, f.c0);
        off = putFp4(out, off, f.c1);
        off = putFp4(out, off, f.c2);
        return out;
    }

    private static int putFp4(byte[] out, int off, Fp4 x) {
        off = putFp2(out, off, x.b0);
        return putFp2(out, off, x.b1);
    }

    private static int putFp2(byte[] out, int off, Fp2 x) {
        off = putBigInteger(out, off, x.a0);
        return putBigInteger(out, off, x.a1);
    }

    private static int putBigInteger(byte[] out, int off, BigInteger v) {
        byte[] b = v.mod(P).toByteArray();
        if (b.length > 32) {
            System.arraycopy(b, b.length - 32, out, off, 32);
        } else {
            System.arraycopy(b, 0, out, off + 32 - b.length, b.length);
        }
        return off + 32;
    }

    private static String encodeG1(PointG1 p) {
        if (p.isInfinity()) {
            throw new IllegalArgumentException("无法编码无穷远点");
        }
        byte[] bytes = p.toBytes();
        return CodecUtil.toHex(bytes).toUpperCase();
    }

    private static String encodeG2(PointG2 p) {
        if (p.isInfinity()) {
            throw new IllegalArgumentException("无法编码无穷远点");
        }
        byte[] bytes = p.toBytes();
        return CodecUtil.toHex(bytes).toUpperCase();
    }

    private static PointG1 decodeG1(String hex) {
        String h = cleanHex(hex);
        if (h.length() != 128) {
            throw new IllegalArgumentException("G1 点编码长度应为 128 位十六进制（64 字节），实际 " + h.length());
        }
        return PointG1.fromBytes(CodecUtil.fromHex(h));
    }

    private static PointG2 decodeG2(String hex) {
        String h = cleanHex(hex);
        if (h.length() != 256) {
            throw new IllegalArgumentException("G2 点编码长度应为 256 位十六进制（128 字节），实际 " + h.length());
        }
        return PointG2.fromBytes(CodecUtil.fromHex(h));
    }

    private static byte[] concat(byte[]... arrs) {
        int len = 0;
        for (byte[] a : arrs) {
            len += a.length;
        }
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] a : arrs) {
            System.arraycopy(a, 0, out, off, a.length);
            off += a.length;
        }
        return out;
    }

    private static String cleanHex(String hex) {
        if (hex == null) {
            return "";
        }
        return hex.replaceAll("[\\s:,]", "").replaceAll("(?i)^0x", "");
    }

    private static String padHex(String hex, int len) {
        StringBuilder sb = new StringBuilder(hex);
        while (sb.length() < len) {
            sb.insert(0, '0');
        }
        return sb.toString();
    }

    private static String formatHex(BigInteger v) {
        String hex = v.toString(16).toUpperCase();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 8) {
            if (i > 0) {
                sb.append(" ");
            }
            sb.append(hex.substring(i, Math.min(i + 8, hex.length())));
        }
        return sb.toString();
    }
}
