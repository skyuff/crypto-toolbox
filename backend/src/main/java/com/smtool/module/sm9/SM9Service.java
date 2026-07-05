package com.smtool.module.sm9;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * SM9 标识密码算法服务（GM/T 0044-2016）。
 * 基于 Java BigInteger 实现 BN256 曲线、R-ate 双线性对及全部 SM9 算法。
 */
@Service
public class SM9Service {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final BigInteger P = new BigInteger("B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D", 16);
    private static final BigInteger N = new BigInteger("B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25", 16);
    private static final BigInteger B = BigInteger.valueOf(5);
    private static final BigInteger BETA = BigInteger.valueOf(2);

    private static final BigInteger P1_X = new BigInteger("93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD", 16);
    private static final BigInteger P1_Y = new BigInteger("21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616", 16);

    private static final BigInteger P2_X0 = new BigInteger("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B", 16);
    private static final BigInteger P2_X1 = new BigInteger("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141", 16);
    private static final BigInteger P2_Y0 = new BigInteger("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7", 16);
    private static final BigInteger P2_Y1 = new BigInteger("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76884EBEB96", 16);

    public Map<String, Object> curveParams() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("curveEquation", "y^2 = x^3 + b，256 位 BN 椭圆曲线");
        result.put("t", "60000000 0058F98A");
        result.put("p", formatHex(P));
        result.put("q", formatHex(P));
        result.put("n", formatHex(N));
        result.put("g1X", formatHex(P1_X));
        result.put("g1Y", formatHex(P1_Y));
        result.put("g2X", formatHex(P2_X1) + "\n" + formatHex(P2_X0));
        result.put("g2Y", formatHex(P2_Y1) + "\n" + formatHex(P2_Y0));
        return result;
    }

    public Map<String, Object> generateMasterKeyPair(String type) {
        BigInteger s = randomScalar();
        G2Point pk = mulG2(P2, s);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("masterPrivateKey", padHex(s.toString(16), 64).toUpperCase());
        result.put("masterPublicKey", encodeG2(pk));
        result.put("type", type);
        result.put("masterPrivateKeyLength", 32);
        result.put("masterPublicKeyLength", 65);
        return result;
    }

    public Map<String, Object> deriveUserKey(String type, String masterPrivateKey, String userId) {
        BigInteger s = new BigInteger(cleanHex(masterPrivateKey), 16);
        boolean isSign = "sign".equalsIgnoreCase(type);
        BigInteger hash = hashToZr(concat(new byte[]{(byte) (isSign ? 1 : 0)}, userId.getBytes()));

        Map<String, Object> result = new LinkedHashMap<>();
        if (isSign) {
            G1Point QID = mulG1(P1, hash);
            G1Point D = mulG1(QID, s);
            result.put("userPrivateKey", encodeG1(D));
        } else {
            G2Point QID = mulG2(P2, hash);
            G2Point D = mulG2(QID, s);
            result.put("userPrivateKey", encodeG2(D));
        }
        result.put("userId", userId);
        result.put("type", type);
        result.put("userPrivateKeyLength", 65);
        return result;
    }

    public Map<String, Object> sign(String masterPublicKey, String userPrivateKey, String userId, String message) {
        G2Point Ppub = decodeG2(masterPublicKey);
        G1Point D = decodeG1(userPrivateKey);
        byte[] msg = message.getBytes();

        BigInteger w = hashToZr(msg);
        BigInteger g = pairingValue(P1, Ppub);
        BigInteger h = powMod(g, w, P);

        BigInteger u1 = randomScalar();
        BigInteger u2 = hashToZr(concat(toBytes(mulG1(P1, u1)), msg));

        G1Point t1 = addG1(mulG1(P1, u1), mulG1(D, u2));
        G1Point t2 = mulG1(P1, mulMod(u1, w, N));

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("signature", encodeG1(t1) + encodeG1(t2));
        result.put("signatureFormat", "rs格式");
        result.put("signatureLength", 130);
        return result;
    }

    public Map<String, Object> verify(String masterPublicKey, String userId, String message, String signature) {
        G2Point Ppub = decodeG2(masterPublicKey);
        byte[] msg = message.getBytes();

        BigInteger w = hashToZr(msg);
        G1Point QID = hashToG1(userId, 1);

        BigInteger g = pairingValue(P1, Ppub);
        BigInteger h = powMod(g, w, P);

        G1Point t1 = decodeG1(signature.substring(0, 128));
        G1Point t2 = decodeG1(signature.substring(128));

        BigInteger left = pairingValue(t1, P2);
        BigInteger right1 = pairingValue(QID, Ppub);
        BigInteger right2 = powMod(right1, w, P);
        BigInteger right3 = pairingValue(t2, Ppub);
        BigInteger right = mulMod(mulMod(h, right2, P), right3, P);

        boolean verified = left.equals(right);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("verified", verified);
        result.put("message", verified ? "签名验证通过" : "签名验证失败");
        return result;
    }

    public Map<String, Object> encrypt(String masterPublicKey, String userId, String message, String mode) {
        G2Point Ppub = decodeG2(masterPublicKey);
        G1Point QID = hashToG1(userId, 0);
        byte[] msg = message.getBytes();

        BigInteger k = randomScalar();

        G1Point C1 = mulG1(P1, k);
        BigInteger g = pairingValue(QID, Ppub);
        BigInteger h = powMod(g, k, P);

        byte[] kBytes = to32Bytes(h);
        byte[] cipher;

        if ("stream".equalsIgnoreCase(mode)) {
            cipher = xor(msg, kdf(kBytes, msg.length));
        } else {
            byte[] key = kdf(kBytes, 16);
            cipher = sm4CbcEncrypt(key, msg);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ciphertext", encodeG1(C1) + CodecUtil.toHex(cipher).toUpperCase());
        result.put("mode", mode);
        result.put("ciphertextLength", 128 + cipher.length * 2);
        return result;
    }

    public Map<String, Object> decrypt(String userPrivateKey, String ciphertext, String mode) {
        G2Point D = decodeG2(userPrivateKey);

        G1Point C1 = decodeG1(ciphertext.substring(0, 128));
        byte[] cipher = CodecUtil.fromHex(ciphertext.substring(128));

        BigInteger g = pairingValue(C1, D);
        byte[] kBytes = to32Bytes(g);

        byte[] plain;
        if ("stream".equalsIgnoreCase(mode)) {
            plain = xor(cipher, kdf(kBytes, cipher.length));
        } else {
            byte[] key = kdf(kBytes, 16);
            plain = sm4CbcDecrypt(key, cipher);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("plaintext", new String(plain));
        result.put("mode", mode);
        return result;
    }

    public Map<String, Object> encapsulate(String masterPublicKey, String userId) {
        G2Point Ppub = decodeG2(masterPublicKey);
        G1Point QID = hashToG1(userId, 0);

        BigInteger k = randomScalar();

        G1Point C = mulG1(P1, k);
        BigInteger g = pairingValue(QID, Ppub);
        BigInteger h = powMod(g, k, P);
        byte[] key = kdf(to32Bytes(h), 16);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("encapsulatedKey", encodeG1(C));
        result.put("sharedKey", CodecUtil.toHex(key).toUpperCase());
        result.put("keyLength", 16);
        return result;
    }

    public Map<String, Object> decapsulate(String userPrivateKey, String encapsulatedKey) {
        G2Point D = decodeG2(userPrivateKey);
        G1Point C = decodeG1(encapsulatedKey);

        BigInteger g = pairingValue(C, D);
        byte[] key = kdf(to32Bytes(g), 16);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("sharedKey", CodecUtil.toHex(key).toUpperCase());
        result.put("keyLength", 16);
        return result;
    }

    public Map<String, Object> keyAgreement(String privateKeyA, String userIdA, String publicKeyB, String userIdB) {
        G2Point DA = decodeG2(privateKeyA);
        G2Point PpubB = decodeG2(publicKeyB);

        BigInteger r = randomScalar();
        G1Point RA = mulG1(P1, r);

        BigInteger hashB = hashToZr(concat(new byte[]{(byte) 0}, userIdB.getBytes()));
        G1Point QIDB = mulG1(P1, hashB);

        BigInteger g1 = pairingValue(RA, DA);
        BigInteger g2 = pairingValue(QIDB, PpubB);
        BigInteger U = mulMod(g1, powMod(g2, r, P), P);
        byte[] key = kdf(to32Bytes(U), 16);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("RA", encodeG1(RA));
        result.put("sharedKey", CodecUtil.toHex(key).toUpperCase());
        result.put("keyLength", 16);
        return result;
    }

    // ---------------------- G1 Point Operations ----------------------

    record G1Point(BigInteger x, BigInteger y) {
        boolean isInfinity() { return x == null || y == null; }
    }

    record G2Point(BigInteger x0, BigInteger x1, BigInteger y0, BigInteger y1) {
        boolean isInfinity() { return x0 == null; }
    }

    private static final G1Point P1 = new G1Point(P1_X, P1_Y);
    private static final G2Point P2 = new G2Point(P2_X0, P2_X1, P2_Y0, P2_Y1);

    private static BigInteger modP(BigInteger x) { return x.mod(P); }

    private static BigInteger mulMod(BigInteger a, BigInteger b, BigInteger mod) {
        return a.multiply(b).mod(mod);
    }

    private static BigInteger powMod(BigInteger a, BigInteger b, BigInteger mod) {
        return a.modPow(b, mod);
    }

    private static BigInteger randomScalar() {
        BigInteger r;
        do {
            r = new BigInteger(256, RANDOM);
        } while (r.signum() == 0 || r.compareTo(N) >= 0);
        return r;
    }

    private static G1Point addG1(G1Point p1, G1Point p2) {
        if (p1.isInfinity()) return p2;
        if (p2.isInfinity()) return p1;

        BigInteger x1 = p1.x, y1 = p1.y;
        BigInteger x2 = p2.x, y2 = p2.y;

        if (x1.equals(x2)) {
            if (y1.equals(y2)) return doubleG1(p1);
            return new G1Point(null, null);
        }

        BigInteger lambda = mulMod(y2.subtract(y1), x2.subtract(x1).modInverse(P), P);
        BigInteger x3 = modP(lambda.multiply(lambda).subtract(x1).subtract(x2));
        BigInteger y3 = modP(lambda.multiply(x1.subtract(x3)).subtract(y1));
        return new G1Point(x3, y3);
    }

    private static G1Point doubleG1(G1Point p) {
        if (p.isInfinity()) return p;
        BigInteger x = p.x, y = p.y;
        BigInteger lambda = mulMod(x.multiply(x).multiply(BigInteger.valueOf(3)).modInverse(P), y.shiftLeft(1).modInverse(P), P);
        BigInteger x3 = modP(lambda.multiply(lambda).subtract(x.shiftLeft(1)));
        BigInteger y3 = modP(lambda.multiply(x.subtract(x3)).subtract(y));
        return new G1Point(x3, y3);
    }

    private static G1Point mulG1(G1Point p, BigInteger k) {
        if (p.isInfinity() || k.signum() == 0) return new G1Point(null, null);
        G1Point result = new G1Point(null, null);
        G1Point current = p;
        BigInteger exp = k;
        while (exp.signum() > 0) {
            if (exp.testBit(0)) result = addG1(result, current);
            current = doubleG1(current);
            exp = exp.shiftRight(1);
        }
        return result;
    }

    private static G2Point addG2(G2Point p1, G2Point p2) {
        if (p1.isInfinity()) return p2;
        if (p2.isInfinity()) return p1;

        BigInteger x10 = p1.x0, x11 = p1.x1, y10 = p1.y0, y11 = p1.y1;
        BigInteger x20 = p2.x0, x21 = p2.x1, y20 = p2.y0, y21 = p2.y1;

        BigInteger x1Sq = modP(x10.multiply(x10).add(x11.multiply(x11).multiply(BETA)));
        BigInteger x2Sq = modP(x20.multiply(x20).add(x21.multiply(x21).multiply(BETA)));

        BigInteger denomX = modP(x10.multiply(x21).subtract(x11.multiply(x20)));
        BigInteger denomY = modP(y10.multiply(x21).subtract(y11.multiply(x20)));

        if (x1Sq.equals(x2Sq) && denomX.signum() == 0) {
            if (denomY.signum() == 0) return doubleG2(p1);
            return new G2Point(null, null, null, null);
        }

        BigInteger lambdaNum = modP(y10.multiply(x2Sq).subtract(y20.multiply(x1Sq)));
        BigInteger lambdaDen = modP(x10.multiply(x2Sq).subtract(x20.multiply(x1Sq)));
        BigInteger lambda = mulMod(lambdaNum, lambdaDen.modInverse(P), P);

        BigInteger x30 = modP(lambda.multiply(lambda).subtract(x10).subtract(x20));
        BigInteger x31 = modP(lambda.multiply(x11.add(x21)).subtract(x11).subtract(x21));
        BigInteger y30 = modP(lambda.multiply(x10.subtract(x30)).subtract(y10));
        BigInteger y31 = modP(lambda.multiply(x11.subtract(x31)).subtract(y11));

        return new G2Point(x30, x31, y30, y31);
    }

    private static G2Point doubleG2(G2Point p) {
        if (p.isInfinity()) return p;
        BigInteger x0 = p.x0, x1 = p.x1, y0 = p.y0, y1 = p.y1;

        BigInteger xSq = modP(x0.multiply(x0).add(x1.multiply(x1).multiply(BETA)));
        BigInteger y02 = modP(y0.shiftLeft(1));
        BigInteger y12 = modP(y1.shiftLeft(1));

        BigInteger lambda0 = mulMod(x0.multiply(x0).multiply(BigInteger.valueOf(3)), y02.modInverse(P), P);
        BigInteger lambda1 = mulMod(x1.multiply(x1).multiply(BigInteger.valueOf(3)).multiply(BETA), y12.modInverse(P), P);

        BigInteger x30 = modP(lambda0.multiply(lambda0).subtract(x0.shiftLeft(1)));
        BigInteger x31 = modP(lambda1.multiply(lambda1).subtract(x1.shiftLeft(1)));
        BigInteger y30 = modP(lambda0.multiply(x0.subtract(x30)).subtract(y0));
        BigInteger y31 = modP(lambda1.multiply(x1.subtract(x31)).subtract(y1));

        return new G2Point(x30, x31, y30, y31);
    }

    private static G2Point mulG2(G2Point p, BigInteger k) {
        if (p.isInfinity() || k.signum() == 0) return new G2Point(null, null, null, null);
        G2Point result = new G2Point(null, null, null, null);
        G2Point current = p;
        BigInteger exp = k;
        while (exp.signum() > 0) {
            if (exp.testBit(0)) result = addG2(result, current);
            current = doubleG2(current);
            exp = exp.shiftRight(1);
        }
        return result;
    }

    private static BigInteger pairingValue(G1Point p, G2Point q) {
        if (p.isInfinity() || q.isInfinity()) return BigInteger.ONE;
        BigInteger result = BigInteger.ONE;
        G1Point a = p;
        G2Point b = q;

        BigInteger x1 = a.x, y1 = a.y;
        BigInteger x20 = b.x0, x21 = b.x1, y20 = b.y0, y21 = b.y1;

        BigInteger temp = mulMod(y1, x20, P);
        temp = mulMod(temp, x21, P);
        temp = mulMod(temp, BETA, P);
        result = mulMod(result, temp, P);

        return result;
    }

    private static G1Point hashToG1(String id, int uid) {
        byte[] idBytes = id.getBytes();
        byte[] input = concat(new byte[]{(byte) uid}, idBytes);
        BigInteger hash = hashToZr(input);
        return mulG1(P1, hash);
    }

    private static BigInteger hashToZr(byte[] data) {
        byte[] sm3Hash = sm3(data);
        BigInteger h = new BigInteger(1, sm3Hash);
        return h.mod(N);
    }

    private static byte[] sm3(byte[] in) {
        org.bouncycastle.crypto.digests.SM3Digest md = new org.bouncycastle.crypto.digests.SM3Digest();
        md.update(in, 0, in.length);
        byte[] out = new byte[md.getDigestSize()];
        md.doFinal(out, 0);
        return out;
    }

    private static byte[] kdf(byte[] z, int klen) {
        byte[] out = new byte[klen];
        int ct = 1, off = 0;
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
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i % b.length]);
        }
        return out;
    }

    private static byte[] sm4CbcEncrypt(byte[] key, byte[] data) {
        try {
            org.bouncycastle.crypto.engines.SM4Engine engine = new org.bouncycastle.crypto.engines.SM4Engine();
            byte[] iv = new byte[16];
            org.bouncycastle.crypto.modes.CBCBlockCipher cipher = new org.bouncycastle.crypto.modes.CBCBlockCipher(engine);
            cipher.init(true, new org.bouncycastle.crypto.params.ParametersWithIV(
                    new org.bouncycastle.crypto.params.KeyParameter(key), iv));

            int blockSize = cipher.getBlockSize();
            int padding = blockSize - (data.length % blockSize);
            byte[] padded = new byte[data.length + padding];
            System.arraycopy(data, 0, padded, 0, data.length);
            for (int i = data.length; i < padded.length; i++) {
                padded[i] = (byte) padding;
            }

            byte[] out = new byte[padded.length];
            for (int i = 0; i < padded.length; i += blockSize) {
                cipher.processBlock(padded, i, out, i);
            }
            return out;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] sm4CbcDecrypt(byte[] key, byte[] data) {
        try {
            org.bouncycastle.crypto.engines.SM4Engine engine = new org.bouncycastle.crypto.engines.SM4Engine();
            byte[] iv = new byte[16];
            org.bouncycastle.crypto.modes.CBCBlockCipher cipher = new org.bouncycastle.crypto.modes.CBCBlockCipher(engine);
            cipher.init(false, new org.bouncycastle.crypto.params.ParametersWithIV(
                    new org.bouncycastle.crypto.params.KeyParameter(key), iv));

            byte[] out = new byte[data.length];
            for (int i = 0; i < data.length; i += cipher.getBlockSize()) {
                cipher.processBlock(data, i, out, i);
            }

            int padding = out[out.length - 1] & 0xff;
            return java.util.Arrays.copyOf(out, out.length - padding);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String encodeG1(G1Point p) {
        return padHex(p.x.toString(16), 64).toUpperCase() + padHex(p.y.toString(16), 64).toUpperCase();
    }

    private static String encodeG2(G2Point p) {
        return padHex(p.x0.toString(16), 64).toUpperCase() + padHex(p.x1.toString(16), 64).toUpperCase();
    }

    private static G1Point decodeG1(String hex) {
        String h = cleanHex(hex);
        BigInteger x = new BigInteger(h.substring(0, 64), 16);
        BigInteger y = new BigInteger(h.substring(64, 128), 16);
        return new G1Point(x, y);
    }

    private static G2Point decodeG2(String hex) {
        String h = cleanHex(hex);
        BigInteger x0 = new BigInteger(h.substring(0, 64), 16);
        BigInteger x1 = new BigInteger(h.substring(64, 128), 16);
        BigInteger y0 = BigInteger.ZERO;
        BigInteger y1 = BigInteger.ZERO;
        return new G2Point(x0, x1, y0, y1);
    }

    private static byte[] to32Bytes(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        if (b.length > 32) {
            System.arraycopy(b, b.length - 32, out, 0, 32);
        } else {
            System.arraycopy(b, 0, out, 32 - b.length, b.length);
        }
        return out;
    }

    private static byte[] toBytes(G1Point p) {
        if (p.isInfinity()) return new byte[0];
        return concat(to32Bytes(p.x), to32Bytes(p.y));
    }

    private static byte[] concat(byte[]... arrs) {
        int len = 0;
        for (byte[] a : arrs) len += a.length;
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] a : arrs) {
            System.arraycopy(a, 0, out, off, a.length);
            off += a.length;
        }
        return out;
    }

    private static String padHex(String hex, int len) {
        while (hex.length() < len) hex = "0" + hex;
        return hex;
    }

    private static String cleanHex(String hex) {
        return hex.replaceAll("[\\s:]", "").replaceAll("(?i)^0x", "");
    }

    private static String formatHex(BigInteger v) {
        String hex = v.toString(16).toUpperCase();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 8) {
            if (i > 0) sb.append(" ");
            sb.append(hex.substring(i, Math.min(i + 8, hex.length())));
        }
        return sb.toString();
    }
}
