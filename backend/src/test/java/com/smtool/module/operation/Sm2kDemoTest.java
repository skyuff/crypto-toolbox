package com.smtool.module.operation;

import com.smtool.util.CodecUtil;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * 生成 SM2 固定小 k 加密示例数据，用于 k 碰撞分析功能验证。
 */
public class Sm2kDemoTest {

    public static void main(String[] args) throws Exception {
        X9ECParameters curve = GMNamedCurves.getByName("sm2p256v1");
        ECCurve ecCurve = curve.getCurve();
        ECPoint G = curve.getG();

        // 公钥 P_B = [d]G，d 为私钥
        BigInteger d = new BigInteger("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263", 16);
        ECPoint pub = G.multiply(d).normalize();
        String pubHex = CodecUtil.toHex(pub.getEncoded(false));
        System.out.println("公钥: " + pubHex);

        // 固定小 k
        BigInteger k = BigInteger.valueOf(12345);
        System.out.println("k (decimal): " + k);
        System.out.println("k (hex): " + k.toString(16));

        String plaintext = "hello sm2 k collision";
        byte[] m = plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // C1 = [k]G
        ECPoint c1Point = G.multiply(k).normalize();
        byte[] c1 = c1Point.getEncoded(false);

        // S = [k]P_B = (x2, y2)
        ECPoint s = pub.multiply(k).normalize();
        byte[] x2 = to32(s.getAffineXCoord().toBigInteger());
        byte[] y2 = to32(s.getAffineYCoord().toBigInteger());
        byte[] x2y2 = concat(x2, y2);

        // t = KDF(x2||y2, |M|)
        byte[] t = KdfService.kdf(new SM3Digest(), x2y2, m.length);

        // C2 = M xor t
        byte[] c2 = new byte[m.length];
        for (int i = 0; i < m.length; i++) {
            c2[i] = (byte) (m[i] ^ t[i]);
        }

        // C3 = Hash(x2 || M || y2)
        SM3Digest sm3 = new SM3Digest();
        sm3.update(x2, 0, x2.length);
        sm3.update(m, 0, m.length);
        sm3.update(y2, 0, y2.length);
        byte[] c3 = new byte[sm3.getDigestSize()];
        sm3.doFinal(c3, 0);

        // C1C3C2
        byte[] cipher = concat(concat(c1, c3), c2);
        System.out.println("完整密文 (C1C3C2): " + CodecUtil.toHex(cipher));
        System.out.println("C1: " + CodecUtil.toHex(c1));
        System.out.println("C2: " + CodecUtil.toHex(c2));
        System.out.println("C3: " + CodecUtil.toHex(c3));
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
}
