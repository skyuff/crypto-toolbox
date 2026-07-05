package com.smtool.module.operation;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Map;

/**
 * SM2 随机数重用攻击示例测试：生成同一私钥、同一随机数 k 下的两组签名，
 * 再调用 SigAttackService 恢复私钥并验证。
 */
public class SigAttackDemoTest {

    public static void main(String[] args) {
        X9ECParameters curve = GMNamedCurves.getByName("sm2p256v1");
        BigInteger n = curve.getN();
        ECPoint g = curve.getG();

        // 固定私钥 d 和重用的随机数 k
        BigInteger d = new BigInteger("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263", 16);
        BigInteger k = new BigInteger("A0B1C2D3E4F5061728394A5B6C7D8E9F0A1B2C3D4E5F60718293A4B5C6D7E8F9", 16);

        // 两组消息摘要 e1, e2
        BigInteger e1 = new BigInteger("123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0", 16).mod(n);
        BigInteger e2 = new BigInteger("FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210", 16).mod(n);

        // 生成第一组签名
        SigValue sig1 = sign(curve, d, k, e1);
        // 生成第二组签名（重用 k）
        SigValue sig2 = sign(curve, d, k, e2);

        System.out.println("私钥 d: " + pad64(d));
        System.out.println("随机数 k: " + pad64(k));
        System.out.println("第一组签名 r1: " + pad64(sig1.r));
        System.out.println("第一组签名 s1: " + pad64(sig1.s));
        System.out.println("第一组消息 e1: " + pad64(e1));
        System.out.println("第二组签名 r2: " + pad64(sig2.r));
        System.out.println("第二组签名 s2: " + pad64(sig2.s));
        System.out.println("第二组消息 e2: " + pad64(e2));

        // 调用攻击服务
        SigAttackRequest req = new SigAttackRequest();
        req.setCurve("sm2p256v1");
        req.setInputFormat("hex");
        req.setR1(pad64(sig1.r));
        req.setS1(pad64(sig1.s));
        req.setE1(pad64(e1));
        req.setR2(pad64(sig2.r));
        req.setS2(pad64(sig2.s));
        req.setE2(pad64(e2));

        SigAttackService service = new SigAttackService();
        Map<String, Object> result = service.sm2NonceReuse(req);

        System.out.println("\n攻击结果:");
        System.out.println("success: " + result.get("success"));
        System.out.println("verified: " + result.get("verified"));
        System.out.println("recoveredPrivateKey: " + result.get("recoveredPrivateKey"));
        System.out.println("recoveredK: " + result.get("recoveredK"));
        System.out.println("recoveredPublicKey: " + result.get("recoveredPublicKey"));
        System.out.println("verifyMessage: " + result.get("verifyMessage"));

        boolean ok = result.get("success") == Boolean.TRUE
                && pad64(d).equalsIgnoreCase((String) result.get("recoveredPrivateKey"))
                && pad64(k).equalsIgnoreCase((String) result.get("recoveredK"));
        System.out.println("\n测试" + (ok ? "通过" : "失败"));
    }

    /** SM2 签名：r = (e + x1) mod n，s = (1+d)^(-1)*(k - r*d) mod n */
    private static SigValue sign(X9ECParameters curve, BigInteger d, BigInteger k, BigInteger e) {
        BigInteger n = curve.getN();
        ECPoint point = curve.getG().multiply(k).normalize();
        BigInteger x1 = point.getAffineXCoord().toBigInteger();
        BigInteger r = e.add(x1).mod(n);
        BigInteger s = k.subtract(r.multiply(d)).multiply(BigInteger.ONE.add(d).modInverse(n)).mod(n);
        return new SigValue(r, s);
    }

    private static String pad64(BigInteger v) {
        String h = v.toString(16);
        while (h.length() < 64) {
            h = "0" + h;
        }
        return h;
    }

    private static class SigValue {
        final BigInteger r;
        final BigInteger s;
        SigValue(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }
    }
}
