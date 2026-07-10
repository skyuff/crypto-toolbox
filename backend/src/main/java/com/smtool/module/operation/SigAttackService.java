package com.smtool.module.operation;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * SM2 随机数（nonce）重用签名攻击服务。
 *
 * <p>SM2 签名满足 s = (1 + d)^(-1) * (k - r*d) mod n，即 s*(1 + d) = k - r*d (mod n)。
 * 当两次签名重用相同的随机数 k 时：
 * <pre>
 *   s1*(1 + d) = k - r1*d      (1)
 *   s2*(1 + d) = k - r2*d      (2)
 * </pre>
 * (1) - (2) 消去 k：(s1 - s2)*(1 + d) = (r2 - r1)*d，展开整理得：
 * <pre>
 *   s1 - s2 = [(r2 - r1) - (s1 - s2)] * d   (mod n)
 *   => d = (s1 - s2) * [(r2 - r1) - (s1 - s2)]^(-1)  (mod n)
 * </pre>
 * 再回代求 k： k = s1*(1 + d) + r1*d (mod n)。
 */
@Service
public class SigAttackService {

    /** 从两组重用同一随机数的 SM2 签名恢复私钥 d 与随机数 k，并验证结果 */
    public Map<String, Object> sm2NonceReuse(SigAttackRequest req) {
        String curveName = (req.getCurve() == null || req.getCurve().isBlank()) ? "sm2p256v1" : req.getCurve();
        X9ECParameters curve = lookupCurve(curveName);
        if (curve == null) {
            throw new IllegalArgumentException("不支持的曲线: " + req.getCurve());
        }
        BigInteger n = curve.getN();
        ECPoint g = curve.getG();

        String fmt = (req.getInputFormat() == null || req.getInputFormat().isBlank()) ? "hex" : req.getInputFormat();
        BigInteger r1 = new BigInteger(decodeInput(req.getR1(), fmt), 16);
        BigInteger s1 = new BigInteger(decodeInput(req.getS1(), fmt), 16);
        BigInteger e1 = new BigInteger(decodeInput(req.getE1(), fmt), 16);
        BigInteger r2 = new BigInteger(decodeInput(req.getR2(), fmt), 16);
        BigInteger s2 = new BigInteger(decodeInput(req.getS2(), fmt), 16);
        BigInteger e2 = new BigInteger(decodeInput(req.getE2(), fmt), 16);

        Map<String, Object> result = new HashMap<>();

        // denom = (r2 - r1) - (s1 - s2) mod n
        BigInteger denom = r2.subtract(r1).subtract(s1.subtract(s2)).mod(n);
        if (denom.signum() == 0 || !denom.gcd(n).equals(BigInteger.ONE)) {
            result.put("success", false);
            result.put("verifyMessage", "分母不可逆，无法恢复私钥（两次签名可能未重用相同随机数）");
            return result;
        }

        try {
            // d = (s1 - s2) * denom^(-1) mod n
            BigInteger d = s1.subtract(s2).mod(n)
                    .multiply(denom.modInverse(n)).mod(n);
            // k = s1*(1 + d) + r1*d mod n
            BigInteger k = s1.multiply(BigInteger.ONE.add(d))
                    .add(r1.multiply(d)).mod(n);

            // 推导公钥 P = d*G
            ECPoint publicKey = g.multiply(d).normalize();
            String publicKeyHex = "04" + pad64(publicKey.getAffineXCoord().toBigInteger())
                    + pad64(publicKey.getAffineYCoord().toBigInteger());

            // 使用推导出的公钥验证两组签名
            boolean valid1 = verifySm2Signature(curve, publicKey, e1, r1, s1);
            boolean valid2 = verifySm2Signature(curve, publicKey, e2, r2, s2);
            boolean verified = valid1 && valid2;

            result.put("success", true);
            result.put("recoveredPrivateKey", pad64(d));
            result.put("recoveredK", pad64(k));
            result.put("recoveredPublicKey", publicKeyHex);
            result.put("verified", verified);
            result.put("group1Valid", valid1);
            result.put("group2Valid", valid2);
            result.put("verifyMessage", verified
                    ? "恢复出的私钥可正确验证两组签名，攻击成功"
                    : "已恢复私钥，但无法通过签名验证（输入数据可能不合法）");
            return result;
        } catch (ArithmeticException ex) {
            result.put("success", false);
            result.put("verifyMessage", "计算过程中出现算术异常，无法恢复私钥");
            return result;
        }
    }

    /** SM2 签名验证：t = r + s mod n，(x1, y1) = s*G + t*P，R = e + x1 mod n，valid iff R == r */
    private boolean verifySm2Signature(X9ECParameters curve, ECPoint publicKey,
                                       BigInteger e, BigInteger r, BigInteger s) {
        BigInteger n = curve.getN();
        if (r.signum() <= 0 || r.compareTo(n) >= 0 || s.signum() <= 0 || s.compareTo(n) >= 0) {
            return false;
        }
        BigInteger t = r.add(s).mod(n);
        if (t.signum() == 0) {
            return false;
        }
        ECPoint point = curve.getG().multiply(s).add(publicKey.multiply(t)).normalize();
        BigInteger x1 = point.getAffineXCoord().toBigInteger();
        BigInteger R = e.add(x1).mod(n);
        return R.equals(r);
    }

    /** 返回该攻击的中文原理说明（固定文本） */
    public String explain() {
        return "SM2 随机数重用攻击原理说明：\n"
                + "SM2 签名算法中，签名值 s = (1 + d)^(-1) * (k - r*d) mod n，其中 d 为签名私钥，"
                + "k 为每次签名应当随机且唯一的临时随机数，r 为签名分量，n 为曲线阶。\n"
                + "若签名者在两次签名中重用了相同的随机数 k，则得到两个方程：\n"
                + "  s1*(1 + d) = k - r1*d (mod n)\n"
                + "  s2*(1 + d) = k - r2*d (mod n)\n"
                + "两式相减即可消去未知量 k：(s1 - s2)*(1 + d) = (r2 - r1)*d (mod n)，"
                + "整理后可解出私钥：\n"
                + "  d = (s1 - s2) * [(r2 - r1) - (s1 - s2)]^(-1) (mod n)。\n"
                + "求得 d 后回代任一方程即可恢复随机数：k = s1*(1 + d) + r1*d (mod n)。\n"
                + "因此 SM2（以及 ECDSA 等）签名必须保证每次签名的随机数 k 唯一且不可预测，"
                + "一旦随机数重用，攻击者仅凭公开的两组签名即可恢复出私钥，造成灾难性后果。";
    }

    /** 按指定格式解码输入，统一输出为可解析的十六进制字符串 */
    private static String decodeInput(String value, String format) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("签名攻击输入值不能为空");
        }
        String cleaned = clean(value);
        if ("base64".equalsIgnoreCase(format)) {
            byte[] bytes = Base64.getDecoder().decode(cleaned);
            return bytesToHex(bytes);
        }
        return cleaned;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    /** 按名称查找椭圆曲线参数，依次查找国密、SEC、X9.62、TeleTrusT 命名曲线 */
    private static X9ECParameters lookupCurve(String name) {
        X9ECParameters curve = GMNamedCurves.getByName(name);
        if (curve != null) {
            return curve;
        }
        curve = SECNamedCurves.getByName(name);
        if (curve != null) {
            return curve;
        }
        curve = X962NamedCurves.getByName(name);
        if (curve != null) {
            return curve;
        }
        return TeleTrusTNamedCurves.getByName(name);
    }

    /** BigInteger 转 64 位十六进制字符串（左补 0） */
    private static String pad64(BigInteger v) {
        String h = v.toString(16);
        while (h.length() < 64) {
            h = "0" + h;
        }
        return h;
    }

    private static String clean(String hex) {
        return hex.replaceAll("[\\s:]", "").replaceAll("(?i)^0x", "");
    }
}
