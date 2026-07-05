package com.smtool.module.asymmetric;

import com.smtool.util.CodecUtil;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 椭圆曲线点压缩/解压缩服务。
 * SM2 曲线（sm2p256v1）使用 GMNamedCurves，SM9 使用 BN256 曲线，其余标准曲线使用 ECNamedCurveTable。
 */
@Service
public class PointService {

    private static final BigInteger SM9_P = new BigInteger(
            "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D", 16);
    private static final BigInteger SM9_A = BigInteger.ZERO;
    private static final BigInteger SM9_B = BigInteger.valueOf(5);
    private static final BigInteger SM9_N = new BigInteger(
            "B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25", 16);
    private static final BigInteger SM9_G1X = new BigInteger(
            "93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD", 16);
    private static final BigInteger SM9_G1Y = new BigInteger(
            "21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616", 16);

    /** 点压缩/解压缩，同时返回压缩、未压缩表示以及点合法性 */
    public Map<String, Object> compress(PointRequest req) {
        String curveName = curveOf(req.getCurve());
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("curve", curveName);

        try {
            byte[] pointBytes = CodecUtil.fromHex(req.getPoint());
            ECPoint point = decodePoint(curveName, pointBytes);
            boolean valid = point.isValid();

            result.put("compressed", CodecUtil.toHex(point.getEncoded(true)));
            result.put("uncompressed", CodecUtil.toHex(point.getEncoded(false)));
            result.put("valid", valid);
        } catch (Exception e) {
            result.put("compressed", null);
            result.put("uncompressed", null);
            result.put("valid", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    /** 返回指定曲线的参数信息 */
    public Map<String, Object> curveParams(String curve) {
        String curveName = curveOf(curve);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", curveName);

        if ("sm9".equals(curveName)) {
            result.put("curveEquation", "y^2 = x^3 + b，256 位 BN 椭圆曲线");
            result.put("p", padHex(SM9_P.toString(16), 64).toUpperCase());
            result.put("a", padHex(SM9_A.toString(16), 64).toUpperCase());
            result.put("b", padHex(SM9_B.toString(16), 64).toUpperCase());
            result.put("n", padHex(SM9_N.toString(16), 64).toUpperCase());
            result.put("gx", padHex(SM9_G1X.toString(16), 64).toUpperCase());
            result.put("gy", padHex(SM9_G1Y.toString(16), 64).toUpperCase());
        } else {
            X9ECParameters params = getCurveParams(curveName);
            ECCurve c = params.getCurve();
            result.put("curveEquation", "y^2 = x^3 + ax + b");
            result.put("p", padHex(c.getField().getCharacteristic().toString(16), 64).toUpperCase());
            result.put("a", padHex(c.getA().toBigInteger().toString(16), 64).toUpperCase());
            result.put("b", padHex(c.getB().toBigInteger().toString(16), 64).toUpperCase());
            result.put("n", padHex(params.getN().toString(16), 64).toUpperCase());
            result.put("gx", padHex(params.getG().getAffineXCoord().toBigInteger().toString(16), 64).toUpperCase());
            result.put("gy", padHex(params.getG().getAffineYCoord().toBigInteger().toString(16), 64).toUpperCase());
        }
        return result;
    }

    /** 压缩公钥：未压缩 -> 压缩 */
    public Map<String, Object> compressPublicKey(PointRequest req) {
        String curveName = curveOf(req.getCurve());
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("curve", curveName);
        try {
            byte[] pointBytes = CodecUtil.fromHex(req.getPoint());
            ECPoint point = decodePoint(curveName, pointBytes);
            if (!point.isValid()) {
                result.put("valid", false);
                result.put("compressed", null);
                return result;
            }
            result.put("valid", true);
            result.put("compressed", CodecUtil.toHex(point.getEncoded(true)));
        } catch (Exception e) {
            result.put("valid", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    /** 解压缩公钥：压缩 -> 未压缩 */
    public Map<String, Object> decompressPublicKey(PointRequest req) {
        String curveName = curveOf(req.getCurve());
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("curve", curveName);
        try {
            byte[] pointBytes = CodecUtil.fromHex(req.getPoint());
            ECPoint point = decodePoint(curveName, pointBytes);
            if (!point.isValid()) {
                result.put("valid", false);
                result.put("uncompressed", null);
                return result;
            }
            result.put("valid", true);
            result.put("uncompressed", CodecUtil.toHex(point.getEncoded(false)));
        } catch (Exception e) {
            result.put("valid", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    // ---------- 内部工具 ----------

    /** 规范化曲线名称，默认 sm2p256v1 */
    private String curveOf(String curve) {
        String c = (curve == null || curve.isBlank()) ? "sm2p256v1" : curve.trim();
        return switch (c.toLowerCase()) {
            case "sm2p256v1", "sm2" -> "sm2p256v1";
            case "sm9", "sm9p256", "bn256", "sm9g1" -> "sm9";
            case "secp256r1", "p-256", "p256", "prime256v1" -> "secp256r1";
            case "secp256k1" -> "secp256k1";
            default -> throw new IllegalArgumentException("不支持的曲线: " + curve);
        };
    }

    /** 根据曲线名解码点 */
    private ECPoint decodePoint(String curveName, byte[] encoded) {
        return getCurve(curveName).decodePoint(encoded);
    }

    /** SM9 G1 曲线：y^2 = x^3 + b, a=0, b=5 */
    private ECCurve getSm9Curve() {
        return new org.bouncycastle.math.ec.ECCurve.Fp(SM9_P, SM9_A, SM9_B, SM9_N, BigInteger.ONE);
    }

    /** 获取标准曲线参数 */
    private X9ECParameters getCurveParams(String curveName) {
        X9ECParameters params = "sm2p256v1".equals(curveName)
                ? GMNamedCurves.getByName(curveName)
                : ECNamedCurveTable.getByName(curveName);
        if (params == null) {
            throw new IllegalArgumentException("无法获取曲线参数: " + curveName);
        }
        return params;
    }

    /** 根据曲线名获取 ECCurve */
    private ECCurve getCurve(String curveName) {
        if ("sm9".equals(curveName)) {
            return getSm9Curve();
        }
        return getCurveParams(curveName).getCurve();
    }

    private static String padHex(String hex, int len) {
        if (hex.length() >= len) return hex;
        StringBuilder sb = new StringBuilder();
        while (sb.length() < len - hex.length()) sb.append('0');
        return sb.append(hex).toString();
    }
}
