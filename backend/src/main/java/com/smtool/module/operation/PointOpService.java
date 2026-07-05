package com.smtool.module.operation;

import com.smtool.util.CodecUtil;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 椭圆曲线点运算服务。
 * 支持 sm2p256v1 / secp256r1 / secp256k1 / secp384r1 / secp521r1 等曲线上的
 * 点加 P+Q、点减 P-Q、点乘 [k]P / [k]G 运算。
 */
@Service
public class PointOpService {

    /** 执行点运算 */
    public Map<String, Object> calc(PointOpRequest req) {
        // 获取曲线参数
        X9ECParameters params = getCurve(req.getCurve());
        ECCurve curve = params.getCurve();
        ECPoint g = params.getG();

        String inputFmt = normalizeFormat(req.getInputFormat(), "hex");
        String outputFmt = normalizeFormat(req.getOutputFormat(), "hex");
        String op = req.getOp() == null ? "" : req.getOp().trim().toLowerCase();

        ECPoint result;
        switch (op) {
            case "add" -> {
                // P + Q
                ECPoint p = decodePoint(curve, req.getP(), "P", inputFmt);
                ECPoint qq = decodePoint(curve, req.getQ(), "Q", inputFmt);
                result = p.add(qq);
            }
            case "sub" -> {
                // P - Q = P + (-Q)
                ECPoint p = decodePoint(curve, req.getP(), "P", inputFmt);
                ECPoint qq = decodePoint(curve, req.getQ(), "Q", inputFmt);
                result = p.add(qq.negate());
            }
            case "mul" -> {
                // [k]P，P 为空时默认使用基点 G
                ECPoint p;
                if (req.getP() == null || req.getP().isBlank()) {
                    p = g;
                } else {
                    p = decodePoint(curve, req.getP(), "P", inputFmt);
                }
                BigInteger k = parseScalar(req.getQ(), inputFmt);
                result = p.multiply(k);
            }
            default -> throw new IllegalArgumentException("不支持的运算: " + req.getOp());
        }

        // 规范化坐标
        result = result.normalize();
        if (result.isInfinity()) {
            throw new IllegalArgumentException("运算结果为无穷远点");
        }

        byte[] uncompressedBytes = result.getEncoded(false);
        byte[] compressedBytes = result.getEncoded(true);

        Map<String, Object> map = new LinkedHashMap<>();
        map.put("result", encode(uncompressedBytes, outputFmt));
        map.put("resultUncompressed", encode(uncompressedBytes, outputFmt));
        map.put("resultCompressed", encode(compressedBytes, outputFmt));
        map.put("x", result.getAffineXCoord().toBigInteger().toString(16));
        map.put("y", result.getAffineYCoord().toBigInteger().toString(16));
        map.put("byteLength", uncompressedBytes.length);
        return map;
    }

    /** 根据曲线名称获取 X9ECParameters，依次查找国密、SEC、X9.62、TeleTrusT 命名曲线 */
    private X9ECParameters getCurve(String name) {
        String c = name == null || name.isBlank() ? "sm2p256v1" : name.trim();
        X9ECParameters params = GMNamedCurves.getByName(c);
        if (params != null) {
            return params;
        }
        params = SECNamedCurves.getByName(c);
        if (params != null) {
            return params;
        }
        params = X962NamedCurves.getByName(c);
        if (params != null) {
            return params;
        }
        params = TeleTrusTNamedCurves.getByName(c);
        if (params != null) {
            return params;
        }
        throw new IllegalArgumentException("不支持的曲线: " + name);
    }

    /** 解析标量 k */
    private BigInteger parseScalar(String k, String format) {
        if (k == null || k.isBlank()) {
            throw new IllegalArgumentException("标量 k 不能为空");
        }
        byte[] bytes = decodeInput(k, format);
        return new BigInteger(1, bytes);
    }

    /** 解析曲线上的点（04开头未压缩或02/03开头压缩） */
    private ECPoint decodePoint(ECCurve curve, String value, String name, String format) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("点 " + name + " 不能为空");
        }
        try {
            byte[] bytes = decodeInput(value, format);
            ECPoint point = curve.decodePoint(bytes).normalize();
            if (!point.isValid()) {
                throw new IllegalArgumentException("点 " + name + " 不在曲线上");
            }
            return point;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("点 " + name + " 解析失败: " + e.getMessage());
        }
    }

    /** 按指定格式解码输入为字节数组 */
    private byte[] decodeInput(String value, String format) {
        String cleaned = clean(value);
        if ("base64".equalsIgnoreCase(format)) {
            return Base64.getDecoder().decode(cleaned);
        }
        // hex 奇数长度时左侧补 0
        if (cleaned.length() % 2 == 1) {
            cleaned = "0" + cleaned;
        }
        return CodecUtil.fromHex(cleaned);
    }

    /** 按指定格式编码字节数组 */
    private String encode(byte[] bytes, String format) {
        if ("base64".equalsIgnoreCase(format)) {
            return Base64.getEncoder().encodeToString(bytes);
        }
        return CodecUtil.toHex(bytes);
    }

    private static String normalizeFormat(String format, String defaultValue) {
        if (format == null || format.isBlank()) {
            return defaultValue;
        }
        return format.trim().toLowerCase();
    }

    private static String clean(String value) {
        return value.replaceAll("[\\s:]", "").replaceAll("(?i)^0x", "");
    }
}
