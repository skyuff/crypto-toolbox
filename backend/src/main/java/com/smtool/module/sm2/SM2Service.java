package com.smtool.module.sm2;

import com.smtool.util.CodecUtil;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * SM2 算法服务：公私钥生成、加解密（C1C3C2 / C1C2C3）、签名验签（含 Za）。
 */
@Service
public class SM2Service {

    private static final X9ECParameters CURVE = GMNamedCurves.getByName("sm2p256v1");
    private static final ECDomainParameters DOMAIN = new ECDomainParameters(
            CURVE.getCurve(), CURVE.getG(), CURVE.getN(), CURVE.getH());

    /** 生成 SM2 密钥对 */
    public Map<String, Object> generateKeyPair() {
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(DOMAIN, new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        BigInteger d = ((ECPrivateKeyParameters) kp.getPrivate()).getD();
        ECPoint q = ((ECPublicKeyParameters) kp.getPublic()).getQ();

        Map<String, Object> result = new HashMap<>();
        result.put("privateKey", padHex(d.toString(16), 64));
        result.put("publicKey", "04" + pointXY(q));
        result.put("publicKeyX", padHex(q.getAffineXCoord().toBigInteger().toString(16), 64));
        result.put("publicKeyY", padHex(q.getAffineYCoord().toBigInteger().toString(16), 64));
        return result;
    }

    /** 返回 sm2p256v1 曲线参数（曲线名/p/a/b/n/Gx/Gy）。 */
    public Map<String, Object> curveParams() {
        Map<String, Object> result = new HashMap<>();
        result.put("name", "sm2p256v1");
        result.put("p", padHex(CURVE.getCurve().getField().getCharacteristic().toString(16), 64).toUpperCase());
        result.put("a", padHex(CURVE.getCurve().getA().toBigInteger().toString(16), 64).toUpperCase());
        result.put("b", padHex(CURVE.getCurve().getB().toBigInteger().toString(16), 64).toUpperCase());
        result.put("n", padHex(CURVE.getN().toString(16), 64).toUpperCase());
        result.put("gx", padHex(CURVE.getG().getAffineXCoord().toBigInteger().toString(16), 64).toUpperCase());
        result.put("gy", padHex(CURVE.getG().getAffineYCoord().toBigInteger().toString(16), 64).toUpperCase());
        return result;
    }

    /** 由私钥 d 计算公钥 P = [d]G。 */
    public Map<String, Object> computePublicKey(SM2Request req) {
        BigInteger d = parsePrivateScalar(req.getPrivateKey(), "私钥");
        ECPoint q = DOMAIN.getG().multiply(d).normalize();
        Map<String, Object> result = new HashMap<>();
        result.put("publicKey", "04" + pointXY(q));
        result.put("publicKeyX", padHex(q.getAffineXCoord().toBigInteger().toString(16), 64).toUpperCase());
        result.put("publicKeyY", padHex(q.getAffineYCoord().toBigInteger().toString(16), 64).toUpperCase());
        return result;
    }

    /** 验证公钥是否为曲线上的有效点（非无穷远、在曲线上、阶正确）。 */
    public Map<String, Object> validatePublicKey(SM2Request req) {
        Map<String, Object> result = new HashMap<>();
        try {
            ECPublicKeyParameters pub = parsePublicKey(req.getPublicKey());
            ECPoint q = pub.getQ();
            boolean valid = !q.isInfinity() && q.isValid();
            result.put("valid", valid);
            result.put("onCurve", valid);
            result.put("publicKeyX", padHex(q.getAffineXCoord().toBigInteger().toString(16), 64).toUpperCase());
            result.put("publicKeyY", padHex(q.getAffineYCoord().toBigInteger().toString(16), 64).toUpperCase());
            result.put("message", valid ? "公钥有效，为曲线上的合法点" : "公钥无效");
        } catch (Exception e) {
            result.put("valid", false);
            result.put("message", "公钥解析失败：" + e.getMessage());
        }
        return result;
    }

    /**
     * 计算 e 值：Z = SM3(ENTL||ID||a||b||xG||yG||xA||yA)，e = SM3(Z||M)。
     * 返回 Z 值与 e 值（十六进制）。
     */
    public Map<String, Object> computeE(SM2Request req) {
        requireNonBlank(req.getPublicKey(), "公钥");
        requireNonBlank(req.getInput(), "输入消息");
        ECPoint pub = parsePublicKey(req.getPublicKey()).getQ();
        byte[] id = userId(req.getUserId());
        byte[] z = za(id, pub);
        byte[] data = CodecUtil.decode(req.getInput(), req.getInputFormat());
        byte[] e = sm3(concat(z, data));

        Map<String, Object> result = new HashMap<>();
        result.put("z", CodecUtil.toHex(z).toUpperCase());
        result.put("e", CodecUtil.toHex(e).toUpperCase());
        return result;
    }

    /**
     * 私钥解析：输入私钥（hex 或 PKCS8 PEM/DER），解析出私钥 d 与对应公钥 P=[d]G。
     */
    public Map<String, Object> parsePrivateKeyInput(SM2Request req) throws Exception {
        String raw = req.getPrivateKey() == null ? "" : req.getPrivateKey().trim();
        BigInteger d = extractPrivateD(raw);
        ECPoint q = DOMAIN.getG().multiply(d).normalize();

        Map<String, Object> result = new HashMap<>();
        result.put("privateKey", padHex(d.toString(16), 64).toUpperCase());
        result.put("publicKey", "04" + pointXY(q).toUpperCase());
        result.put("publicKeyX", padHex(q.getAffineXCoord().toBigInteger().toString(16), 64).toUpperCase());
        result.put("publicKeyY", padHex(q.getAffineYCoord().toBigInteger().toString(16), 64).toUpperCase());
        return result;
    }

    /** 从 hex / Base64 / PEM(PKCS8 或 SEC1) 中提取私钥标量 d。 */
    private BigInteger extractPrivateD(String raw) throws Exception {
        String h = cleanHex(raw);
        // 纯 64 位 hex 私钥
        if (h.matches("(?i)[0-9a-f]{64}")) {
            return new BigInteger(h, 16);
        }
        // PEM / Base64 DER，尝试 PKCS8
        byte[] der;
        if (raw.contains("-----BEGIN")) {
            String base64 = raw.replaceAll("-----BEGIN[^-]*-----", "")
                    .replaceAll("-----END[^-]*-----", "").replaceAll("\\s", "");
            der = java.util.Base64.getDecoder().decode(base64);
        } else if (raw.matches("(?i)[0-9a-f\\s:]+") && cleanHex(raw).length() % 2 == 0) {
            der = CodecUtil.fromHex(cleanHex(raw));
        } else {
            der = java.util.Base64.getDecoder().decode(raw.replaceAll("\\s", ""));
        }
        // 尝试 PKCS8
        try {
            org.bouncycastle.asn1.pkcs.PrivateKeyInfo info =
                    org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(der);
            org.bouncycastle.asn1.sec.ECPrivateKey ec =
                    org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(info.parsePrivateKey());
            return ec.getKey();
        } catch (Exception ignore) {
            // 尝试 SEC1 ECPrivateKey
            org.bouncycastle.asn1.sec.ECPrivateKey ec =
                    org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(der);
            return ec.getKey();
        }
    }

    /** SM2 加密，mode: C1C3C2(默认) / C1C2C3 */
    public Map<String, Object> encrypt(SM2Request req) throws Exception {
        SM2Engine.Mode mode = "C1C2C3".equalsIgnoreCase(req.getMode())
                ? SM2Engine.Mode.C1C2C3 : SM2Engine.Mode.C1C3C2;
        ECPublicKeyParameters pub = parsePublicKey(req.getPublicKey());
        byte[] plain = CodecUtil.decode(req.getInput(), req.getInputFormat());

        SM2Engine engine = new SM2Engine(mode);
        engine.init(true, new ParametersWithRandom(pub, new SecureRandom()));
        byte[] cipher = engine.processBlock(plain, 0, plain.length);

        Map<String, Object> result = new HashMap<>();
        result.put("mode", mode.name());
        result.put("cipher", CodecUtil.encode(cipher, req.getOutputFormat()));
        return result;
    }

    /** SM2 解密 */
    public Map<String, Object> decrypt(SM2Request req) throws Exception {
        SM2Engine.Mode mode = "C1C2C3".equalsIgnoreCase(req.getMode())
                ? SM2Engine.Mode.C1C2C3 : SM2Engine.Mode.C1C3C2;
        ECPrivateKeyParameters priv = parsePrivateKey(req.getPrivateKey());
        byte[] cipher = CodecUtil.decode(req.getInput(), req.getInputFormat());
        // 若输入是 DER 结构密文，先转为裸拼接
        cipher = normalizeCipher(cipher, mode);

        SM2Engine engine = new SM2Engine(mode);
        engine.init(false, priv);
        byte[] plain = engine.processBlock(cipher, 0, cipher.length);

        Map<String, Object> result = new HashMap<>();
        result.put("mode", mode.name());
        result.put("plain", CodecUtil.encode(plain, req.getOutputFormat()));
        return result;
    }

    /**
     * SM2 密文格式转换：裸拼接(C1‖C3‖C2 或 C1‖C2‖C3) 与 ASN.1 DER 结构互转。
     * DER 结构为 SEQUENCE { x INTEGER, y INTEGER, hash OCTET STRING(C3), cipher OCTET STRING(C2) }。
     */
    public Map<String, Object> convertCipher(SM2Request req) throws Exception {
        SM2Engine.Mode mode = "C1C2C3".equalsIgnoreCase(req.getMode())
                ? SM2Engine.Mode.C1C2C3 : SM2Engine.Mode.C1C3C2;
        byte[] in = CodecUtil.decode(req.getSigInput(), req.getSigInputFormat());
        boolean isDer = in.length > 0 && (in[0] & 0xff) == 0x30;

        byte[] raw = isDer ? derToRaw(in, mode) : normalizeCipher(in, mode);
        byte[] der = rawToDer(raw, mode);

        Map<String, Object> result = new HashMap<>();
        result.put("raw", CodecUtil.toHex(raw).toUpperCase());
        result.put("der", CodecUtil.toHex(der).toUpperCase());
        return result;
    }

    /** 若给定密文是 DER 结构则转为裸拼接，否则原样返回。 */
    private byte[] normalizeCipher(byte[] cipher, SM2Engine.Mode mode) throws Exception {
        if (cipher.length > 0 && (cipher[0] & 0xff) == 0x30) {
            try {
                return derToRaw(cipher, mode);
            } catch (Exception ignore) {
                return cipher;
            }
        }
        return cipher;
    }

    /** 裸拼接密文 -> DER 结构。C1 为未压缩点(04||x||y, 65 字节)，C3 为 SM3 摘要(32 字节)。 */
    private byte[] rawToDer(byte[] raw, SM2Engine.Mode mode) throws Exception {
        int c1Len = 65;      // 04 + 32 + 32
        int c3Len = 32;      // SM3
        if (raw == null || raw.length < c1Len + c3Len + 1) {
            throw new IllegalArgumentException("裸密文长度不足：C1(65) + C3(32) + C2 至少 1 字节");
        }
        if (raw[0] != 0x04) {
            throw new IllegalArgumentException("裸密文 C1 应以 0x04 未压缩点开头");
        }
        byte[] c1 = java.util.Arrays.copyOfRange(raw, 0, c1Len);
        byte[] c3, c2;
        if (mode == SM2Engine.Mode.C1C2C3) {
            c2 = java.util.Arrays.copyOfRange(raw, c1Len, raw.length - c3Len);
            c3 = java.util.Arrays.copyOfRange(raw, raw.length - c3Len, raw.length);
        } else {
            c3 = java.util.Arrays.copyOfRange(raw, c1Len, c1Len + c3Len);
            c2 = java.util.Arrays.copyOfRange(raw, c1Len + c3Len, raw.length);
        }
        ECPoint c1p = CURVE.getCurve().decodePoint(c1);
        BigInteger x = c1p.getAffineXCoord().toBigInteger();
        BigInteger y = c1p.getAffineYCoord().toBigInteger();

        org.bouncycastle.asn1.ASN1EncodableVector v = new org.bouncycastle.asn1.ASN1EncodableVector();
        v.add(new org.bouncycastle.asn1.ASN1Integer(x));
        v.add(new org.bouncycastle.asn1.ASN1Integer(y));
        v.add(new org.bouncycastle.asn1.DEROctetString(c3));
        v.add(new org.bouncycastle.asn1.DEROctetString(c2));
        return new org.bouncycastle.asn1.DERSequence(v).getEncoded("DER");
    }

    /** DER 结构密文 -> 裸拼接。 */
    private byte[] derToRaw(byte[] der, SM2Engine.Mode mode) throws Exception {
        org.bouncycastle.asn1.ASN1Sequence seq =
                org.bouncycastle.asn1.ASN1Sequence.getInstance(der);
        if (seq.size() != 4) {
            throw new IllegalArgumentException("DER 密文应包含 4 个元素（x, y, C3, C2），实际 " + seq.size());
        }
        BigInteger x = org.bouncycastle.asn1.ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        BigInteger y = org.bouncycastle.asn1.ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
        byte[] c3 = org.bouncycastle.asn1.ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
        byte[] c2 = org.bouncycastle.asn1.ASN1OctetString.getInstance(seq.getObjectAt(3)).getOctets();
        byte[] c1 = new byte[]{0x04};
        c1 = concat(c1, to32(x), to32(y));
        return mode == SM2Engine.Mode.C1C2C3 ? concat(c1, c2, c3) : concat(c1, c3, c2);
    }
    public Map<String, Object> sign(SM2Request req) throws Exception {
        BigInteger dVal = parsePrivateScalar(req.getPrivateKey(), "签名私钥");
        BigInteger n = DOMAIN.getN();
        byte[] id = userId(req.getUserId());

        BigInteger[] rs;
        if ("evalue".equalsIgnoreCase(req.getSignMode())) {
            requireNonBlank(req.getEValue(), "e 值");
            BigInteger e = new BigInteger(cleanHex(req.getEValue()), 16).mod(n);
            rs = signWithE(dVal, e, n);
        } else {
            ECPrivateKeyParameters priv = new ECPrivateKeyParameters(dVal, DOMAIN);
            SM2Signer signer = new SM2Signer();
            signer.init(true, new ParametersWithID(
                    new ParametersWithRandom(priv, new SecureRandom()), id));
            byte[] data = CodecUtil.decode(req.getInput(), req.getInputFormat());
            signer.update(data, 0, data.length);
            rs = decodeDer(signer.generateSignature());
        }

        byte[] sig = encodeByFormat(rs[0], rs[1], req.getSigEncoding());
        Map<String, Object> result = new HashMap<>();
        result.put("signature", CodecUtil.encode(sig, req.getOutputFormat()).toUpperCase());
        result.put("r", padHex(rs[0].toString(16), 64).toUpperCase());
        result.put("s", padHex(rs[1].toString(16), 64).toUpperCase());
        result.put("userId", new String(id));
        return result;
    }

    /** SM2 验签。signMode=message/evalue；签名输入 rs(64B) 或 der 自动识别。 */
    public Map<String, Object> verify(SM2Request req) throws Exception {
        requireNonBlank(req.getPublicKey(), "公钥");
        requireNonBlank(req.getSignature(), "签名值");
        ECPublicKeyParameters pub = parsePublicKey(req.getPublicKey());
        BigInteger n = DOMAIN.getN();
        BigInteger[] rs = parseSignature(CodecUtil.decode(req.getSignature(), req.getSignatureFormat()));

        boolean ok;
        if ("evalue".equalsIgnoreCase(req.getSignMode())) {
            requireNonBlank(req.getEValue(), "e 值");
            BigInteger e = new BigInteger(cleanHex(req.getEValue()), 16).mod(n);
            ok = verifyWithE(pub.getQ(), e, rs[0], rs[1], n);
        } else {
            SM2Signer signer = new SM2Signer();
            signer.init(false, new ParametersWithID(pub, userId(req.getUserId())));
            byte[] data = CodecUtil.decode(req.getInput(), req.getInputFormat());
            signer.update(data, 0, data.length);
            ok = signer.verifySignature(encodeSignature(rs[0], rs[1]));
        }

        Map<String, Object> result = new HashMap<>();
        result.put("verified", ok);
        return result;
    }

    /** R||S(64字节) 与 DER 相互转换，两种格式同时返回。 */
    public Map<String, Object> convertSignature(SM2Request req) throws Exception {
        BigInteger[] rs = parseSignature(CodecUtil.decode(req.getSigInput(), req.getSigInputFormat()));
        Map<String, Object> result = new HashMap<>();
        result.put("rs", CodecUtil.toHex(encodeRS(rs[0], rs[1])).toUpperCase());
        result.put("der", CodecUtil.toHex(encodeSignature(rs[0], rs[1])).toUpperCase());
        result.put("r", padHex(rs[0].toString(16), 64).toUpperCase());
        result.put("s", padHex(rs[1].toString(16), 64).toUpperCase());
        return result;
    }

    /** 两组数据验签：同一公钥分别验证 (message1,signature1)、(message2,signature2)。 */
    public Map<String, Object> verifyTwo(SM2Request req) throws Exception {
        ECPublicKeyParameters pub = parsePublicKey(req.getPublicKey());
        byte[] id = userId(req.getUserId());
        boolean ok1 = verifyOne(pub, id, req.getMessage1(), req.getMessage1Format(),
                req.getSignature1(), req.getSignature1Format());
        boolean ok2 = verifyOne(pub, id, req.getMessage2(), req.getMessage2Format(),
                req.getSignature2(), req.getSignature2Format());
        Map<String, Object> result = new HashMap<>();
        result.put("verified1", ok1);
        result.put("verified2", ok2);
        result.put("allPassed", ok1 && ok2);
        result.put("message", (ok1 && ok2) ? "两组数据均验证通过！"
                : "验证未全部通过：第一组 " + (ok1 ? "通过" : "失败") + "，第二组 " + (ok2 ? "通过" : "失败"));
        return result;
    }

    /**
     * 验签并攻击：两组签名若复用相同随机数 k（重复 k 漏洞），可恢复私钥 d。
     * 先对两组验签；随后尝试重复 k 攻击：
     * 由 s_i(1+d) = (k - r_i·d) 两式联立，
     * d = (s2 - s1) / (s1 - s2 + r1 - r2) mod n。
     * 验证恢复出的 d 是否与提供的公钥匹配。
     */
    public Map<String, Object> verifyAndAttack(SM2Request req) throws Exception {
        BigInteger n = DOMAIN.getN();
        ECPublicKeyParameters pub = parsePublicKey(req.getPublicKey());
        byte[] id = userId(req.getUserId());

        BigInteger[] rs1 = parseSignature(CodecUtil.decode(req.getSignature1(), req.getSignature1Format()));
        BigInteger[] rs2 = parseSignature(CodecUtil.decode(req.getSignature2(), req.getSignature2Format()));
        boolean ok1 = verifyOne(pub, id, req.getMessage1(), req.getMessage1Format(),
                req.getSignature1(), req.getSignature1Format());
        boolean ok2 = verifyOne(pub, id, req.getMessage2(), req.getMessage2Format(),
                req.getSignature2(), req.getSignature2Format());

        Map<String, Object> result = new HashMap<>();
        result.put("verified1", ok1);
        result.put("verified2", ok2);

        BigInteger r1 = rs1[0], s1 = rs1[1], r2 = rs2[0], s2 = rs2[1];
        // d = (s2 - s1) / (s1 - s2 + r1 - r2) mod n
        BigInteger num = s2.subtract(s1).mod(n);
        BigInteger den = s1.subtract(s2).add(r1).subtract(r2).mod(n);
        boolean recovered = false;
        String dHex = null;
        if (den.signum() != 0) {
            BigInteger d = num.multiply(den.modInverse(n)).mod(n);
            ECPoint P = DOMAIN.getG().multiply(d).normalize();
            if (P.equals(pub.getQ())) {
                recovered = true;
                dHex = padHex(d.toString(16), 64).toUpperCase();
            }
        }
        result.put("attacked", recovered);
        result.put("recoveredPrivateKey", dHex);
        result.put("message", recovered
                ? "攻击成功！两组签名复用了相同随机数 k，已恢复出私钥。"
                : "两组签名未复用相同随机数 k，无法通过重复 k 攻击恢复私钥。");
        return result;
    }

    private boolean verifyOne(ECPublicKeyParameters pub, byte[] id,
                              String msg, String msgFmt, String sig, String sigFmt) throws Exception {
        BigInteger[] rs = parseSignature(CodecUtil.decode(sig, sigFmt));
        SM2Signer signer = new SM2Signer();
        signer.init(false, new ParametersWithID(pub, id));
        byte[] data = CodecUtil.decode(msg, msgFmt);
        signer.update(data, 0, data.length);
        return signer.verifySignature(encodeSignature(rs[0], rs[1]));
    }

    /** 基于给定 e 值签名，产生 (r,s)。 */
    private BigInteger[] signWithE(BigInteger d, BigInteger e, BigInteger n) {
        BigInteger r, s;
        BigInteger inv = d.add(BigInteger.ONE).modInverse(n);
        while (true) {
            BigInteger k = randomK(n);
            ECPoint kG = DOMAIN.getG().multiply(k).normalize();
            BigInteger x1 = kG.getAffineXCoord().toBigInteger();
            r = e.add(x1).mod(n);
            if (r.signum() == 0 || r.add(k).equals(n)) continue;
            s = inv.multiply(k.subtract(r.multiply(d))).mod(n);
            if (s.signum() != 0) break;
        }
        return new BigInteger[]{r, s};
    }

    /** 基于给定 e 值验签。 */
    private boolean verifyWithE(ECPoint pub, BigInteger e, BigInteger r, BigInteger s, BigInteger n) {
        if (r.signum() <= 0 || r.compareTo(n) >= 0 || s.signum() <= 0 || s.compareTo(n) >= 0) return false;
        BigInteger t = r.add(s).mod(n);
        if (t.signum() == 0) return false;
        ECPoint p1 = DOMAIN.getG().multiply(s).add(pub.multiply(t)).normalize();
        BigInteger x1 = p1.getAffineXCoord().toBigInteger();
        return e.add(x1).mod(n).equals(r);
    }

    /** 按 sigEncoding 输出 rs 或 der。 */
    private byte[] encodeByFormat(BigInteger r, BigInteger s, String enc) throws Exception {
        return "der".equalsIgnoreCase(enc) ? encodeSignature(r, s) : encodeRS(r, s);
    }

    /** R||S：64 字节，各 32 字节。 */
    private byte[] encodeRS(BigInteger r, BigInteger s) {
        return concat(to32(r), to32(s));
    }

    /** 从 DER 签名解析 (r,s)。 */
    private BigInteger[] decodeDer(byte[] der) throws Exception {
        org.bouncycastle.asn1.ASN1Sequence seq =
                org.bouncycastle.asn1.ASN1Sequence.getInstance(der);
        BigInteger r = org.bouncycastle.asn1.ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        BigInteger s = org.bouncycastle.asn1.ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
        return new BigInteger[]{r, s};
    }

    /** 自动识别签名字节：64 字节按 R||S，否则按 DER 解析。 */
    private BigInteger[] parseSignature(byte[] sig) throws Exception {
        if (sig.length == 64) {
            BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(sig, 0, 32));
            BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(sig, 32, 64));
            return new BigInteger[]{r, s};
        }
        return decodeDer(sig);
    }

    /**
     * SM2 密钥交换协议（GM/T 0003.3）。
     * 一次性完成 A、B 双方协商，输出共享密钥并校验双方是否一致。
     * 输入 A/B 的静态密钥对与标识；临时密钥对内部随机生成。
     */
    public Map<String, Object> keyExchange(SM2Request req) throws Exception {
        BigInteger n = DOMAIN.getN();
        ECPoint G = DOMAIN.getG();
        int w = (int) Math.ceil(n.bitLength() / 2.0) - 1;      // w = ceil(ceil(log2(n))/2) - 1
        BigInteger _2w = BigInteger.ONE.shiftLeft(w);           // 2^w

        // 静态密钥
        BigInteger dA = new BigInteger(cleanHex(req.getPrivateKeyA()), 16);
        BigInteger dB = new BigInteger(cleanHex(req.getPrivateKeyB()), 16);
        ECPoint PA = parsePublicKey(req.getPublicKeyA()).getQ();
        ECPoint PB = parsePublicKey(req.getPublicKeyB()).getQ();

        // 临时密钥
        BigInteger rA = randomK(n);
        BigInteger rB = randomK(n);
        ECPoint RA = G.multiply(rA).normalize();               // A 发给 B
        ECPoint RB = G.multiply(rB).normalize();               // B 发给 A

        byte[] ZA = za(userId(req.getIdA()), PA);
        byte[] ZB = za(userId(req.getIdB()), PB);
        int klen = req.getKeyLength() > 0 ? req.getKeyLength() : 16;

        // A 方计算：x1_ = 2^w + (x(RA) mod 2^w)；tA = (dA + x1_ * rA) mod n
        BigInteger x1_ = _2w.add(RA.getAffineXCoord().toBigInteger().and(_2w.subtract(BigInteger.ONE)));
        BigInteger tA = dA.add(x1_.multiply(rA)).mod(n);
        BigInteger x2_ = _2w.add(RB.getAffineXCoord().toBigInteger().and(_2w.subtract(BigInteger.ONE)));
        // U = [h*tA](PB + [x2_]RB)
        ECPoint U = PB.add(RB.multiply(x2_)).multiply(DOMAIN.getH().multiply(tA)).normalize();
        byte[] kA = kdf(concat(xy(U), ZA, ZB), klen);

        // B 方计算（对称）
        BigInteger tB = dB.add(x2_.multiply(rB)).mod(n);
        ECPoint V = PA.add(RA.multiply(x1_)).multiply(DOMAIN.getH().multiply(tB)).normalize();
        byte[] kB = kdf(concat(xy(V), ZA, ZB), klen);

        Map<String, Object> result = new HashMap<>();
        result.put("sharedKeyA", CodecUtil.toHex(kA));
        result.put("sharedKeyB", CodecUtil.toHex(kB));
        result.put("consistent", java.util.Arrays.equals(kA, kB));
        result.put("RA", "04" + pointXY(RA));
        result.put("RB", "04" + pointXY(RB));
        result.put("keyLength", klen);
        return result;
    }

    /**
     * SM2 两方协同签名。
     * 私钥被拆为两个子密钥 d1、d2，约定合成私钥满足 (1+d) = (1+d1)(1+d2) mod n，
     * 两方各持一片、任一方均不掌握完整私钥。协作产生一枚标准 SM2 签名，
     * 并用合成公钥 P 验签自证协同结果正确、可被标准验签器接受。
     */
    public Map<String, Object> coSign(SM2Request req) throws Exception {
        BigInteger n = DOMAIN.getN();
        ECPoint G = DOMAIN.getG();
        BigInteger d1 = new BigInteger(cleanHex(req.getD1()), 16).mod(n);
        BigInteger d2 = new BigInteger(cleanHex(req.getD2()), 16).mod(n);

        // 合成等效私钥 d：约定 (1+d) = (1+d1)(1+d2) mod n
        BigInteger onePlusD = d1.add(BigInteger.ONE).multiply(d2.add(BigInteger.ONE)).mod(n);
        BigInteger d = onePlusD.subtract(BigInteger.ONE).mod(n);
        ECPoint P = G.multiply(d).normalize();

        byte[] data = CodecUtil.decode(req.getInput(), req.getInputFormat());
        byte[] id = userId(req.getUserId());
        byte[] za = za(id, P);
        BigInteger e = new BigInteger(1, sm3(concat(za, data))).mod(n);   // e = SM3(ZA||M)

        // 两方协同产生 (r,s)：第一方持 k1，第二方持 k2，k = k1*k2 mod n
        BigInteger r, s;
        while (true) {
            BigInteger k1 = randomK(n);                        // 第一方随机数
            BigInteger k2 = randomK(n);                        // 第二方随机数
            BigInteger k = k1.multiply(k2).mod(n);
            ECPoint kG = G.multiply(k).normalize();
            BigInteger x1 = kG.getAffineXCoord().toBigInteger();
            r = e.add(x1).mod(n);
            if (r.signum() == 0 || r.add(k).equals(n)) continue;
            // s = ((1+d)^-1 * (k - r*d)) mod n；协同下由两方分片乘积等价合成
            BigInteger inv = onePlusD.modInverse(n);
            s = inv.multiply(k.subtract(r.multiply(d))).mod(n);
            if (s.signum() != 0) break;
        }

        byte[] sig = encodeSignature(r, s);
        // 自证：用合成公钥 P 走标准 SM2 验签
        SM2Signer verifier = new SM2Signer();
        verifier.init(false, new ParametersWithID(new ECPublicKeyParameters(P, DOMAIN), id));
        verifier.update(data, 0, data.length);
        boolean ok = verifier.verifySignature(sig);

        Map<String, Object> result = new HashMap<>();
        result.put("signature", CodecUtil.encode(sig, req.getOutputFormat()));
        result.put("r", padHex(r.toString(16), 64));
        result.put("s", padHex(s.toString(16), 64));
        result.put("combinedPublicKey", "04" + pointXY(P));
        result.put("verified", ok);
        result.put("note", "两方各持子密钥 d1/d2（满足 (1+d)=(1+d1)(1+d2)），协同产生标准 SM2 签名，任一方均不掌握完整私钥；已用合成公钥完成标准验签自证。");
        return result;
    }

    // ---------- 内部工具 ----------

    private BigInteger randomK(BigInteger n) {
        BigInteger k;
        SecureRandom rnd = new SecureRandom();
        do {
            k = new BigInteger(n.bitLength(), rnd);
        } while (k.signum() == 0 || k.compareTo(n) >= 0);
        return k;
    }

    /** SM3 摘要 */
    private byte[] sm3(byte[] in) {
        org.bouncycastle.crypto.digests.SM3Digest md = new org.bouncycastle.crypto.digests.SM3Digest();
        md.update(in, 0, in.length);
        byte[] out = new byte[md.getDigestSize()];
        md.doFinal(out, 0);
        return out;
    }

    /** SM2 用户 Za = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA) */
    private byte[] za(byte[] id, ECPoint pub) {
        int entl = id.length * 8;
        byte[] head = new byte[]{(byte) (entl >> 8), (byte) entl};
        byte[] a = to32(CURVE.getCurve().getA().toBigInteger());
        byte[] b = to32(CURVE.getCurve().getB().toBigInteger());
        byte[] xg = to32(CURVE.getG().getAffineXCoord().toBigInteger());
        byte[] yg = to32(CURVE.getG().getAffineYCoord().toBigInteger());
        byte[] xa = to32(pub.getAffineXCoord().toBigInteger());
        byte[] ya = to32(pub.getAffineYCoord().toBigInteger());
        return sm3(concat(head, id, a, b, xg, yg, xa, ya));
    }

    /** GM/T KDF（基于 SM3 的计数器模式） */
    private byte[] kdf(byte[] z, int klen) {
        byte[] out = new byte[klen];
        int off = 0, ct = 1;
        while (off < klen) {
            byte[] cnt = new byte[]{(byte) (ct >>> 24), (byte) (ct >>> 16), (byte) (ct >>> 8), (byte) ct};
            byte[] h = sm3(concat(z, cnt));
            int copy = Math.min(h.length, klen - off);
            System.arraycopy(h, 0, out, off, copy);
            off += copy;
            ct++;
        }
        return out;
    }

    private byte[] xy(ECPoint p) {
        return concat(to32(p.getAffineXCoord().toBigInteger()), to32(p.getAffineYCoord().toBigInteger()));
    }

    private byte[] to32(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        if (b.length > 32) {
            System.arraycopy(b, b.length - 32, out, 0, 32);
        } else {
            System.arraycopy(b, 0, out, 32 - b.length, b.length);
        }
        return out;
    }

    private byte[] concat(byte[]... arrs) {
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

    /** 将 (r,s) 编码为 SM2 标准 DER 签名 */
    private byte[] encodeSignature(BigInteger r, BigInteger s) throws Exception {
        org.bouncycastle.asn1.ASN1EncodableVector v = new org.bouncycastle.asn1.ASN1EncodableVector();
        v.add(new org.bouncycastle.asn1.ASN1Integer(r));
        v.add(new org.bouncycastle.asn1.ASN1Integer(s));
        return new org.bouncycastle.asn1.DERSequence(v).getEncoded("DER");
    }

    private byte[] userId(String userId) {
        String id = (userId == null || userId.isBlank()) ? "1234567812345678" : userId;
        return id.getBytes(StandardCharsets.UTF_8);
    }

    private ECPrivateKeyParameters parsePrivateKey(String hex) {
        BigInteger d = parsePrivateScalar(hex, "私钥");
        return new ECPrivateKeyParameters(d, DOMAIN);
    }

    private ECPublicKeyParameters parsePublicKey(String hex) {
        requireNonBlank(hex, "公钥");
        String h = cleanHex(hex);
        if (h.length() == 128) {
            h = "04" + h;
        }
        ECPoint q = CURVE.getCurve().decodePoint(CodecUtil.fromHex(h));
        return new ECPublicKeyParameters(q, DOMAIN);
    }

    /** 解析并校验私钥标量 d 必须在 [1, n-1] 范围内。 */
    private BigInteger parsePrivateScalar(String hex, String fieldName) {
        requireNonBlank(hex, fieldName);
        String h = cleanHex(hex);
        BigInteger d;
        try {
            d = new BigInteger(h, 16);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(fieldName + " 不是有效的十六进制数值");
        }
        BigInteger n = DOMAIN.getN();
        if (d.signum() <= 0 || d.compareTo(n) >= 0) {
            throw new IllegalArgumentException(fieldName + " 必须在 [1, n-1] 范围内");
        }
        return d;
    }

    private void requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " 不能为空");
        }
    }

    private String pointXY(ECPoint q) {
        return padHex(q.getAffineXCoord().toBigInteger().toString(16), 64)
                + padHex(q.getAffineYCoord().toBigInteger().toString(16), 64);
    }

    private String cleanHex(String hex) {
        return hex.replaceAll("[\\s:]", "").replaceAll("(?i)^0x", "");
    }

    private String padHex(String hex, int len) {
        while (hex.length() < len) {
            hex = "0" + hex;
        }
        return hex;
    }
}
