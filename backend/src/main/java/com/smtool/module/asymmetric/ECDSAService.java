package com.smtool.module.asymmetric;

import com.smtool.util.CodecUtil;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

@Service
public class ECDSAService {

    public Map<String, Object> generateKeyPair(ECDSARequest req) throws Exception {
        String curve = curveOf(req == null ? null : req.getCurve());

        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec(curve), new SecureRandom());
        KeyPair kp = gen.generateKeyPair();

        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        ECPoint q = pub.getQ();
        String pointHex = CodecUtil.toHex(q.getEncoded(false));

        Map<String, Object> result = new HashMap<>();
        result.put("curve", curve);
        result.put("publicKey", toPem(kp.getPublic()));
        result.put("privateKey", toPem(kp.getPrivate()));
        result.put("publicKeyHex", CodecUtil.encode(kp.getPublic().getEncoded(), "hex"));
        result.put("privateKeyHex", CodecUtil.encode(kp.getPrivate().getEncoded(), "hex"));
        result.put("publicKeyPoint", pointHex);
        return result;
    }

    public Map<String, Object> sign(ECDSARequest req) throws Exception {
        PrivateKey priv = parsePrivateKey(req.getPrivateKey(), req.getPrivateKeyFormat());
        String algo = signAlgorithmOf(req.getHash());

        Signature signature = Signature.getInstance(algo, "BC");
        signature.initSign(priv);
        signature.update(CodecUtil.decode(req.getInput(), req.getInputFormat()));
        byte[] sig = signature.sign();

        Map<String, Object> result = new HashMap<>();
        result.put("algorithm", algo);
        result.put("signature", CodecUtil.encode(sig, req.getOutputFormat()));
        return result;
    }

    public Map<String, Object> verify(ECDSARequest req) throws Exception {
        PublicKey pub = parsePublicKey(req.getPublicKey(), req.getPublicKeyFormat());
        String algo = signAlgorithmOf(req.getHash());

        Signature signature = Signature.getInstance(algo, "BC");
        signature.initVerify(pub);
        signature.update(CodecUtil.decode(req.getInput(), req.getInputFormat()));
        byte[] sig = CodecUtil.decode(req.getSignature(), req.getSignatureFormat());
        boolean ok = signature.verify(sig);

        Map<String, Object> result = new HashMap<>();
        result.put("algorithm", algo);
        result.put("verified", ok);
        return result;
    }

    public Map<String, Object> encrypt(ECDSARequest req) throws Exception {
        PublicKey pub = parsePublicKey(req.getPublicKey(), req.getPublicKeyFormat());
        String curve = curveOf(req.getCurve());

        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec(curve), new SecureRandom());
        KeyPair ephemKp = gen.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(ephemKp.getPrivate());
        ka.doPhase(pub, true);
        byte[] shared = ka.generateSecret();

        MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
        byte[] key = md.digest(shared);

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, 0, 16, "AES"));
        byte[] plain = CodecUtil.decode(req.getInput(), req.getInputFormat());
        byte[] cipherData = cipher.doFinal(plain);

        byte[] ephemPub = ephemKp.getPublic().getEncoded();
        byte[] result = new byte[ephemPub.length + cipherData.length];
        System.arraycopy(ephemPub, 0, result, 0, ephemPub.length);
        System.arraycopy(cipherData, 0, result, ephemPub.length, cipherData.length);

        Map<String, Object> r = new HashMap<>();
        r.put("curve", curve);
        r.put("cipher", CodecUtil.encode(result, req.getOutputFormat()));
        return r;
    }

    public Map<String, Object> decrypt(ECDSARequest req) throws Exception {
        PrivateKey priv = parsePrivateKey(req.getPrivateKey(), req.getPrivateKeyFormat());
        byte[] all = CodecUtil.decode(req.getInput(), req.getInputFormat());

        int pubKeyLen;
        String curve = curveOf(req.getCurve());
        switch (curve) {
            case "secp256k1":
            case "secp256r1": pubKeyLen = 91; break;
            case "secp384r1": pubKeyLen = 120; break;
            case "secp521r1": pubKeyLen = 158; break;
            default: pubKeyLen = 91;
        }

        byte[] ephemPubBytes = new byte[pubKeyLen];
        byte[] cipherData = new byte[all.length - pubKeyLen];
        System.arraycopy(all, 0, ephemPubBytes, 0, pubKeyLen);
        System.arraycopy(all, pubKeyLen, cipherData, 0, cipherData.length);

        PublicKey ephemPub = KeyFactory.getInstance("EC", "BC")
                .generatePublic(new X509EncodedKeySpec(ephemPubBytes));

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(priv);
        ka.doPhase(ephemPub, true);
        byte[] shared = ka.generateSecret();

        MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
        byte[] key = md.digest(shared);

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, 0, 16, "AES"));
        byte[] plain = cipher.doFinal(cipherData);

        Map<String, Object> r = new HashMap<>();
        r.put("curve", curve);
        r.put("plain", CodecUtil.encode(plain, req.getOutputFormat()));
        return r;
    }

    private String curveOf(String curve) {
        String c = (curve == null || curve.isBlank()) ? "secp256r1" : curve.trim();
        String lower = c.toLowerCase();
        if (lower.contains("secp256k1")) return "secp256k1";
        if (lower.contains("secp256r1") || lower.contains("p-256") || lower.contains("p256") || lower.contains("prime256v1")) return "secp256r1";
        if (lower.contains("secp384r1") || lower.contains("p-384") || lower.contains("p384")) return "secp384r1";
        if (lower.contains("secp521r1") || lower.contains("p-521") || lower.contains("p521")) return "secp521r1";
        return "secp256r1";
    }

    private String signAlgorithmOf(String hash) {
        String h = (hash == null || hash.isBlank()) ? "SHA256" : hash.trim().toUpperCase();
        if (h.contains("SHA1") || h.contains("SHA-1")) return "SHA1withECDSA";
        if (h.contains("SHA256") || h.contains("SHA-256")) return "SHA256withECDSA";
        if (h.contains("SHA384") || h.contains("SHA-384")) return "SHA384withECDSA";
        if (h.contains("SHA512") || h.contains("SHA-512")) return "SHA512withECDSA";
        return "SHA256withECDSA";
    }

    private String toPem(Object key) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(key);
        }
        return sw.toString();
    }

    private PublicKey parsePublicKey(String key, String format) throws Exception {
        if (key == null || key.isBlank()) throw new IllegalArgumentException("公钥不能为空");
        String f = (format == null) ? "pem" : format.trim().toLowerCase();
        byte[] der;
        if ("hex".equals(f)) {
            der = CodecUtil.decode(key, "hex");
        } else if ("base64".equals(f)) {
            der = CodecUtil.decode(key, "base64");
        } else {
            if (key.contains("-----BEGIN")) {
                try (PEMParser parser = new PEMParser(new StringReader(key))) {
                    Object obj = parser.readObject();
                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                    if (obj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki) {
                        return converter.getPublicKey(spki);
                    }
                    if (obj instanceof org.bouncycastle.openssl.PEMKeyPair kp) {
                        return converter.getPublicKey(kp.getPublicKeyInfo());
                    }
                }
                der = CodecUtil.decode(stripPem(key), "base64");
            } else {
                der = CodecUtil.decode(key, "base64");
            }
        }
        return KeyFactory.getInstance("EC", "BC")
                .generatePublic(new X509EncodedKeySpec(der));
    }

    private PrivateKey parsePrivateKey(String key, String format) throws Exception {
        if (key == null || key.isBlank()) throw new IllegalArgumentException("私钥不能为空");
        String f = (format == null) ? "pem" : format.trim().toLowerCase();
        byte[] der;
        if ("hex".equals(f)) {
            der = CodecUtil.decode(key, "hex");
        } else if ("base64".equals(f)) {
            der = CodecUtil.decode(key, "base64");
        } else {
            if (key.contains("-----BEGIN")) {
                try (PEMParser parser = new PEMParser(new StringReader(key))) {
                    Object obj = parser.readObject();
                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                    if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki) {
                        return converter.getPrivateKey(pki);
                    }
                    if (obj instanceof org.bouncycastle.openssl.PEMKeyPair kp) {
                        return converter.getPrivateKey(kp.getPrivateKeyInfo());
                    }
                }
                der = CodecUtil.decode(stripPem(key), "base64");
            } else {
                der = CodecUtil.decode(key, "base64");
            }
        }
        return KeyFactory.getInstance("EC", "BC")
                .generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private String stripPem(String pem) {
        return pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
    }
}
