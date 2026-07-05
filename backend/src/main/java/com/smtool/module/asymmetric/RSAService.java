package com.smtool.module.asymmetric;

import com.smtool.util.CodecUtil;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.PEMParser;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

@Service
public class RSAService {

    public Map<String, Object> generateKeyPair(RSARequest req) throws Exception {
        int keySize = (req == null || req.getKeySize() == null) ? 2048 : req.getKeySize();

        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
        gen.initialize(keySize, new SecureRandom());
        KeyPair kp = gen.generateKeyPair();

        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        RSAPrivateCrtKey priv = (RSAPrivateCrtKey) kp.getPrivate();

        Map<String, Object> result = new HashMap<>();
        result.put("keySize", keySize);
        result.put("publicKey", toPem(pub));
        result.put("privateKey", toPem(priv));
        result.put("publicKeyHex", CodecUtil.encode(pub.getEncoded(), "hex"));
        result.put("privateKeyHex", CodecUtil.encode(priv.getEncoded(), "hex"));
        result.put("modulus", pub.getModulus().toString(16));
        result.put("publicExponent", pub.getPublicExponent().toString(16));
        return result;
    }

    public Map<String, Object> encrypt(RSARequest req) throws Exception {
        PublicKey pub = parsePublicKey(req.getPublicKey(), req.getPublicKeyFormat());
        String transformation = transformationOf(req.getPadding());
        Cipher cipher = Cipher.getInstance(transformation, "BC");
        if (transformation.contains("OAEP")) {
            cipher.init(Cipher.ENCRYPT_MODE, pub, oaepParams(req.getPadding()));
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, pub);
        }

        byte[] plain = CodecUtil.decode(req.getInput(), req.getInputFormat());
        byte[] out = cipher.doFinal(plain);

        Map<String, Object> result = new HashMap<>();
        result.put("padding", req.getPadding());
        result.put("cipher", CodecUtil.encode(out, req.getOutputFormat()));
        return result;
    }

    public Map<String, Object> decrypt(RSARequest req) throws Exception {
        PrivateKey priv = parsePrivateKey(req.getPrivateKey(), req.getPrivateKeyFormat());
        String transformation = transformationOf(req.getPadding());
        Cipher cipher = Cipher.getInstance(transformation, "BC");
        if (transformation.contains("OAEP")) {
            cipher.init(Cipher.DECRYPT_MODE, priv, oaepParams(req.getPadding()));
        } else {
            cipher.init(Cipher.DECRYPT_MODE, priv);
        }

        byte[] input = CodecUtil.decode(req.getInput(), req.getInputFormat());
        byte[] out = cipher.doFinal(input);

        Map<String, Object> result = new HashMap<>();
        result.put("padding", req.getPadding());
        result.put("plain", CodecUtil.encode(out, req.getOutputFormat()));
        return result;
    }

    public Map<String, Object> sign(RSARequest req) throws Exception {
        PrivateKey priv = parsePrivateKey(req.getPrivateKey(), req.getPrivateKeyFormat());
        String algo = signAlgorithmOf(req.getAlgorithm());

        Signature signature = Signature.getInstance(algo, "BC");
        signature.initSign(priv);
        signature.update(CodecUtil.decode(req.getInput(), req.getInputFormat()));
        byte[] sig = signature.sign();

        Map<String, Object> result = new HashMap<>();
        result.put("algorithm", algo);
        result.put("signature", CodecUtil.encode(sig, req.getOutputFormat()));
        return result;
    }

    public Map<String, Object> verify(RSARequest req) throws Exception {
        PublicKey pub = parsePublicKey(req.getPublicKey(), req.getPublicKeyFormat());
        String algo = signAlgorithmOf(req.getAlgorithm());

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

    private String transformationOf(String padding) {
        String p = (padding == null || padding.isBlank()) ? "RSA/ECB/PKCS1Padding" : padding.trim();
        if (p.contains("NoPadding")) return "RSA/ECB/NoPadding";
        if (p.contains("PKCS1")) return "RSA/ECB/PKCS1Padding";
        if (p.contains("OAEP")) return "RSA/ECB/OAEPPadding";
        return "RSA/ECB/PKCS1Padding";
    }

    private OAEPParameterSpec oaepParams(String padding) {
        String p = (padding == null) ? "" : padding;
        String hash = "SHA-256";
        if (p.contains("SHA-1") || p.contains("SHA1")) hash = "SHA-1";
        else if (p.contains("SHA-256") || p.contains("SHA256")) hash = "SHA-256";
        else if (p.contains("SHA-384") || p.contains("SHA384")) hash = "SHA-384";
        else if (p.contains("SHA-512") || p.contains("SHA512")) hash = "SHA-512";
        else if (p.contains("MD5")) hash = "MD5";
        MGF1ParameterSpec mgf = new MGF1ParameterSpec(hash);
        return new OAEPParameterSpec(hash, "MGF1", mgf, PSource.PSpecified.DEFAULT);
    }

    private String signAlgorithmOf(String algo) {
        String a = (algo == null || algo.isBlank()) ? "SHA256withRSA" : algo.trim();
        String lower = a.toLowerCase();
        if (lower.contains("md2")) return "MD2withRSA";
        if (lower.contains("md5")) return "MD5withRSA";
        if (lower.contains("sha1") || lower.contains("sha-1")) return "SHA1withRSA";
        if (lower.contains("sha224") || lower.contains("sha-224")) return "SHA224withRSA";
        if (lower.contains("sha256") || lower.contains("sha-256")) return "SHA256withRSA";
        if (lower.contains("sha384") || lower.contains("sha-384")) return "SHA384withRSA";
        if (lower.contains("sha512") || lower.contains("sha-512")) return "SHA512withRSA";
        if (lower.contains("sha3-224")) return "SHA3-224withRSA";
        if (lower.contains("sha3-256")) return "SHA3-256withRSA";
        if (lower.contains("sha3-384")) return "SHA3-384withRSA";
        if (lower.contains("sha3-512")) return "SHA3-512withRSA";
        return "SHA256withRSA";
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
        return KeyFactory.getInstance("RSA", "BC")
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
        return KeyFactory.getInstance("RSA", "BC")
                .generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private String stripPem(String pem) {
        return pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
    }
}
