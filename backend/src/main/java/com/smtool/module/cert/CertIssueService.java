package com.smtool.module.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 证书在线签发服务（本地 CA 模拟）。
 *
 * <p>支持：
 * <ul>
 *   <li>根据主题字段生成 PKCS#10 CSR</li>
 *   <li>直接生成 PFX（同时生成密钥对 + 自签证书并打包为 PFX）</li>
 *   <li>提交 CSR/P10 请求，由本地 CA 签发证书</li>
 * </ul>
 * </p>
 */
@Service
public class CertIssueService {

    static {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** 生成 PKCS#10 CSR。 */
    public Map<String, Object> generateCsr(CsrRequest req) throws Exception {
        boolean isSm2 = "SM2".equalsIgnoreCase(req.getAlgorithm());
        int keySize = resolveRsaKeySize(req.getKeySize(), isSm2);
        KeyPair kp = generateKeyPair(isSm2, keySize);
        X500Name subject = buildSubject(req);
        String sigAlg = isSm2 ? "SM3withSM2" : "SHA256withRSA";

        PKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(kp.getPrivate());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("csr", toPem("CERTIFICATE REQUEST", csr.getEncoded()));
        result.put("privateKey", toPem("PRIVATE KEY", kp.getPrivate().getEncoded()));
        result.put("publicKey", toPem("PUBLIC KEY", kp.getPublic().getEncoded()));
        result.put("algorithm", req.getAlgorithm());
        result.put("subject", subject.toString());
        return result;
    }

    /** 签发证书：支持直接生成 PFX 或根据 CSR 签发。 */
    public Map<String, Object> issue(CertIssueRequest req) throws Exception {
        boolean isSm2 = "SM2".equalsIgnoreCase(req.getAlgorithm());
        String sigAlg = isSm2 ? "SM3withSM2" : "SHA256withRSA";
        int validMonths = req.getValidMonths() == null || req.getValidMonths() <= 0 ? 12 : req.getValidMonths();
        int keySize = resolveRsaKeySize(req.getKeySize(), isSm2);

        X500Name subject;
        PublicKey publicKey;
        PrivateKey subjectPrivateKey;
        PrivateKey signingKey;
        X509Certificate issuerCert;
        X500Name issuer;

        boolean useCsr = "csr".equalsIgnoreCase(req.getIssueMode());
        if (useCsr) {
            if (req.getCsr() == null || req.getCsr().isBlank()) {
                throw new IllegalArgumentException("提交 CSR/P10 模式必须提供 CSR 内容");
            }
            PKCS10CertificationRequest csr = parseCsr(req.getCsr());
            subject = csr.getSubject();
            publicKey = new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter()
                    .setProvider("BC").getPublicKey(csr.getSubjectPublicKeyInfo());
            subjectPrivateKey = null;

            // 使用传入的 CA 证书/私钥签发；未传入则生成临时 CA
            if (req.getIssuerCertPem() != null && !req.getIssuerCertPem().isBlank()
                    && req.getIssuerKeyPem() != null && !req.getIssuerKeyPem().isBlank()) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
                try (ByteArrayInputStream in = new ByteArrayInputStream(DerInputUtil.toDer(req.getIssuerCertPem()))) {
                    issuerCert = (X509Certificate) cf.generateCertificate(in);
                }
                signingKey = DerInputUtil.parsePrivateKey(req.getIssuerKeyPem());
                issuer = new X500Name(issuerCert.getSubjectX500Principal().getName());
            } else {
                KeyPair caKp = generateKeyPair(isSm2, keySize);
                signingKey = caKp.getPrivate();
                issuer = subject;
                issuerCert = null;
            }
        } else {
            // 直接生成模式：生成新密钥对并自签
            KeyPair kp = generateKeyPair(isSm2, keySize);
            publicKey = kp.getPublic();
            subjectPrivateKey = kp.getPrivate();
            signingKey = kp.getPrivate();
            subject = buildSubject(req);
            issuer = subject;
            issuerCert = null;
        }

        BigInteger serial = new BigInteger(64, new SecureRandom());
        Date notBefore = new Date();
        Date notAfter = calculateNotAfter(notBefore, validMonths);

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject,
                SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(signingKey);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certBuilder.build(signer));

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("certificate", toPem("CERTIFICATE", cert.getEncoded()));
        result.put("serialNumber", serial.toString(16));
        result.put("subject", cert.getSubjectX500Principal().getName());
        result.put("issuer", cert.getIssuerX500Principal().getName());
        result.put("notBefore", notBefore.toInstant().toString());
        result.put("notAfter", notAfter.toInstant().toString());
        result.put("signatureAlgorithm", sigAlg);
        result.put("certType", req.getCertType());
        result.put("issueMode", req.getIssueMode());

        if (!useCsr) {
            // 直接生成模式：返回私钥，并可选打包 PFX
            result.put("privateKey", toPem("PRIVATE KEY", subjectPrivateKey.getEncoded()));
            if (req.getPfxPassword() != null && !req.getPfxPassword().isBlank()) {
                byte[] pfx = exportPfx(cert, subjectPrivateKey, req.getPfxPassword());
                result.put("pfxBase64", Base64.getEncoder().encodeToString(pfx));
                result.put("pfxPassword", req.getPfxPassword());
            }
        } else {
            result.put("privateKey", null);
        }
        return result;
    }

    /** 按字段或完整 DN 构建 X500Name */
    private X500Name buildSubject(CertIssueRequest req) {
        if (req.getSubject() != null && !req.getSubject().isBlank()) {
            return new X500Name(req.getSubject());
        }
        X500NameBuilder builder = new X500NameBuilder();
        if (notBlank(req.getCountry())) builder.addRDN(BCStyle.C, req.getCountry());
        if (notBlank(req.getState())) builder.addRDN(BCStyle.ST, req.getState());
        if (notBlank(req.getLocality())) builder.addRDN(BCStyle.L, req.getLocality());
        if (notBlank(req.getOrganization())) builder.addRDN(BCStyle.O, req.getOrganization());
        if (notBlank(req.getOrganizationalUnit())) builder.addRDN(BCStyle.OU, req.getOrganizationalUnit());
        if (notBlank(req.getCommonName())) builder.addRDN(BCStyle.CN, req.getCommonName());
        if (notBlank(req.getEmailAddress())) builder.addRDN(BCStyle.EmailAddress, req.getEmailAddress());
        return builder.build();
    }

    private X500Name buildSubject(CsrRequest req) {
        if (req.getSubject() != null && !req.getSubject().isBlank()) {
            return new X500Name(req.getSubject());
        }
        X500NameBuilder builder = new X500NameBuilder();
        if (notBlank(req.getCountry())) builder.addRDN(BCStyle.C, req.getCountry());
        if (notBlank(req.getState())) builder.addRDN(BCStyle.ST, req.getState());
        if (notBlank(req.getLocality())) builder.addRDN(BCStyle.L, req.getLocality());
        if (notBlank(req.getOrganization())) builder.addRDN(BCStyle.O, req.getOrganization());
        if (notBlank(req.getOrganizationalUnit())) builder.addRDN(BCStyle.OU, req.getOrganizationalUnit());
        if (notBlank(req.getCommonName())) builder.addRDN(BCStyle.CN, req.getCommonName());
        if (notBlank(req.getEmailAddress())) builder.addRDN(BCStyle.EmailAddress, req.getEmailAddress());
        return builder.build();
    }

    private boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    /** 校验并解析 RSA 密钥长度；SM2 返回 0（忽略）。 */
    private int resolveRsaKeySize(Integer requestedKeySize, boolean isSm2) {
        if (isSm2) {
            return 0;
        }
        int keySize = requestedKeySize == null || requestedKeySize <= 0 ? 2048 : requestedKeySize;
        if (keySize != 2048 && keySize != 3072 && keySize != 4096) {
            throw new IllegalArgumentException("RSA 密钥长度仅支持 2048/3072/4096");
        }
        return keySize;
    }

    /** 按算法生成密钥对 */
    private KeyPair generateKeyPair(boolean isSm2, int keySize) throws Exception {
        if (isSm2) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
            kpg.initialize(new ECGenParameterSpec("sm2p256v1"), new SecureRandom());
            return kpg.generateKeyPair();
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(keySize, new SecureRandom());
        return kpg.generateKeyPair();
    }

    /** 使用 java.time 按月计算有效期结束时间，确保 12 个月等跨月计算准确。 */
    private Date calculateNotAfter(Date notBefore, int validMonths) {
        ZonedDateTime start = ZonedDateTime.ofInstant(notBefore.toInstant(), ZoneId.systemDefault());
        ZonedDateTime end = start.plusMonths(validMonths);
        return Date.from(end.toInstant());
    }

    /** 解析 PEM 格式的 PKCS#10 CSR */
    private PKCS10CertificationRequest parseCsr(String pem) throws Exception {
        try (PemReader reader = new PemReader(new StringReader(pem))) {
            PemObject obj = reader.readPemObject();
            if (obj == null) {
                throw new IllegalArgumentException("无法解析 CSR：不是有效的 PEM 内容");
            }
            return new PKCS10CertificationRequest(obj.getContent());
        }
    }

    /** 将证书与私钥打包为 PFX/PKCS12 */
    private byte[] exportPfx(X509Certificate cert, PrivateKey key, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, null);
        keyStore.setKeyEntry("alias", key, password.toCharArray(), new Certificate[]{cert});
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        keyStore.store(out, password.toCharArray());
        return out.toByteArray();
    }

    /** 将 DER 字节封装为 PEM 字符串 */
    private String toPem(String type, byte[] der) throws Exception {
        StringWriter sw = new StringWriter();
        try (PemWriter writer = new PemWriter(sw)) {
            writer.writeObject(new PemObject(type, der));
        }
        return sw.toString();
    }
}
