package com.smtool.module.cert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * CRL（证书吊销列表）有效性校验服务：
 * 解析 X.509 CRL（支持 PEM / base64 DER / hex DER），提取颁发者、更新时间、签名算法、
 * 吊销条目，验证 CRL 签名，并给出结构合法性、是否过期等检查结果。
 */
@Service
public class CrlCheckService {

    private static final Logger log = LoggerFactory.getLogger(CrlCheckService.class);


    /**
     * 提取 CRL 结构化信息。
     */
    public Map<String, Object> extract(CrlCheckRequest req) throws Exception {
        X509CRL crl = parseCrl(req.getCrlPem(), req.getCrlFormat());
        return buildCrlInfo(crl, null);
    }

    /**
     * 验证 CRL 有效性：结构、有效期、签名（提供上级证书时）。
     */
    public Map<String, Object> validate(CrlCheckRequest req) throws Exception {
        X509CRL crl = parseCrl(req.getCrlPem(), req.getCrlFormat());
        X509Certificate issuerCert = null;
        String issuerMatchError = null;
        String signatureError = null;
        boolean signatureValid = false;

        if (req.getIssuerCert() != null && !req.getIssuerCert().isBlank()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            byte[] certDer = toDer(req.getIssuerCert(), req.getIssuerCertFormat());
            try (java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(certDer)) {
                issuerCert = (X509Certificate) cf.generateCertificate(in);
            }

            // 上级证书主题应和 CRL 颁发者一致
            if (!issuerCert.getSubjectX500Principal().equals(crl.getIssuerX500Principal())) {
                issuerMatchError = "上级证书主题与 CRL 颁发者不匹配";
            }

            try {
                crl.verify(issuerCert.getPublicKey());
                signatureValid = true;
            } catch (Exception e) {
                signatureError = "CRL 签名验证失败: " + e.getMessage();
                log.warn("CRL 签名验证失败", e);
            }
        }

        Map<String, Object> result = buildCrlInfo(crl, issuerCert);
        result.put("signatureValid", signatureValid);
        if (issuerMatchError != null) {
            result.put("issuerMatchError", issuerMatchError);
        }
        if (signatureError != null) {
            result.put("signatureError", signatureError);
        }

        // 追加签名检查项
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> checks = (List<Map<String, Object>>) result.get("checks");
        if (req.getIssuerCert() != null && !req.getIssuerCert().isBlank()) {
            checks.add(check("上级证书主题匹配", issuerMatchError == null,
                    issuerMatchError == null ? "上级证书主题与 CRL 颁发者一致" : issuerMatchError));
            checks.add(check("CRL 签名验证", signatureValid,
                    signatureValid ? "CRL 签名验证通过" : (signatureError == null ? "签名验证失败" : signatureError)));
        } else {
            checks.add(check("CRL 签名验证", false, "未提供上级证书，未进行签名验证"));
        }
        return result;
    }

    /** 解析 CRL */
    private X509CRL parseCrl(String crlPem, String crlFormat) throws Exception {
        if (crlPem == null || crlPem.isBlank()) {
            throw new IllegalArgumentException("请提供 CRL 内容");
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        byte[] der = toDer(crlPem, crlFormat);
        try (java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(der)) {
            return (X509CRL) cf.generateCRL(in);
        }
    }

    /** 构造 CRL 信息结果 */
    private Map<String, Object> buildCrlInfo(X509CRL crl, X509Certificate issuerCert) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("issuer", crl.getIssuerX500Principal().getName());

        Date thisUpdate = crl.getThisUpdate();
        Date nextUpdate = crl.getNextUpdate();
        result.put("thisUpdate", thisUpdate == null ? null : thisUpdate.toInstant().toString());
        result.put("nextUpdate", nextUpdate == null ? null : nextUpdate.toInstant().toString());
        result.put("signatureAlgorithm", crl.getSigAlgName() + " (" + crl.getSigAlgOID() + ")");
        result.put("sigAlgOid", crl.getSigAlgOID());

        Set<? extends X509CRLEntry> entries = crl.getRevokedCertificates();
        int revokedCount = entries == null ? 0 : entries.size();
        result.put("revokedCount", revokedCount);
        result.put("revokedTotal", revokedCount);
        result.put("revokedTruncated", false);

        List<Map<String, Object>> revokedList = new ArrayList<>();
        if (entries != null) {
            for (X509CRLEntry entry : entries) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("serialNumber", entry.getSerialNumber().toString(16));
                item.put("revocationDate", entry.getRevocationDate().toInstant().toString());
                if (entry.getRevocationReason() != null) {
                    item.put("revocationReason", entry.getRevocationReason().name());
                }
                revokedList.add(item);
            }
        }
        result.put("revokedCertificates", revokedList);

        Date now = new Date();
        boolean expired = nextUpdate != null && now.after(nextUpdate);
        result.put("expired", expired);

        List<Map<String, Object>> checks = new ArrayList<>();
        checks.add(check("结构合法", true, "CRL DER 编码解析成功"));
        checks.add(check("包含签名算法", crl.getSigAlgOID() != null,
                "签名算法: " + crl.getSigAlgName()));
        checks.add(check("包含 nextUpdate", nextUpdate != null,
                nextUpdate == null ? "CRL 未包含 nextUpdate 字段" : "nextUpdate: " + nextUpdate.toInstant()));
        checks.add(check("在有效期内（nextUpdate 未过期）", !expired,
                expired ? "CRL 已过期，nextUpdate 早于当前时间" : "CRL 在有效期内"));
        result.put("checks", checks);

        return result;
    }

    /**
     * 生成测试 CRL（仅用于功能验证）：使用指定证书和私钥签名一个包含示例序列号的 CRL。
     */
    public String generateTestCrl(String certPem, String keyPem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        byte[] certDer = DerInputUtil.toDer(certPem);
        X509Certificate cert;
        try (java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(certDer)) {
            cert = (X509Certificate) cf.generateCertificate(in);
        }
        java.security.PrivateKey key = DerInputUtil.parsePrivateKey(keyPem);

        Date now = new Date();
        Date next = new Date(now.getTime() + 86400000L);
        org.bouncycastle.asn1.x500.X500Name issuer =
                org.bouncycastle.asn1.x500.X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
        org.bouncycastle.cert.X509v2CRLBuilder builder = new org.bouncycastle.cert.X509v2CRLBuilder(issuer, now);
        builder.setNextUpdate(next);
        builder.addCRLEntry(java.math.BigInteger.valueOf(12345), now, 0);
        String sigAlg = cert.getSigAlgName();
        org.bouncycastle.cert.X509CRLHolder holder = builder.build(
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(sigAlg).setProvider("BC").build(key));
        java.security.cert.X509CRL crl = new org.bouncycastle.cert.jcajce.JcaX509CRLConverter()
                .setProvider("BC").getCRL(holder);

        java.io.StringWriter sw = new java.io.StringWriter();
        try (org.bouncycastle.util.io.pem.PemWriter w = new org.bouncycastle.util.io.pem.PemWriter(sw)) {
            w.writeObject(new org.bouncycastle.util.io.pem.PemObject("X509 CRL", crl.getEncoded()));
        }
        return sw.toString();
    }

    private byte[] toDer(String input, String format) {
        if (format == null || format.isBlank()) {
            return DerInputUtil.toDer(input);
        }
        return DerInputUtil.toDer(input, format);
    }

    /** 构造单条检查结果 */
    private Map<String, Object> check(String item, boolean pass, String message) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("item", item);
        m.put("pass", pass);
        m.put("message", message);
        return m;
    }
}
