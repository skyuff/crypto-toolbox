package com.smtool.module.cert;

import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 证书撤销状态检查服务：
 * <p>提供 crlPem 时进行离线 CRL 撤销检查：解析证书序列号，在 CRL 的吊销列表中查找。
 * 未提供 crlPem 时诚实说明离线环境限制（OCSP 实时查询需联网，已禁用）。</p>
 */
@Service
public class CertStatusService {

    /**
     * CRL 检查入口：解析证书与 CRL，查询证书序列号是否在 CRL 吊销列表中。
     */
    public Map<String, Object> checkByCrl(CertStatusRequest req) throws Exception {
        if (req.getCertPem() == null || req.getCertPem().isBlank()) {
            throw new IllegalArgumentException("请提供待检查的证书内容 certPem");
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        byte[] certDer = toDer(req.getCertPem(), req.getCertFormat());
        X509Certificate cert;
        try (ByteArrayInputStream in = new ByteArrayInputStream(certDer)) {
            cert = (X509Certificate) cf.generateCertificate(in);
        }
        BigInteger serial = cert.getSerialNumber();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("checkedBy", "CRL");
        result.put("certSubject", cert.getSubjectX500Principal().getName());
        result.put("certIssuer", cert.getIssuerX500Principal().getName());
        result.put("certSerialNumber", serial.toString(16));

        if (req.getCrlPem() == null || req.getCrlPem().isBlank()) {
            result.put("revoked", false);
            result.put("message", "未提供 CRL 文件，无法完成离线撤销检查");
            return result;
        }

        byte[] crlDer = toDer(req.getCrlPem(), req.getCrlFormat());
        X509CRL crl;
        try (ByteArrayInputStream in = new ByteArrayInputStream(crlDer)) {
            crl = (X509CRL) cf.generateCRL(in);
        }

        result.put("crlIssuer", crl.getIssuerX500Principal().getName());

        X509CRLEntry entry = crl.getRevokedCertificate(serial);
        boolean revoked = entry != null;
        result.put("revoked", revoked);
        if (revoked) {
            result.put("revocationDate", entry.getRevocationDate().toInstant().toString());
            if (entry.getRevocationReason() != null) {
                result.put("revocationReason", entry.getRevocationReason().name());
            }
        }
        return result;
    }

    /**
     * OCSP 检查入口：离线环境无法访问外网，构造 OCSP 请求说明并返回提示。
     */
    public Map<String, Object> checkByOcsp(CertStatusRequest req) throws Exception {
        if (req.getCertPem() == null || req.getCertPem().isBlank()) {
            throw new IllegalArgumentException("请提供待检查的证书内容 certPem");
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        byte[] certDer = toDer(req.getCertPem(), req.getCertFormat());
        X509Certificate cert;
        try (ByteArrayInputStream in = new ByteArrayInputStream(certDer)) {
            cert = (X509Certificate) cf.generateCertificate(in);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("checkedBy", "OCSP");
        result.put("certSubject", cert.getSubjectX500Principal().getName());
        result.put("certIssuer", cert.getIssuerX500Principal().getName());
        result.put("certSerialNumber", cert.getSerialNumber().toString(16));
        result.put("ocspUrl", req.getOcspUrl());
        result.put("digestAlgorithm", defaultDigest(req.getDigestAlgorithm()));
        result.put("revoked", false);
        result.put("message", "离线环境：OCSP 实时查询需联网，已禁用。请在联网环境或受信任 CA 环境中发起 OCSP 请求。");
        return result;
    }

    private byte[] toDer(String input, String format) {
        if (format == null || format.isBlank()) {
            return DerInputUtil.toDer(input);
        }
        return DerInputUtil.toDer(input, format);
    }

    private String defaultDigest(String digest) {
        if (digest == null || digest.isBlank()) {
            return "SM3";
        }
        return digest.trim().toUpperCase();
    }
}
