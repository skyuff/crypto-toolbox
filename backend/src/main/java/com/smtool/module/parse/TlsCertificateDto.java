package com.smtool.module.parse;

import java.util.List;
import java.util.Map;

/**
 * TLS 会话中的证书 DTO。
 */
public class TlsCertificateDto {

    private String version;
    private String serialNumber;
    private String subject;
    private String issuer;
    private String notBefore;
    private String notAfter;
    private String validityPeriod;
    private boolean expired;
    private Map<String, Object> signatureAlgorithm;
    private String publicKeyAlgorithm;
    private String publicKeyHex;
    private String keyUsage;
    private boolean isSm2;
    private String derBase64;
    private List<Map<String, Object>> extensions;
    private List<Map<String, Object>> checks;

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(String notBefore) {
        this.notBefore = notBefore;
    }

    public String getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(String notAfter) {
        this.notAfter = notAfter;
    }

    public String getValidityPeriod() {
        return validityPeriod;
    }

    public void setValidityPeriod(String validityPeriod) {
        this.validityPeriod = validityPeriod;
    }

    public boolean isExpired() {
        return expired;
    }

    public void setExpired(boolean expired) {
        this.expired = expired;
    }

    public Map<String, Object> getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(Map<String, Object> signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public String getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    public void setPublicKeyAlgorithm(String publicKeyAlgorithm) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
    }

    public String getPublicKeyHex() {
        return publicKeyHex;
    }

    public void setPublicKeyHex(String publicKeyHex) {
        this.publicKeyHex = publicKeyHex;
    }

    public String getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(String keyUsage) {
        this.keyUsage = keyUsage;
    }

    public boolean isSm2() {
        return isSm2;
    }

    public void setSm2(boolean sm2) {
        isSm2 = sm2;
    }

    public String getDerBase64() {
        return derBase64;
    }

    public void setDerBase64(String derBase64) {
        this.derBase64 = derBase64;
    }

    public List<Map<String, Object>> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<Map<String, Object>> extensions) {
        this.extensions = extensions;
    }

    public List<Map<String, Object>> getChecks() {
        return checks;
    }

    public void setChecks(List<Map<String, Object>> checks) {
        this.checks = checks;
    }
}
