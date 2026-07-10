package com.smtool.module.parse;

/**
 * IPSEC / IKE 证书信息展示 DTO。
 */
public class IpsecCertificateInfoDto {

    private int index;
    private String version;
    private String serialNumber;
    private String subject;
    private String issuer;
    private String notBefore;
    private String notAfter;
    private String signatureAlgorithm;
    private String publicKeyAlgorithm;
    private String keyUsage;
    private String derBase64;

    public int getIndex() { return index; }
    public void setIndex(int index) { this.index = index; }

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }

    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }

    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }

    public String getNotBefore() { return notBefore; }
    public void setNotBefore(String notBefore) { this.notBefore = notBefore; }

    public String getNotAfter() { return notAfter; }
    public void setNotAfter(String notAfter) { this.notAfter = notAfter; }

    public String getSignatureAlgorithm() { return signatureAlgorithm; }
    public void setSignatureAlgorithm(String signatureAlgorithm) { this.signatureAlgorithm = signatureAlgorithm; }

    public String getPublicKeyAlgorithm() { return publicKeyAlgorithm; }
    public void setPublicKeyAlgorithm(String publicKeyAlgorithm) { this.publicKeyAlgorithm = publicKeyAlgorithm; }

    public String getKeyUsage() { return keyUsage; }
    public void setKeyUsage(String keyUsage) { this.keyUsage = keyUsage; }

    public String getDerBase64() { return derBase64; }
    public void setDerBase64(String derBase64) { this.derBase64 = derBase64; }
}
