package com.smtool.module.cert;

import lombok.Data;

/**
 * CRL（证书吊销列表）有效性校验请求 DTO。
 */
@Data
public class CrlCheckRequest {
    /** CRL 内容：PEM（含 -----BEGIN X509 CRL-----）/ base64 DER / hex DER */
    private String crlPem;
    /** CRL 格式：pem / base64 / hex；为空时自动识别 */
    private String crlFormat;
    /** 上级证书：用于验证 CRL 签名；PEM / base64 DER / hex DER */
    private String issuerCert;
    /** 上级证书格式：pem / base64 / hex；为空时自动识别 */
    private String issuerCertFormat;
}
