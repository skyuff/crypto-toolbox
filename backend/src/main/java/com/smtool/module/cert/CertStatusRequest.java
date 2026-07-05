package com.smtool.module.cert;

import lombok.Data;

/**
 * 证书撤销状态检查请求 DTO。
 */
@Data
public class CertStatusRequest {
    /** 待检查证书内容：PEM / base64 DER / hex DER */
    private String certPem;
    /** 待检查证书格式：pem / base64 / hex；为空时自动识别 */
    private String certFormat;
    /** CRL 内容（可选）：PEM / base64 DER / hex DER；提供后进行离线撤销检查 */
    private String crlPem;
    /** CRL 格式：pem / base64 / hex；为空时自动识别 */
    private String crlFormat;
    /** OCSP 请求地址 */
    private String ocspUrl;
    /** OCSP 哈希算法：SM3 / SHA1 / SHA256 / SHA384 / SHA512 */
    private String digestAlgorithm;
}
