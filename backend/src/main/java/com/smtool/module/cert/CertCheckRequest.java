package com.smtool.module.cert;

import lombok.Data;

/**
 * 证书格式检查请求 DTO。
 */
@Data
public class CertCheckRequest {
    /** 证书内容：PEM（含 -----BEGIN CERTIFICATE-----）/ base64 DER / hex DER */
    private String certPem;
}
