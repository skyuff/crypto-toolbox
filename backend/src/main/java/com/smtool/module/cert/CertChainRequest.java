package com.smtool.module.cert;

import lombok.Data;

import java.util.List;

/**
 * 证书链验证请求 DTO。
 */
@Data
public class CertChainRequest {

    /** 证书链：从根证书到终端证书，每项为 PEM / base64 DER / hex DER */
    private List<String> certs;
}
