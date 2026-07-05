package com.smtool.module.cert;

import lombok.Data;

/**
 * ASN.1 解析请求 DTO。
 */
@Data
public class Asn1ParseRequest {
    /** 待解析内容：PEM / base64 / hex 编码的 DER 数据 */
    private String input;
    /** 格式：pem / base64 / hex，默认（空或 auto）自动判断 */
    private String format = "auto";
}
