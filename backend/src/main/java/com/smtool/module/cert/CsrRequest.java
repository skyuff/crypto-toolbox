package com.smtool.module.cert;

import lombok.Data;

/**
 * CSR（PKCS#10）生成请求 DTO。
 */
@Data
public class CsrRequest {

    /** 国家 C */
    private String country;
    /** 省份 ST */
    private String state;
    /** 城市 L */
    private String locality;
    /** 组织 O */
    private String organization;
    /** 部门 OU */
    private String organizationalUnit;
    /** 通用名 CN */
    private String commonName;
    /** 邮箱 EmailAddress */
    private String emailAddress;

    /** 完整主题 DN（优先级高于单独字段） */
    private String subject;

    /** 密钥算法：SM2 / RSA */
    private String algorithm = "SM2";

    /** RSA 密钥长度（位）：仅 RSA 有效，默认 2048，支持 3072/4096 */
    private Integer keySize = 2048;
}
