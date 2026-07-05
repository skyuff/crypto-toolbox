package com.smtool.module.cert;

import lombok.Data;

/**
 * 证书在线签发请求参数。
 */
@Data
public class CertIssueRequest {

    /** 签发方式：direct（直接生成 PFX 证书） / csr（提交 CSR/P10 签发） */
    private String issueMode = "direct";

    /** 证书类型：user（用户证书） / ca（CA 证书） / etc. */
    private String certType = "用户证书";

    /** 有效期（月），默认 12 */
    private Integer validMonths = 12;

    /** PFX 导出密码（直接生成模式必填） */
    private String pfxPassword;

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

    /** 完整主题 DN（兼容旧接口），如 "CN=Test,O=Org,C=CN" */
    private String subject;

    /** 密钥/签名算法：RSA 或 SM2 */
    private String algorithm = "SM2";

    /** 可选：PEM 格式的 PKCS#10 CSR；提供时从中取公钥与主题 */
    private String csr;

    /** 可选：上级 CA 证书 PEM（非自签时使用） */
    private String issuerCertPem;

    /** 可选：上级 CA 私钥 PEM（非自签时使用） */
    private String issuerKeyPem;
}
