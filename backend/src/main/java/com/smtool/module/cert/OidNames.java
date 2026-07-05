package com.smtool.module.cert;

import java.util.HashMap;
import java.util.Map;

/**
 * 常用 OID 名称映射表：用于证书签名算法、公钥算法、ASN.1 OID 节点的可读化展示。
 * 未收录的 OID 只返回点分字符串。
 */
public final class OidNames {

    private OidNames() {
    }

    /** OID 点分字符串 -> 可读名称 */
    private static final Map<String, String> MAP = new HashMap<>();

    static {
        // 公钥算法
        MAP.put("1.2.840.113549.1.1.1", "rsaEncryption");
        MAP.put("1.2.840.10045.2.1", "ecPublicKey");
        MAP.put("1.2.840.10040.4.1", "dsa");
        MAP.put("1.2.156.10197.1.301", "sm2p256v1"); // SM2 曲线
        // 签名算法
        MAP.put("1.2.840.113549.1.1.5", "SHA1withRSA");
        MAP.put("1.2.840.113549.1.1.11", "SHA256withRSA");
        MAP.put("1.2.840.113549.1.1.12", "SHA384withRSA");
        MAP.put("1.2.840.113549.1.1.13", "SHA512withRSA");
        MAP.put("1.2.840.10045.4.1", "SHA1withECDSA");
        MAP.put("1.2.840.10045.4.3.2", "SHA256withECDSA");
        MAP.put("1.2.840.10045.4.3.3", "SHA384withECDSA");
        MAP.put("1.2.840.10045.4.3.4", "SHA512withECDSA");
        MAP.put("1.2.156.10197.1.501", "SM3withSM2");
        MAP.put("1.2.156.10197.1.401", "SM3"); // 杂凑算法
        MAP.put("1.2.156.10197.1.104", "SM4");
        // 常见摘要
        MAP.put("2.16.840.1.101.3.4.2.1", "SHA-256");
        MAP.put("2.16.840.1.101.3.4.2.2", "SHA-384");
        MAP.put("2.16.840.1.101.3.4.2.3", "SHA-512");
        MAP.put("1.3.14.3.2.26", "SHA-1");
        // DN 常见属性
        MAP.put("2.5.4.3", "CN(commonName)");
        MAP.put("2.5.4.6", "C(countryName)");
        MAP.put("2.5.4.7", "L(localityName)");
        MAP.put("2.5.4.8", "ST(stateOrProvinceName)");
        MAP.put("2.5.4.10", "O(organizationName)");
        MAP.put("2.5.4.11", "OU(organizationalUnitName)");
        MAP.put("1.2.840.113549.1.9.1", "emailAddress");
        // 证书扩展
        MAP.put("2.5.29.14", "subjectKeyIdentifier");
        MAP.put("2.5.29.15", "keyUsage");
        MAP.put("2.5.29.17", "subjectAltName");
        MAP.put("2.5.29.19", "basicConstraints");
        MAP.put("2.5.29.31", "cRLDistributionPoints");
        MAP.put("2.5.29.32", "certificatePolicies");
        MAP.put("2.5.29.35", "authorityKeyIdentifier");
        MAP.put("2.5.29.37", "extKeyUsage");
        MAP.put("1.3.6.1.5.5.7.1.1", "authorityInfoAccess");
    }

    /** 返回 OID 对应的可读名称，未知则返回 null */
    public static String get(String oid) {
        return MAP.get(oid);
    }

    /** 返回“点分 OID (名称)”形式，未知则仅返回点分 OID */
    public static String describe(String oid) {
        String name = MAP.get(oid);
        return name == null ? oid : oid + " (" + name + ")";
    }
}
