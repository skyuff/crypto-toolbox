package com.smtool.module.operation;

import lombok.Data;

/**
 * 口令密钥派生 PBKDF2 请求 DTO。
 */
@Data
public class Pbkdf2Request {
    /** 口令 */
    private String password;
    /** 盐值 */
    private String salt;
    /** 迭代次数，默认 10000 */
    private int iterations = 10000;
    /** 派生密钥长度（字节），默认 32 */
    private int keyLength = 32;
    /** 伪随机函数：SM3 / SHA-224 / SHA-256(默认) / SHA-384 / SHA-512 / SHA3-224 / SHA3-256 / SHA3-384 / SHA3-512 / SHA-1 / MD5 */
    private String prf = "SHA-256";
    /** 口令编码格式：utf8 / hex / base64，默认 utf8 */
    private String passwordFormat = "utf8";
    /** 盐值编码格式：utf8 / hex / base64，默认 hex */
    private String saltFormat = "hex";
    /** 输出编码格式：hex / base64，默认 hex */
    private String outputFormat = "hex";
}
