package com.smtool.module.symmetric;

import lombok.Data;

/**
 * 对称加解密通用请求。
 */
@Data
public class SymmetricRequest {
    /** encrypt / decrypt */
    private String operation = "encrypt";
    /** SM4 / AES / DES / 3DES */
    private String algorithm;
    /** ECB / CBC / CFB / OFB / CTR / GCM */
    private String mode = "ECB";
    /** PKCS5Padding / PKCS7Padding / NoPadding ... */
    private String padding = "PKCS5Padding";

    private String key;
    private String keyFormat = "hex";
    private String iv;
    private String ivFormat = "hex";
    private String input;
    private String inputFormat = "hex";
    private String outputFormat = "hex";

    /** GCM 专用：附加认证数据 */
    private String aad;
    private String aadFormat = "hex";
    /** GCM 专用：tag 长度（bit），默认 128 */
    private Integer tagLength = 128;
    /** GCM 解密专用：认证标签 */
    private String tag;
    private String tagFormat = "hex";
}
