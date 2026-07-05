package com.smtool.module.sm2;

import lombok.Data;
import com.fasterxml.jackson.annotation.JsonProperty;

@Data
public class SM2Request {
    private String publicKey;
    private String privateKey;
    /** C1C3C2(默认) / C1C2C3 */
    private String mode = "C1C3C2";
    private String userId = "1234567812345678";

    private String input;
    private String inputFormat = "utf8";
    private String outputFormat = "hex";

    private String signature;
    private String signatureFormat = "hex";

    // ---------- 签名验签标签页 ----------
    /** 签名模式：message（基于消息）/ evalue（基于 e 值） */
    private String signMode = "message";
    /** 基于 e 值签名/验签时直接给出的 e（hex） */
    @JsonProperty("eValue")
    private String eValue;
    /** 签名值编码格式：rs（R||S 64字节）/ der */
    private String sigEncoding = "rs";
    /** 待转换的签名值（用于 R||S <-> DER 转换） */
    private String sigInput;
    private String sigInputFormat = "hex";

    // ---------- 两组数据验签 / 验签并攻击 ----------
    private String message1;
    private String message1Format = "utf8";
    private String signature1;
    private String signature1Format = "hex";
    private String message2;
    private String message2Format = "utf8";
    private String signature2;
    private String signature2Format = "hex";

    // ---------- 密钥交换（GM/T 0003.3） ----------
    /** 发起方标识 A */
    private String idA = "1234567812345678";
    /** 响应方标识 B */
    private String idB = "1234567812345678";
    /** A 的静态私钥 dA / 公钥 PA */
    private String privateKeyA;
    private String publicKeyA;
    /** B 的静态私钥 dB / 公钥 PB */
    private String privateKeyB;
    private String publicKeyB;
    /** 协商密钥长度（字节） */
    private int keyLength = 16;

    // ---------- 协同签名（两方） ----------
    /** 第一子密钥（第一方，如客户端） d1 */
    private String d1;
    /** 第二子密钥（第二方，如服务端） d2 */
    private String d2;
}
