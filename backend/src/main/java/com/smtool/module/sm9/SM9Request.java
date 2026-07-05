package com.smtool.module.sm9;

import lombok.Data;

/**
 * SM9 请求参数。
 * 由于 BouncyCastle 1.78.1 未提供 SM9 高层 API（无双线性对/pairing 实现），
 * 各接口仅接收参数并返回诚实的“不支持”说明，不伪造密码学结果。
 */
@Data
public class SM9Request {
    /** 密钥类型：sign（签名主密钥）/ encrypt（加密主密钥） */
    private String type = "sign";

    /** 用户标识（签名/加密的身份 ID），如 "Alice" */
    private String userId;

    /** 签名/加密主密钥（十六进制，测试用） */
    private String masterKey;

    /** 用户私钥（十六进制，测试用） */
    private String userKey;

    /** 待处理输入（明文 / 密文 / 待签名数据） */
    private String input;
    private String inputFormat = "utf8";

    /** 签名值（验签时使用） */
    private String signature;
    private String signatureFormat = "hex";
}
