package com.smtool.module.operation;

import lombok.Data;

/**
 * SM2 随机数（nonce）重用签名攻击请求参数。
 * 两次签名重用了相同随机数 k，给出两组 (r, s, e)。
 */
@Data
public class SigAttackRequest {
    /** 曲线名，默认 sm2p256v1 */
    private String curve = "sm2p256v1";
    /** 输入编码格式：hex / base64，默认 hex */
    private String inputFormat = "hex";
    /** 第一组签名 r1 */
    private String r1;
    /** 第一组签名 s1 */
    private String s1;
    /** 第一组消息相关的 e1 */
    private String e1;
    /** 第二组签名 r2 */
    private String r2;
    /** 第二组签名 s2 */
    private String s2;
    /** 第二组消息相关的 e2 */
    private String e2;
}
