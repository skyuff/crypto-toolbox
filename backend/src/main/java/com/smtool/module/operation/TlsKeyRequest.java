package com.smtool.module.operation;

import lombok.Data;

/**
 * TLS 1.2 / TLCP 密钥派生请求参数。
 */
@Data
public class TlsKeyRequest {
    /** 预主密钥 preMasterSecret，默认 hex */
    private String preMasterSecret;
    /** 客户端随机数，默认 hex */
    private String clientRandom;
    /** 服务端随机数，默认 hex */
    private String serverRandom;
    /** 哈希算法，默认 SM3 */
    private String hash = "SM3";
    /** 主密钥派生标签，默认 "master secret" */
    private String label1 = "master secret";
    /** 密钥扩展标签，默认 "key expansion" */
    private String label2 = "key expansion";
    /** 密码套件类型：block(分组算法) / aead(GCM)，默认 block */
    private String suiteType = "block";
    /** 会话密钥块字节长度；<=0 时按 suiteType 自动选取 */
    private int keyBlockLength = 0;
    /** preMasterSecret 编码格式，默认 hex */
    private String preMasterSecretFormat = "hex";
    /** 输出格式：hex / base64，默认 hex */
    private String formatOut = "hex";
    /** 操作类型：master（仅主密钥） / keyblock（主密钥+会话密钥） */
    private String operation = "master";
}
