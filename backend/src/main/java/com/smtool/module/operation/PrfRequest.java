package com.smtool.module.operation;

import lombok.Data;

/**
 * TLS 1.2 PRF 运算请求参数。
 */
@Data
public class PrfRequest {
    /** 密钥（secret），按 secretFormat 解析，默认 hex */
    private String secret;
    /** 标签（label），按 utf8 处理 */
    private String label;
    /** 种子（seed），按 seedFormat 解析，默认 hex */
    private String seed;
    /** 输出字节长度（与 iterations 二选一，优先使用 iterations） */
    private int outputLength;
    /** 迭代轮数，每轮输出一个摘要长度 */
    private int iterations;
    /** 哈希算法 */
    private String hash = "SHA256";
    /** secret 编码格式：hex / base64 / string，默认 hex */
    private String secretFormat = "hex";
    /** seed 编码格式：hex / base64 / string，默认 hex */
    private String seedFormat = "hex";
    /** 结果输出格式：hex / base64，默认 hex */
    private String formatOut = "hex";
}
