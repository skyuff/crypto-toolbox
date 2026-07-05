package com.smtool.module.operation;

import lombok.Data;

/**
 * SM2 加密 k 碰撞分析请求参数。
 */
@Data
public class Sm2kRequest {
    /** 密文或 C1 部分 */
    private String input;
    /** input 编码格式：hex / base64，默认 hex */
    private String inputFormat = "hex";
    /** 公钥（04 开头未压缩点或 128 位裸坐标） */
    private String publicKey;
    /** publicKey 编码格式：hex / base64，默认 hex */
    private String publicKeyFormat = "hex";
    /** 完整密文拼接模式：C1C3C2(默认) / C1C2C3 */
    private String mode = "C1C3C2";
    /** 恢复明文输出格式：string / hex / base64，默认 string */
    private String formatOut = "string";
    /** 碰撞搜索上限，默认 1_000_000 */
    private long kMax = 1_000_000L;
}
