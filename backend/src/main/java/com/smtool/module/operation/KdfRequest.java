package com.smtool.module.operation;

import lombok.Data;

/**
 * GM/T 规范 KDF 运算请求参数。
 */
@Data
public class KdfRequest {
    /** 共享秘密 Z，按 zFormat 解析，默认 hex */
    private String z;
    /** 期望派生密钥字节长度 */
    private int keyLength;
    /** 哈希算法，默认 SM3 */
    private String hash = "SM3";
    /** z 编码格式：hex / base64，默认 hex */
    private String zFormat = "hex";
    /** 结果输出格式：hex / base64，默认 hex */
    private String formatOut = "hex";
}
