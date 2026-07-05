package com.smtool.module.signature;

import lombok.Data;

/**
 * 电子签章（GM/T 0031）解析请求 DTO。
 */
@Data
public class SealParseRequest {
    /** 待解析的签章数据内容 */
    private String input;
    /** 输入编码格式：base64（默认）/ pem / hex */
    private String format = "base64";
}
