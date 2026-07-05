package com.smtool.module.other;

import lombok.Data;

/**
 * 密文长度分析请求 DTO。
 */
@Data
public class CipherLengthRequest {
    /** 输入数据 */
    private String input;

    /** 输入格式：string / hex / base64 */
    private String format = "string";
}
