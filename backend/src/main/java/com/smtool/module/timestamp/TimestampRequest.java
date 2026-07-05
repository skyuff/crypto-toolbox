package com.smtool.module.timestamp;

import lombok.Data;

/**
 * 时间戳解析请求参数。
 */
@Data
public class TimestampRequest {
    /** 时间戳数据：TimeStampResponse 或 TimeStampToken(ContentInfo) 的 DER 编码 */
    private String input;

    /** 输入编码格式：PEM / base64 / hex */
    private String format = "base64";

    /** 原始数据（验证时使用）：hex / base64 / utf8 */
    private String originalInput;

    /** 原始数据编码格式：hex / base64 / utf8，默认 utf8 */
    private String originalFormat = "utf8";
}
