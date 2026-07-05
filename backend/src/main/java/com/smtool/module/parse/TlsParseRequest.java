package com.smtool.module.parse;

import lombok.Data;

/**
 * TLS 报文解析请求 DTO。
 */
@Data
public class TlsParseRequest {
    /** 待解析的报文内容 */
    private String input;
    /** 输入编码格式：hex（默认）/ base64 / utf8 */
    private String format = "hex";

    /** 源 IP */
    private String srcIp;
    /** 目标 IP */
    private String dstIp;
}
