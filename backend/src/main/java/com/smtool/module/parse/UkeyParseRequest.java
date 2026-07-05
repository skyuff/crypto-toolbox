package com.smtool.module.parse;

import lombok.Data;

/**
 * UKey APDU 解析请求 DTO。
 */
@Data
public class UkeyParseRequest {
    /** 待解析的 APDU 内容 */
    private String input;
    /** 输入编码格式：hex（默认）/ base64 / utf8 */
    private String format = "hex";
    /** APDU 类型：command（命令，默认）/ response（响应） */
    private String type = "command";
}
