package com.smtool.module.tool;

import lombok.Data;

/**
 * 字符集转换请求 DTO。
 */
@Data
public class CharsetConvertRequest {
    /** 输入内容 */
    private String input;
    /** 源字符集，如 UTF-8 */
    private String fromCharset = "UTF-8";
    /** 目标字符集，如 GBK */
    private String toCharset = "GBK";
}
