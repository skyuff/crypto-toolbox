package com.smtool.module.tool;

import lombok.Data;

/**
 * 字节逆序请求 DTO。
 */
@Data
public class ByteOrderRequest {
    /** 输入内容 */
    private String input;
    /** 输入编码格式，默认 hex */
    private String format = "hex";
    /** 结果输出格式，默认 hex */
    private String formatOut = "hex";
    /** 分组字节数，支持 1/2/4/8，默认 1（整体逆序） */
    private int unit = 1;
}
