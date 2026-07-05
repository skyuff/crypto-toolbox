package com.smtool.module.tool;

import lombok.Data;

/**
 * 大数运算请求 DTO。
 */
@Data
public class BigNumberRequest {
    /** 操作数 A */
    private String a;
    /** 操作数 B */
    private String b;
    /** A 的输入格式：hex / base64 */
    private String formatA = "hex";
    /** B 的输入格式：hex / base64 */
    private String formatB = "hex";
    /** 结果输出格式：hex / base64 */
    private String formatOut = "hex";
    /** 运算：add / sub / mul */
    private String op;
}
