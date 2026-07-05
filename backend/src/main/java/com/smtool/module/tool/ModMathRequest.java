package com.smtool.module.tool;

import lombok.Data;

/**
 * 取模运算请求 DTO。
 */
@Data
public class ModMathRequest {
    /** 操作数 a */
    private String a;
    /** 操作数 b */
    private String b;
    /** 模数 m */
    private String m;
    /** A 的输入格式：hex / base64 */
    private String formatA = "hex";
    /** B 的输入格式：hex / base64 */
    private String formatB = "hex";
    /** 模数 M 的输入格式：hex / base64 */
    private String formatM = "hex";
    /** 结果输出格式：hex / base64 */
    private String formatOut = "hex";
    /** 运算：add / sub / mul / inv / pow */
    private String op;
}
