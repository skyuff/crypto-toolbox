package com.smtool.module.tool;

import lombok.Data;

/**
 * 逻辑运算请求 DTO。
 */
@Data
public class LogicRequest {
    /** 操作数 a */
    private String a;
    /** 操作数 b（部分运算不需要） */
    private String b;
    /** 运算：xor/and/or/not/shl/shr */
    private String op;
    /** A 的输入格式：hex / base64 */
    private String formatA = "hex";
    /** B 的输入格式：hex / base64 */
    private String formatB = "hex";
    /** 结果输出格式：hex / base64 */
    private String formatOut = "hex";
    /** 循环位移的位数（shl/shr 使用） */
    private int shift;
}
