package com.smtool.module.operation;

import lombok.Data;

/**
 * 椭圆曲线点运算请求 DTO。
 */
@Data
public class PointOpRequest {
    /** 曲线名称，默认 sm2p256v1 */
    private String curve = "sm2p256v1";
    /** 运算类型：add(点加 P+Q) / sub(点减 P-Q) / mul(点乘 [k]P) */
    private String op;
    /** 点 P，未压缩(04开头)或压缩 hex/base64 */
    private String p;
    /** 点 Q 或标量 k，hex/base64 */
    private String q;
    /** 输入编码格式：hex / base64，默认 hex */
    private String inputFormat = "hex";
    /** 输出编码格式：hex / base64，默认 hex */
    private String outputFormat = "hex";
}
