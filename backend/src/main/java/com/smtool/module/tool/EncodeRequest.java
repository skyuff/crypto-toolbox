package com.smtool.module.tool;

import lombok.Data;

/**
 * 编码转换请求 DTO。
 */
@Data
public class EncodeRequest {
    /** 输入内容 */
    private String input;
    /** 源编码格式：utf8/hex/base64/base58/decimal/bytes */
    private String fromFormat = "utf8";
    /** 目标编码格式：utf8/hex/base64/base58/decimal/bytes */
    private String toFormat = "hex";
}
