package com.smtool.module.other;

import lombok.Data;

/**
 * 工作模式检测请求 DTO。
 */
@Data
public class CipherModeRequest {
    /** 第一组密文 */
    private String ciphertext1;
    /** 第一组密文编码格式，默认 hex */
    private String format1 = "hex";
    /** 第二组密文 */
    private String ciphertext2;
    /** 第二组密文编码格式，默认 hex */
    private String format2 = "hex";
    /** 分组大小（字节），默认 16（SM4/AES=16，DES=8） */
    private int blockSize = 16;
}
