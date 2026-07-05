package com.smtool.module.hash;

import lombok.Data;

@Data
public class MacRequest {
    /** MAC 模式：CBC-MAC / CMAC / EMAC / ANSI-retail-MAC / MacDES / LMAC / CBCR / TrCBC */
    private String type = "CBC-MAC";
    /** 底层分组算法：SM4 / AES-128 / AES-192 / AES-256 */
    private String algorithm = "SM4";
    /** 填充方式：method1（C.2）/ method2（C.3）/ method3（C.4） */
    private String padding = "method1";
    /** MAC 输出截断字节数（8/12/16），默认整块 16 */
    private int macSize = 16;
    private String key;
    private String keyFormat = "hex";
    /** 结果编码：hex / base64 */
    private String outputFormat = "hex";
    private String input;
    private String inputFormat = "utf8";
}
