package com.smtool.module.hash;

import lombok.Data;

@Data
public class HashRequest {
    private String algorithm;
    private String input;
    private String inputFormat = "utf8";
    /** 盐值 */
    private String salt;
    private String saltFormat = "utf8";
    /** 盐值位置：pre（前置）/ post（后置） */
    private String saltPosition = "pre";
    /** 迭代次数，至少 1 */
    private int iterations = 1;
}
