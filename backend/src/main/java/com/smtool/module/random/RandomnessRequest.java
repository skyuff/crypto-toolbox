package com.smtool.module.random;

import lombok.Data;

import java.util.List;

/**
 * 随机数检测请求参数。
 */
@Data
public class RandomnessRequest {
    /** 待检测的随机二进制数据 */
    private String input;

    /** 输入编码格式：hex / base64 / utf8 */
    private String format = "hex";

    /** 期望检测的目标比特长度（可选，仅用于提示或截断/补齐） */
    private Integer bitLength;

    /** 选中的检测方法编号列表，为空则执行全部 28 种 */
    private List<Integer> selectedMethods;
}
