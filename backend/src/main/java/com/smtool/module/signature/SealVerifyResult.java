package com.smtool.module.signature;

import lombok.Data;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 电子签章校验结果 DTO。
 */
@Data
public class SealVerifyResult {

    /** 文件类型：PDF / OFD / UNKNOWN */
    private String fileType;
    /** 是否解析成功 */
    private boolean parsed;
    /** 全局错误说明 */
    private String error;
    /** 签章摘要列表 */
    private List<Map<String, Object>> signatures = new ArrayList<>();
    /** 其他提取信息 */
    private Map<String, Object> extra = new LinkedHashMap<>();

    public static SealVerifyResult error(String msg) {
        SealVerifyResult r = new SealVerifyResult();
        r.setParsed(false);
        r.setError(msg);
        return r;
    }
}
