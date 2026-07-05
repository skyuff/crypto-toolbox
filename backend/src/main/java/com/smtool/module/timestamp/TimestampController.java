package com.smtool.module.timestamp;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 时间戳（RFC 3161）解析接口。
 */
@RestController
@RequestMapping("/api/timestamp")
public class TimestampController {

    private final TimestampService timestampService;

    public TimestampController(TimestampService timestampService) {
        this.timestampService = timestampService;
    }

    /** 解析 TimeStampResponse 或 TimeStampToken，返回结构化信息 */
    @PostMapping("/parse")
    public ApiResponse<Map<String, Object>> parse(@RequestBody TimestampRequest req) throws Exception {
        return ApiResponse.ok(timestampService.parse(req));
    }

    /** 验证时间戳与原始数据的摘要是否一致 */
    @PostMapping("/verify")
    public ApiResponse<Map<String, Object>> verify(@RequestBody TimestampRequest req) throws Exception {
        return ApiResponse.ok(timestampService.verify(req));
    }
}
