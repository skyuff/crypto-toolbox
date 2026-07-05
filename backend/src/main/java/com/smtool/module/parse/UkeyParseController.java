package com.smtool.module.parse;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * UKey APDU 解析控制器。
 */
@RestController
@RequestMapping("/api/ukey")
public class UkeyParseController {

    private final UkeyParseService ukeyParseService;

    public UkeyParseController(UkeyParseService ukeyParseService) {
        this.ukeyParseService = ukeyParseService;
    }

    /** 解析 UKey 命令 / 响应 APDU */
    @PostMapping("/parse")
    public ApiResponse<Map<String, Object>> parse(@RequestBody UkeyParseRequest req) throws Exception {
        return ApiResponse.ok(ukeyParseService.parse(req));
    }
}
