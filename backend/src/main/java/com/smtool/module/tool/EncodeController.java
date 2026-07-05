package com.smtool.module.tool;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 编码转换控制器。
 */
@RestController
@RequestMapping("/api/encode")
public class EncodeController {

    private final EncodeService encodeService;

    public EncodeController(EncodeService encodeService) {
        this.encodeService = encodeService;
    }

    /** 单向编码转换 */
    @PostMapping("/convert")
    public ApiResponse<Map<String, Object>> convert(@RequestBody EncodeRequest req) throws Exception {
        return ApiResponse.ok(encodeService.convert(req));
    }

    /** 一次性多向展示 */
    @PostMapping("/all")
    public ApiResponse<Map<String, Object>> all(@RequestBody EncodeRequest req) throws Exception {
        return ApiResponse.ok(encodeService.all(req));
    }

    /** 字符集转换 */
    @PostMapping("/charset/convert")
    public ApiResponse<Map<String, Object>> charsetConvert(@RequestBody CharsetConvertRequest req) throws Exception {
        return ApiResponse.ok(encodeService.charsetConvert(req));
    }
}
