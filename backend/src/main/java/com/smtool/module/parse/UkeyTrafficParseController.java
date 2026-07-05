package com.smtool.module.parse;

import com.smtool.common.ApiResponse;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

/**
 * UKey 流量包解析接口。
 */
@RestController
@RequestMapping("/api/ukey")
public class UkeyTrafficParseController {

    private final UkeyTrafficParseService ukeyTrafficParseService;

    public UkeyTrafficParseController(UkeyTrafficParseService ukeyTrafficParseService) {
        this.ukeyTrafficParseService = ukeyTrafficParseService;
    }

    /** 解析 UKey 流量包 */
    @PostMapping(value = "/traffic/parse", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ApiResponse<Map<String, Object>> trafficParse(
            @RequestParam("vendor") String vendor,
            @RequestParam(value = "file", required = false) MultipartFile file,
            @RequestParam(value = "keyCertInput", required = false) String keyCertInput,
            @RequestParam(value = "keyCertMode", required = false) String keyCertMode) throws Exception {
        return ApiResponse.ok(ukeyTrafficParseService.parse(vendor, file, keyCertInput, keyCertMode));
    }
}
