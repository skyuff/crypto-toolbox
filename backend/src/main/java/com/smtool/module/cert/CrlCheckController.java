package com.smtool.module.cert;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * CRL（证书吊销列表）有效性校验接口。
 */
@RestController
@RequestMapping("/api/crl")
public class CrlCheckController {

    private final CrlCheckService crlCheckService;

    public CrlCheckController(CrlCheckService crlCheckService) {
        this.crlCheckService = crlCheckService;
    }

    /** 提取 CRL 信息 */
    @PostMapping("/info/extract")
    public ApiResponse<Map<String, Object>> extract(@RequestBody CrlCheckRequest req) throws Exception {
        return ApiResponse.ok(crlCheckService.extract(req));
    }

    /** 验证 CRL 有效性（结构、有效期、签名） */
    @PostMapping("/validate/signature")
    public ApiResponse<Map<String, Object>> validate(@RequestBody CrlCheckRequest req) throws Exception {
        return ApiResponse.ok(crlCheckService.validate(req));
    }

    /** 生成测试 CRL（使用证书和私钥签名），用于功能验证 */
    @PostMapping("/generate/test")
    public ApiResponse<String> generateTestCrl(@RequestBody Map<String, String> req) throws Exception {
        return ApiResponse.ok(crlCheckService.generateTestCrl(req.get("certPem"), req.get("keyPem")));
    }
}
