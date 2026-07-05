package com.smtool.module.cert;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 数字证书格式检查接口。
 */
@RestController
@RequestMapping("/api/cert")
public class CertCheckController {

    private final CertCheckService certCheckService;

    public CertCheckController(CertCheckService certCheckService) {
        this.certCheckService = certCheckService;
    }

    /** 检查 X.509 证书格式并返回结构化信息 */
    @PostMapping("/format/check")
    public ApiResponse<Map<String, Object>> check(@RequestBody CertCheckRequest req) throws Exception {
        return ApiResponse.ok(certCheckService.check(req));
    }

    /** 验证证书链 */
    @PostMapping("/chain/validate")
    public ApiResponse<Map<String, Object>> validateChain(@RequestBody CertChainRequest req) throws Exception {
        return ApiResponse.ok(certCheckService.validateChain(req.getCerts()));
    }
}
