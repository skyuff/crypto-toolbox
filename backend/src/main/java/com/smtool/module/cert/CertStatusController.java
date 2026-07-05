package com.smtool.module.cert;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 证书撤销状态检查控制器。
 */
@RestController
@RequestMapping("/api/cert")
public class CertStatusController {

    private final CertStatusService certStatusService;

    public CertStatusController(CertStatusService certStatusService) {
        this.certStatusService = certStatusService;
    }

    /** 通过 CRL 检查证书撤销状态 */
    @PostMapping("/status/check/crl")
    public ApiResponse<Map<String, Object>> checkByCrl(@RequestBody CertStatusRequest req) throws Exception {
        return ApiResponse.ok(certStatusService.checkByCrl(req));
    }

    /** 通过 OCSP 检查证书撤销状态（离线环境仅返回说明） */
    @PostMapping("/status/check/ocsp")
    public ApiResponse<Map<String, Object>> checkByOcsp(@RequestBody CertStatusRequest req) throws Exception {
        return ApiResponse.ok(certStatusService.checkByOcsp(req));
    }
}
