package com.smtool.module.cert;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 证书在线签发接口（轻量本地 CA 模拟）。
 */
@RestController
@RequestMapping("/api/cert")
public class CertIssueController {

    private final CertIssueService certIssueService;

    public CertIssueController(CertIssueService certIssueService) {
        this.certIssueService = certIssueService;
    }

    /** 在线签发一张 X.509 证书（直接生成 PFX 或根据 CSR/P10 签发） */
    @PostMapping("/sign/issue")
    public ApiResponse<Map<String, Object>> issue(@RequestBody CertIssueRequest req) throws Exception {
        return ApiResponse.ok(certIssueService.issue(req));
    }

    /** 生成 PKCS#10 CSR */
    @PostMapping("/sign/csr")
    public ApiResponse<Map<String, Object>> generateCsr(@RequestBody CsrRequest req) throws Exception {
        return ApiResponse.ok(certIssueService.generateCsr(req));
    }
}
