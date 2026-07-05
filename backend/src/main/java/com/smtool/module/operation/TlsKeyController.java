package com.smtool.module.operation;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * TLS 1.2 密钥生成校验。
 */
@RestController
@RequestMapping("/api/tlskey")
public class TlsKeyController {

    private final TlsKeyService tlsKeyService;

    public TlsKeyController(TlsKeyService tlsKeyService) {
        this.tlsKeyService = tlsKeyService;
    }

    @PostMapping("/derive")
    public ApiResponse<Map<String, Object>> derive(@RequestBody TlsKeyRequest req) throws Exception {
        return ApiResponse.ok(tlsKeyService.derive(req));
    }
}
