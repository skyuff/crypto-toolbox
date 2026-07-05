package com.smtool.module.operation;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * TLS 1.2 PRF 运算校验。
 */
@RestController
@RequestMapping("/api/prf")
public class PrfController {

    private final PrfService prfService;

    public PrfController(PrfService prfService) {
        this.prfService = prfService;
    }

    @PostMapping("/compute")
    public ApiResponse<Map<String, Object>> compute(@RequestBody PrfRequest req) throws Exception {
        return ApiResponse.ok(prfService.compute(req));
    }
}
