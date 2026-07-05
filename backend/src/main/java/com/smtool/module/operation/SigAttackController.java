package com.smtool.module.operation;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 签名攻击校验：SM2 随机数重用攻击。
 */
@RestController
@RequestMapping("/api/sigattack")
public class SigAttackController {

    private final SigAttackService sigAttackService;

    public SigAttackController(SigAttackService sigAttackService) {
        this.sigAttackService = sigAttackService;
    }

    @PostMapping("/sm2-nonce-reuse")
    public ApiResponse<Map<String, Object>> sm2NonceReuse(@RequestBody SigAttackRequest req) throws Exception {
        return ApiResponse.ok(sigAttackService.sm2NonceReuse(req));
    }

    @PostMapping("/explain")
    public ApiResponse<String> explain() {
        return ApiResponse.ok(sigAttackService.explain());
    }
}
