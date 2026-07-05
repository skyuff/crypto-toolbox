package com.smtool.module.operation;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * GM/T KDF 运算校验。
 */
@RestController
@RequestMapping("/api/kdf")
public class KdfController {

    private final KdfService kdfService;

    public KdfController(KdfService kdfService) {
        this.kdfService = kdfService;
    }

    @PostMapping("/compute")
    public ApiResponse<Map<String, Object>> compute(@RequestBody KdfRequest req) throws Exception {
        return ApiResponse.ok(kdfService.compute(req));
    }
}
