package com.smtool.module.other;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 工作模式检测控制器。
 */
@RestController
@RequestMapping("/api/cipher-mode")
public class CipherModeController {

    private final CipherModeService cipherModeService;

    public CipherModeController(CipherModeService cipherModeService) {
        this.cipherModeService = cipherModeService;
    }

    /** 密文合规静态检测（无需密钥） */
    @PostMapping("/detect")
    public ApiResponse<Map<String, Object>> detect(@RequestBody CipherModeRequest req) throws Exception {
        return ApiResponse.ok(cipherModeService.detect(req));
    }
}
