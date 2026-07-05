package com.smtool.module.operation;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 口令密钥派生 PBKDF2 控制器。
 */
@RestController
@RequestMapping("/api/pbkdf2")
public class Pbkdf2Controller {

    private final Pbkdf2Service pbkdf2Service;

    public Pbkdf2Controller(Pbkdf2Service pbkdf2Service) {
        this.pbkdf2Service = pbkdf2Service;
    }

    /** 执行 PBKDF2 密钥派生 */
    @PostMapping("/derive")
    public ApiResponse<Map<String, Object>> derive(@RequestBody Pbkdf2Request req) throws Exception {
        return ApiResponse.ok(pbkdf2Service.derive(req));
    }
}
