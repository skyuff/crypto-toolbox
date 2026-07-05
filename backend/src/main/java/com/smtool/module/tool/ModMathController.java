package com.smtool.module.tool;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 取模运算控制器。
 */
@RestController
@RequestMapping("/api/modmath")
public class ModMathController {

    private final ModMathService modMathService;

    public ModMathController(ModMathService modMathService) {
        this.modMathService = modMathService;
    }

    /** 模加/模减/模乘/模逆/模幂 */
    @PostMapping("/calc")
    public ApiResponse<Map<String, Object>> calc(@RequestBody ModMathRequest req) throws Exception {
        return ApiResponse.ok(modMathService.calc(req));
    }
}
