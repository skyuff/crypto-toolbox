package com.smtool.module.tool;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 大数运算控制器。
 */
@RestController
@RequestMapping("/api/bignumber")
public class BigNumberController {

    private final BigNumberService bigNumberService;

    public BigNumberController(BigNumberService bigNumberService) {
        this.bigNumberService = bigNumberService;
    }

    /** 大数四则、幂、gcd 等运算 */
    @PostMapping("/calc")
    public ApiResponse<Map<String, Object>> calc(@RequestBody BigNumberRequest req) throws Exception {
        return ApiResponse.ok(bigNumberService.calc(req));
    }
}
