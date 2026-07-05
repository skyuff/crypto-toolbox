package com.smtool.module.tool;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 逻辑运算控制器。
 */
@RestController
@RequestMapping("/api/logic")
public class LogicController {

    private final LogicService logicService;

    public LogicController(LogicService logicService) {
        this.logicService = logicService;
    }

    /** xor/and/or/not/shl/shr */
    @PostMapping("/calc")
    public ApiResponse<Map<String, Object>> calc(@RequestBody LogicRequest req) throws Exception {
        return ApiResponse.ok(logicService.calc(req));
    }
}
