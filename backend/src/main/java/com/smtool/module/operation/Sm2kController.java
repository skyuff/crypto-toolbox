package com.smtool.module.operation;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * SM2 加密 k 碰撞分析接口。
 */
@RestController
@RequestMapping("/api/sm2k")
public class Sm2kController {

    private final Sm2kService sm2kService;

    public Sm2kController(Sm2kService sm2kService) {
        this.sm2kService = sm2kService;
    }

    /** 在较小范围内碰撞随机数 k */
    @PostMapping("/collide")
    public ApiResponse<Map<String, Object>> collide(@RequestBody Sm2kRequest req) throws Exception {
        return ApiResponse.ok(sm2kService.collide(req));
    }

    /** 尝试根据碰撞出的 k 恢复明文 */
    @PostMapping("/recover")
    public ApiResponse<Map<String, Object>> recover(@RequestBody Sm2kRequest req) throws Exception {
        return ApiResponse.ok(sm2kService.recover(req));
    }
}
