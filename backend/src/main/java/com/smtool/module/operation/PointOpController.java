package com.smtool.module.operation;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 椭圆曲线点运算控制器。
 * 注意：路由使用 /api/point-op，避免与已有 /api/point 冲突。
 */
@RestController
@RequestMapping("/api/point-op")
public class PointOpController {

    private final PointOpService pointOpService;

    public PointOpController(PointOpService pointOpService) {
        this.pointOpService = pointOpService;
    }

    /** 点运算：基点倍乘 / 点乘 / 点加 / 倍点 */
    @PostMapping("/calc")
    public ApiResponse<Map<String, Object>> calc(@RequestBody PointOpRequest req) throws Exception {
        return ApiResponse.ok(pointOpService.calc(req));
    }
}
