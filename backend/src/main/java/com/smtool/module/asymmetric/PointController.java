package com.smtool.module.asymmetric;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 椭圆曲线点压缩/解压缩接口。
 */
@RestController
@RequestMapping("/api/point")
public class PointController {

    private final PointService pointService;

    public PointController(PointService pointService) {
        this.pointService = pointService;
    }

    @PostMapping("/compress")
    public ApiResponse<Map<String, Object>> compress(@RequestBody PointRequest req) {
        return ApiResponse.ok(pointService.compress(req));
    }

    @PostMapping("/compress-public-key")
    public ApiResponse<Map<String, Object>> compressPublicKey(@RequestBody PointRequest req) {
        return ApiResponse.ok(pointService.compressPublicKey(req));
    }

    @PostMapping("/decompress-public-key")
    public ApiResponse<Map<String, Object>> decompressPublicKey(@RequestBody PointRequest req) {
        return ApiResponse.ok(pointService.decompressPublicKey(req));
    }

    @GetMapping("/curve-params")
    public ApiResponse<Map<String, Object>> curveParams(@RequestParam(defaultValue = "sm2p256v1") String curve) {
        return ApiResponse.ok(pointService.curveParams(curve));
    }
}
