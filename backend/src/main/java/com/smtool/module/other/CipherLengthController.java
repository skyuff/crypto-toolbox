package com.smtool.module.other;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 密文长度分析控制器。
 */
@RestController
@RequestMapping("/api/cipher-length")
public class CipherLengthController {

    private final CipherLengthService cipherLengthService;

    public CipherLengthController(CipherLengthService cipherLengthService) {
        this.cipherLengthService = cipherLengthService;
    }

    /** 根据输入数据长度分析可能对应的算法 */
    @PostMapping("/analyze")
    public ApiResponse<Map<String, Object>> analyze(@RequestBody CipherLengthRequest req) throws Exception {
        return ApiResponse.ok(cipherLengthService.analyze(req));
    }

    /** 获取全部算法分组与安全强度清单 */
    @GetMapping("/algorithms")
    public ApiResponse<List<Map<String, Object>>> algorithms() {
        return ApiResponse.ok(cipherLengthService.algorithms());
    }
}
