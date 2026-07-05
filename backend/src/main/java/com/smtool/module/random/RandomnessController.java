package com.smtool.module.random;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 随机数检测接口（GM/T 0005 / NIST SP800-22，28 种检测方法）。
 */
@RestController
@RequestMapping("/api/randomness")
public class RandomnessController {

    private final RandomnessService randomnessService;

    public RandomnessController(RandomnessService randomnessService) {
        this.randomnessService = randomnessService;
    }

    /** 获取所有支持的检测方法列表 */
    @GetMapping("/methods")
    public ApiResponse<List<Map<String, Object>>> methods() {
        return ApiResponse.ok(randomnessService.listMethods());
    }

    /** 对输入的随机二进制数据执行选中的随机性检测 */
    @PostMapping("/test")
    public ApiResponse<Map<String, Object>> test(@RequestBody RandomnessRequest req) throws Exception {
        return ApiResponse.ok(randomnessService.test(req));
    }
}
