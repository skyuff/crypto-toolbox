package com.smtool.module.hash;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * 哈希算法校验：哈希、MAC、哈希猜测。
 */
@RestController
@RequestMapping("/api/hash")
public class HashController {

    private final HashService hashService;
    private final MacService macService;

    public HashController(HashService hashService, MacService macService) {
        this.hashService = hashService;
        this.macService = macService;
    }

    @GetMapping("/algorithms")
    public ApiResponse<Collection<String>> algorithms() {
        return ApiResponse.ok(hashService.supportedAlgorithms());
    }

    @PostMapping("/digest")
    public ApiResponse<Map<String, Object>> digest(@RequestBody HashRequest req) throws Exception {
        return ApiResponse.ok(hashService.digest(req));
    }

    @PostMapping("/digest/all")
    public ApiResponse<List<Map<String, Object>>> digestAll(@RequestBody HashRequest req) throws Exception {
        return ApiResponse.ok(hashService.digestAll(req));
    }

    @GetMapping("/guess")
    public ApiResponse<Map<String, Object>> guess(@RequestParam String hash) {
        return ApiResponse.ok(hashService.guess(hash));
    }

    @PostMapping("/mac")
    public ApiResponse<Map<String, Object>> mac(@RequestBody MacRequest req) throws Exception {
        return ApiResponse.ok(macService.compute(req));
    }
}
