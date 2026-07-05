package com.smtool.module.asymmetric;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * RSA 算法接口：密钥对生成、加解密、签名验签。
 */
@RestController
@RequestMapping("/api/rsa")
public class RSAController {

    private final RSAService rsaService;

    public RSAController(RSAService rsaService) {
        this.rsaService = rsaService;
    }

    @PostMapping("/keypair")
    public ApiResponse<Map<String, Object>> keypair(@RequestBody(required = false) RSARequest req) throws Exception {
        return ApiResponse.ok(rsaService.generateKeyPair(req));
    }

    @PostMapping("/encrypt")
    public ApiResponse<Map<String, Object>> encrypt(@RequestBody RSARequest req) throws Exception {
        return ApiResponse.ok(rsaService.encrypt(req));
    }

    @PostMapping("/decrypt")
    public ApiResponse<Map<String, Object>> decrypt(@RequestBody RSARequest req) throws Exception {
        return ApiResponse.ok(rsaService.decrypt(req));
    }

    @PostMapping("/sign")
    public ApiResponse<Map<String, Object>> sign(@RequestBody RSARequest req) throws Exception {
        return ApiResponse.ok(rsaService.sign(req));
    }

    @PostMapping("/verify")
    public ApiResponse<Map<String, Object>> verify(@RequestBody RSARequest req) throws Exception {
        return ApiResponse.ok(rsaService.verify(req));
    }
}
