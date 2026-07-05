package com.smtool.module.asymmetric;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/ecdsa")
public class ECDSAController {

    private final ECDSAService ecdsaService;

    public ECDSAController(ECDSAService ecdsaService) {
        this.ecdsaService = ecdsaService;
    }

    @PostMapping("/keypair")
    public ApiResponse<Map<String, Object>> keypair(@RequestBody(required = false) ECDSARequest req) throws Exception {
        return ApiResponse.ok(ecdsaService.generateKeyPair(req));
    }

    @PostMapping("/sign")
    public ApiResponse<Map<String, Object>> sign(@RequestBody ECDSARequest req) throws Exception {
        return ApiResponse.ok(ecdsaService.sign(req));
    }

    @PostMapping("/verify")
    public ApiResponse<Map<String, Object>> verify(@RequestBody ECDSARequest req) throws Exception {
        return ApiResponse.ok(ecdsaService.verify(req));
    }

    @PostMapping("/encrypt")
    public ApiResponse<Map<String, Object>> encrypt(@RequestBody ECDSARequest req) throws Exception {
        return ApiResponse.ok(ecdsaService.encrypt(req));
    }

    @PostMapping("/decrypt")
    public ApiResponse<Map<String, Object>> decrypt(@RequestBody ECDSARequest req) throws Exception {
        return ApiResponse.ok(ecdsaService.decrypt(req));
    }
}
