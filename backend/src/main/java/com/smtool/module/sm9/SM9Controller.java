package com.smtool.module.sm9;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * SM9 标识密码算法接口（GM/T 0044-2016）。
 * 支持曲线参数查询、密钥生成、签名验签、加解密、密钥封装、密钥协商。
 */
@RestController
@RequestMapping("/api/sm9")
public class SM9Controller {

    private final SM9Service sm9Service;

    public SM9Controller(SM9Service sm9Service) {
        this.sm9Service = sm9Service;
    }

    @GetMapping("/curve-params")
    public ApiResponse<Map<String, Object>> curveParams() {
        return ApiResponse.ok(sm9Service.curveParams());
    }

    @PostMapping("/master-key-pair")
    public ApiResponse<Map<String, Object>> masterKeyPair(@RequestBody Map<String, String> req) {
        String type = req.getOrDefault("type", "sign");
        return ApiResponse.ok(sm9Service.generateMasterKeyPair(type));
    }

    @PostMapping("/user-key")
    public ApiResponse<Map<String, Object>> userKey(@RequestBody Map<String, String> req) {
        String type = req.getOrDefault("type", "sign");
        String masterPrivateKey = req.get("masterPrivateKey");
        String userId = req.get("userId");
        return ApiResponse.ok(sm9Service.deriveUserKey(type, masterPrivateKey, userId));
    }

    @PostMapping("/sign")
    public ApiResponse<Map<String, Object>> sign(@RequestBody Map<String, String> req) {
        return ApiResponse.ok(sm9Service.sign(
                req.get("masterPublicKey"),
                req.get("userPrivateKey"),
                req.get("userId"),
                req.get("message")
        ));
    }

    @PostMapping("/verify")
    public ApiResponse<Map<String, Object>> verify(@RequestBody Map<String, String> req) {
        return ApiResponse.ok(sm9Service.verify(
                req.get("masterPublicKey"),
                req.get("userId"),
                req.get("message"),
                req.get("signature")
        ));
    }

    @PostMapping("/encrypt")
    public ApiResponse<Map<String, Object>> encrypt(@RequestBody Map<String, String> req) {
        return ApiResponse.ok(sm9Service.encrypt(
                req.get("masterPublicKey"),
                req.get("userId"),
                req.get("message"),
                req.getOrDefault("mode", "block")
        ));
    }

    @PostMapping("/decrypt")
    public ApiResponse<Map<String, Object>> decrypt(@RequestBody Map<String, String> req) {
        return ApiResponse.ok(sm9Service.decrypt(
                req.get("userPrivateKey"),
                req.get("userId"),
                req.get("ciphertext"),
                req.getOrDefault("mode", "block")
        ));
    }

    @PostMapping("/encapsulate")
    public ApiResponse<Map<String, Object>> encapsulate(@RequestBody Map<String, String> req) {
        return ApiResponse.ok(sm9Service.encapsulate(
                req.get("masterPublicKey"),
                req.get("userId")
        ));
    }

    @PostMapping("/decapsulate")
    public ApiResponse<Map<String, Object>> decapsulate(@RequestBody Map<String, String> req) {
        return ApiResponse.ok(sm9Service.decapsulate(
                req.get("userPrivateKey"),
                req.get("userId"),
                req.get("encapsulatedKey")
        ));
    }

    @PostMapping("/key-agreement")
    public ApiResponse<Map<String, Object>> keyAgreement(@RequestBody Map<String, String> req) {
        return ApiResponse.ok(sm9Service.keyAgreement(
                req.get("privateKeyA"),
                req.get("userIdA"),
                req.get("publicKeyB"),
                req.get("userIdB")
        ));
    }
}
