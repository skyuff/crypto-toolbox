package com.smtool.module.sm2;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * SM2 算法校验。
 */
@RestController
@RequestMapping("/api/sm2")
public class SM2Controller {

    private final SM2Service sm2Service;

    public SM2Controller(SM2Service sm2Service) {
        this.sm2Service = sm2Service;
    }

    @PostMapping("/keypair")
    public ApiResponse<Map<String, Object>> keypair(@RequestBody(required = false) SM2Request req) {
        return ApiResponse.ok(sm2Service.generateKeyPair());
    }

    /** sm2p256v1 曲线参数 */
    @GetMapping("/curve")
    public ApiResponse<Map<String, Object>> curve() {
        return ApiResponse.ok(sm2Service.curveParams());
    }

    /** 由私钥计算公钥 */
    @PostMapping("/publicKey")
    public ApiResponse<Map<String, Object>> publicKey(@RequestBody SM2Request req) {
        return ApiResponse.ok(sm2Service.computePublicKey(req));
    }

    /** 验证公钥合法性 */
    @PostMapping("/validateKey")
    public ApiResponse<Map<String, Object>> validateKey(@RequestBody SM2Request req) {
        return ApiResponse.ok(sm2Service.validatePublicKey(req));
    }

    /** 计算 e 值（Z 值 + e 值） */
    @PostMapping("/eValue")
    public ApiResponse<Map<String, Object>> eValue(@RequestBody SM2Request req) {
        return ApiResponse.ok(sm2Service.computeE(req));
    }

    /** 私钥解析（PEM/hex -> 私钥 + 公钥） */
    @PostMapping("/parsePrivateKey")
    public ApiResponse<Map<String, Object>> parsePrivateKey(@RequestBody SM2Request req) throws Exception {
        return ApiResponse.ok(sm2Service.parsePrivateKeyInput(req));
    }

    /** 签名值 R||S <-> DER 转换 */
    @PostMapping("/convertSignature")
    public ApiResponse<Map<String, Object>> convertSignature(@RequestBody SM2Request req) throws Exception {
        return ApiResponse.ok(sm2Service.convertSignature(req));
    }

    /** 密文 裸拼接 <-> DER 结构 转换 */
    @PostMapping("/convertCipher")
    public ApiResponse<Map<String, Object>> convertCipher(@RequestBody SM2Request req) throws Exception {
        return ApiResponse.ok(sm2Service.convertCipher(req));
    }

    /** 两组数据验签 */
    @PostMapping("/verifyTwo")
    public ApiResponse<Map<String, Object>> verifyTwo(@RequestBody SM2Request req) throws Exception {
        return ApiResponse.ok(sm2Service.verifyTwo(req));
    }

    /** 验签并攻击（重复 k 恢复私钥） */
    @PostMapping("/verifyAndAttack")
    public ApiResponse<Map<String, Object>> verifyAndAttack(@RequestBody SM2Request req) throws Exception {
        return ApiResponse.ok(sm2Service.verifyAndAttack(req));
    }

    @PostMapping("/encrypt")
    public ApiResponse<Map<String, Object>> encrypt(@RequestBody SM2Request req) throws Exception {
        return ApiResponse.ok(sm2Service.encrypt(req));
    }

    @PostMapping("/decrypt")
    public ApiResponse<Map<String, Object>> decrypt(@RequestBody SM2Request req) throws Exception {
        return ApiResponse.ok(sm2Service.decrypt(req));
    }

    @PostMapping("/sign")
    public ApiResponse<Map<String, Object>> sign(@RequestBody SM2Request req) throws Exception {
        return ApiResponse.ok(sm2Service.sign(req));
    }

    @PostMapping("/verify")
    public ApiResponse<Map<String, Object>> verify(@RequestBody SM2Request req) throws Exception {
        return ApiResponse.ok(sm2Service.verify(req));
    }

    /** SM2 密钥交换（GM/T 0003.3） */
    @PostMapping("/keyExchange")
    public ApiResponse<Map<String, Object>> keyExchange(@RequestBody SM2Request req) throws Exception {
        return ApiResponse.ok(sm2Service.keyExchange(req));
    }

    /** SM2 两方协同签名 */
    @PostMapping("/coSign")
    public ApiResponse<Map<String, Object>> coSign(@RequestBody SM2Request req) throws Exception {
        return ApiResponse.ok(sm2Service.coSign(req));
    }
}
