package com.smtool.module.symmetric;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 对称密码校验：分组密码、序列密码、GCM。
 */
@RestController
@RequestMapping("/api/symmetric")
public class SymmetricController {

    private final BlockCipherService blockCipherService;
    private final GcmCipherService gcmCipherService;
    private final StreamCipherService streamCipherService;

    public SymmetricController(BlockCipherService blockCipherService,
                              GcmCipherService gcmCipherService,
                              StreamCipherService streamCipherService) {
        this.blockCipherService = blockCipherService;
        this.gcmCipherService = gcmCipherService;
        this.streamCipherService = streamCipherService;
    }

    @PostMapping("/block")
    public ApiResponse<Map<String, Object>> block(@RequestBody SymmetricRequest req) throws Exception {
        return ApiResponse.ok(blockCipherService.crypt(req));
    }

    @PostMapping("/gcm")
    public ApiResponse<Map<String, Object>> gcm(@RequestBody SymmetricRequest req) throws Exception {
        return ApiResponse.ok(gcmCipherService.crypt(req));
    }

    @PostMapping("/stream")
    public ApiResponse<Map<String, Object>> stream(@RequestBody SymmetricRequest req) throws Exception {
        return ApiResponse.ok(streamCipherService.crypt(req));
    }

    @PostMapping("/stream/mac")
    public ApiResponse<Map<String, Object>> streamMac(@RequestBody SymmetricRequest req) throws Exception {
        return ApiResponse.ok(streamCipherService.mac(req));
    }
}
