package com.smtool.module.tool;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 字节逆序控制器。
 */
@RestController
@RequestMapping("/api/byteorder")
public class ByteOrderController {

    private final ByteOrderService byteOrderService;

    public ByteOrderController(ByteOrderService byteOrderService) {
        this.byteOrderService = byteOrderService;
    }

    /** 字节逆序 / 大小端转换 */
    @PostMapping("/reverse")
    public ApiResponse<Map<String, Object>> reverse(@RequestBody ByteOrderRequest req) throws Exception {
        return ApiResponse.ok(byteOrderService.reverse(req));
    }
}
