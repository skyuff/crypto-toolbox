package com.smtool.module.parse;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * IPSec / IKE 报文解析控制器。
 */
@RestController
@RequestMapping("/api/ipsec")
public class IpsecParseController {

    private final IpsecParseService ipsecParseService;

    public IpsecParseController(IpsecParseService ipsecParseService) {
        this.ipsecParseService = ipsecParseService;
    }

    /** 解析 IKE (ISAKMP) 报文头与 payload 链 */
    @PostMapping("/parse")
    public ApiResponse<Map<String, Object>> parse(@RequestBody IpsecParseRequest req) throws Exception {
        return ApiResponse.ok(ipsecParseService.parse(req));
    }
}
