package com.smtool.module.parse;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * TLS 报文解析控制器。
 */
@RestController
@RequestMapping("/api/tls")
public class TlsParseController {

    private final TlsParseService tlsParseService;

    public TlsParseController(TlsParseService tlsParseService) {
        this.tlsParseService = tlsParseService;
    }

    /** 解析 TLS Record + Handshake 报文 */
    @PostMapping("/parse")
    public ApiResponse<Map<String, Object>> parse(@RequestBody TlsParseRequest req) throws Exception {
        return ApiResponse.ok(tlsParseService.parse(req));
    }
}
