package com.smtool.module.parse;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

/**
 * TLS 报文解析控制器。
 */
@RestController
@RequestMapping("/api/tls")
public class TlsParseController {

    private final TlsParseService tlsParseService;
    private final TlsTrafficParseService tlsTrafficParseService;

    public TlsParseController(TlsParseService tlsParseService,
                              TlsTrafficParseService tlsTrafficParseService) {
        this.tlsParseService = tlsParseService;
        this.tlsTrafficParseService = tlsTrafficParseService;
    }

    /** 解析 TLS Record + Handshake 报文 */
    @PostMapping("/parse")
    public ApiResponse<Map<String, Object>> parse(@RequestBody TlsParseRequest req) throws Exception {
        return ApiResponse.ok(tlsParseService.parse(req));
    }

    /** 解析 TLS 流量包（pcap / pcapng） */
    @PostMapping("/traffic/parse")
    public ApiResponse<TlsTrafficParseResult> parseTraffic(@RequestParam("file") MultipartFile file) throws Exception {
        return ApiResponse.ok(tlsTrafficParseService.parse(file));
    }
}
