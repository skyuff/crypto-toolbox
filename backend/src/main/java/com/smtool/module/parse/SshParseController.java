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
 * SSH 报文解析控制器。
 */
@RestController
@RequestMapping("/api/ssh")
public class SshParseController {

    private final SshParseService sshParseService;
    private final SshTrafficParseService sshTrafficParseService;

    public SshParseController(SshParseService sshParseService,
                              SshTrafficParseService sshTrafficParseService) {
        this.sshParseService = sshParseService;
        this.sshTrafficParseService = sshTrafficParseService;
    }

    /** 解析 SSH banner 或二进制包报文 */
    @PostMapping("/parse")
    public ApiResponse<Map<String, Object>> parse(@RequestBody SshParseRequest req) throws Exception {
        return ApiResponse.ok(sshParseService.parse(req));
    }

    /** 解析 SSH 流量包（pcap / pcapng） */
    @PostMapping("/traffic/parse")
    public ApiResponse<SshTrafficParseResult> parseTraffic(@RequestParam("file") MultipartFile file) throws Exception {
        return ApiResponse.ok(sshTrafficParseService.parse(file));
    }
}
