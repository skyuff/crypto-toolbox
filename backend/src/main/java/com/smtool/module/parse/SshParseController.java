package com.smtool.module.parse;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * SSH 报文解析控制器。
 */
@RestController
@RequestMapping("/api/ssh")
public class SshParseController {

    private final SshParseService sshParseService;

    public SshParseController(SshParseService sshParseService) {
        this.sshParseService = sshParseService;
    }

    /** 解析 SSH banner 或二进制包报文 */
    @PostMapping("/parse")
    public ApiResponse<Map<String, Object>> parse(@RequestBody SshParseRequest req) throws Exception {
        return ApiResponse.ok(sshParseService.parse(req));
    }
}
