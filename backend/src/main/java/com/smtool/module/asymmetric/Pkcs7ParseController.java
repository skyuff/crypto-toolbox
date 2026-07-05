package com.smtool.module.asymmetric;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/pkcs7")
public class Pkcs7ParseController {

    private final Pkcs7ParseService pkcs7ParseService;

    public Pkcs7ParseController(Pkcs7ParseService pkcs7ParseService) {
        this.pkcs7ParseService = pkcs7ParseService;
    }

    @PostMapping("/sign")
    public ApiResponse<Map<String, Object>> sign(@RequestBody Pkcs7ParseRequest req) throws Exception {
        return ApiResponse.ok(pkcs7ParseService.sign(req));
    }

    @PostMapping("/verify")
    public ApiResponse<Map<String, Object>> verify(@RequestBody Pkcs7ParseRequest req) throws Exception {
        return ApiResponse.ok(pkcs7ParseService.verify(req));
    }

    @PostMapping("/parse")
    public ApiResponse<Map<String, Object>> parse(@RequestBody Pkcs7ParseRequest req) throws Exception {
        return ApiResponse.ok(pkcs7ParseService.parse(req));
    }
}
