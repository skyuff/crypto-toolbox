package com.smtool.module.cert;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * ASN.1 解析接口。
 */
@RestController
@RequestMapping("/api/asn1")
public class Asn1ParseController {

    private final Asn1ParseService asn1ParseService;

    public Asn1ParseController(Asn1ParseService asn1ParseService) {
        this.asn1ParseService = asn1ParseService;
    }

    /** 将 DER 数据解析为 ASN.1 树结构 */
    @PostMapping("/parse")
    public ApiResponse<Map<String, Object>> parse(@RequestBody Asn1ParseRequest req) throws Exception {
        return ApiResponse.ok(asn1ParseService.parse(req));
    }
}
