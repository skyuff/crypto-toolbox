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
 * IPSec / IKE 报文解析控制器。
 */
@RestController
@RequestMapping("/api/ipsec")
public class IpsecParseController {

    private final IpsecParseService ipsecParseService;
    private final IpsecTrafficParseService ipsecTrafficParseService;

    public IpsecParseController(IpsecParseService ipsecParseService,
                                IpsecTrafficParseService ipsecTrafficParseService) {
        this.ipsecParseService = ipsecParseService;
        this.ipsecTrafficParseService = ipsecTrafficParseService;
    }

    /** 解析 IKE (ISAKMP) 报文头与 payload 链 */
    @PostMapping("/parse")
    public ApiResponse<Map<String, Object>> parse(@RequestBody IpsecParseRequest req) throws Exception {
        return ApiResponse.ok(ipsecParseService.parse(req));
    }

    /** 解析 IPSEC 流量包（pcap / pcapng），可选上传 IKE 解密密钥日志或国密证书链补录 */
    @PostMapping("/traffic/parse")
    public ApiResponse<IpsecTrafficParseResult> parseTraffic(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "keyLogFile", required = false) MultipartFile keyLogFile,
            @RequestParam(value = "initiatorCertFiles", required = false) MultipartFile[] initiatorCertFiles,
            @RequestParam(value = "responderCertFiles", required = false) MultipartFile[] responderCertFiles) throws Exception {
        return ApiResponse.ok(ipsecTrafficParseService.parse(file, keyLogFile, initiatorCertFiles, responderCertFiles));
    }
}
