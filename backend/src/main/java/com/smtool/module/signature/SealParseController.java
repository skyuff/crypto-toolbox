package com.smtool.module.signature;

import com.smtool.common.ApiResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

/**
 * 电子签章（GM/T 0031 / PDF / OFD）解析与校验控制器。
 */
@RestController
@RequestMapping("/api/seal")
public class SealParseController {

    private final SealParseService sealParseService;

    public SealParseController(SealParseService sealParseService) {
        this.sealParseService = sealParseService;
    }

    /** 解析电子签章 ASN.1 结构并启发式提取可读字段 */
    @PostMapping("/parse")
    public ApiResponse<Map<String, Object>> parse(@RequestBody SealParseRequest req) throws Exception {
        return ApiResponse.ok(sealParseService.parse(req));
    }

    /** 上传 OFD / PDF 文件进行电子签章真实校验 */
    @PostMapping("/verify-file")
    public ApiResponse<SealVerifyResult> verifyFile(@RequestParam("file") MultipartFile file) throws Exception {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("请上传签章文件");
        }
        if (file.getSize() > 10 * 1024 * 1024) {
            throw new IllegalArgumentException("单个文件大小不超过 10 MB");
        }
        return ApiResponse.ok(sealParseService.verifyFile(file.getBytes()));
    }
}
