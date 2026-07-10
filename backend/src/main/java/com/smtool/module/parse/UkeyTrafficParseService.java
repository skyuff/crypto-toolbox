package com.smtool.module.parse;

import com.smtool.module.cert.DerInputUtil;
import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * UKey 流量包解析服务：
 * - 根据厂商选择进行针对性解析；
 * - “符合 0017 标准规范”按 GM/T 0017 APDU 流解析；
 * - 其他厂商先返回文件基本信息，并尝试按通用 APDU 流解析作为参考；
 * - 支持对随包上传的公钥/证书做基础解析。
 */
@Service
public class UkeyTrafficParseService {

    private final UkeyParseService ukeyParseService;
    private int maxPackets = 200;

    public UkeyTrafficParseService(UkeyParseService ukeyParseService) {
        this.ukeyParseService = ukeyParseService;
    }

    /**
     * 解析 UKey 流量包（使用默认 APDU 数量上限）。
     */
    public Map<String, Object> parse(String vendor, MultipartFile file, String keyCertInput, String keyCertMode) throws Exception {
        return parse(vendor, file, keyCertInput, keyCertMode, 0);
    }

    /**
     * 解析 UKey 流量包。
     *
     * @param maxPackets 单条流量最多解析的 APDU 个数；<=0 时使用默认 200。
     */
    public Map<String, Object> parse(String vendor, MultipartFile file, String keyCertInput, String keyCertMode, int maxPackets) throws Exception {
        int limit = maxPackets > 0 ? maxPackets : this.maxPackets;
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("vendor", vendor == null ? "" : vendor);

        byte[] trafficBytes = null;
        if (file != null && !file.isEmpty()) {
            trafficBytes = file.getBytes();
            result.put("fileName", file.getOriginalFilename());
            result.put("fileSize", trafficBytes.length);
            result.put("fileHexPreview", previewHex(trafficBytes, 128));
        } else {
            result.put("fileName", null);
            result.put("fileSize", 0);
        }

        if (keyCertInput != null && !keyCertInput.isBlank()) {
            result.put("keyCertInfo", parseKeyCert(keyCertInput, keyCertMode));
        }

        if (trafficBytes != null && trafficBytes.length > 0) {
            if (vendor != null && vendor.contains("0017")) {
                result.put("apduPackets", parseApduStream(trafficBytes, limit));
            } else {
                result.put("note", "当前厂商私有协议解析器暂未实现，已按通用 GM/T 0017 APDU 流做参考解析。");
                result.put("apduPackets", parseApduStream(trafficBytes, limit));
            }
        }

        return result;
    }

    /** 顺序解析字节流中的 command APDU */
    private List<Map<String, Object>> parseApduStream(byte[] data, int limit) {
        List<Map<String, Object>> list = new ArrayList<>();
        int pos = 0;
        while (pos < data.length && list.size() < limit) {
            int remaining = data.length - pos;
            if (remaining < 4) {
                Map<String, Object> leftover = new LinkedHashMap<>();
                leftover.put("index", list.size() + 1);
                leftover.put("offset", pos);
                leftover.put("note", "剩余字节不足 4 字节，无法构成 APDU 头");
                leftover.put("raw", CodecUtil.toHex(java.util.Arrays.copyOfRange(data, pos, data.length)));
                list.add(leftover);
                break;
            }
            byte[] apdu = java.util.Arrays.copyOfRange(data, pos, data.length);
            Map<String, Object> parsed = ukeyParseService.parseCommandApdu(apdu);
            int consumed = parsed.get("consumedBytes") instanceof Number n ? n.intValue() : 0;
            if (consumed <= 0) {
                parsed.put("parseError", "consumedBytes 非法（" + consumed + "），按 1 字节跳过以避免死循环");
                consumed = 1;
            }
            parsed.put("index", list.size() + 1);
            parsed.put("offset", pos);
            parsed.put("length", consumed);
            list.add(parsed);
            pos += consumed;
        }
        if (pos < data.length) {
            Map<String, Object> endNote = new LinkedHashMap<>();
            endNote.put("index", list.size() + 1);
            endNote.put("note", "仅解析前 " + limit + " 个 APDU，后续数据未处理（当前偏移 " + pos + "，总长度 " + data.length + "）");
            list.add(endNote);
        }
        return list;
    }

    private String previewHex(byte[] data, int maxBytes) {
        int len = Math.min(data.length, maxBytes);
        return CodecUtil.toHex(java.util.Arrays.copyOfRange(data, 0, len));
    }

    private Map<String, Object> parseKeyCert(String input, String mode) {
        Map<String, Object> info = new LinkedHashMap<>();
        try {
            byte[] der;
            String m = mode == null ? "auto" : mode.trim().toLowerCase();
            der = switch (m) {
                case "hex" -> CodecUtil.decode(input, "hex");
                case "base64" -> CodecUtil.decode(input, "base64");
                case "publickey", "certificate" -> DerInputUtil.toDer(input, "auto");
                default -> DerInputUtil.toDer(input, "auto");
            };

            // 优先尝试解析为 X.509 证书
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
                info.put("type", "X.509 证书");
                info.put("subject", cert.getSubjectX500Principal().toString());
                info.put("issuer", cert.getIssuerX500Principal().toString());
                info.put("serialNumber", cert.getSerialNumber().toString(16));
                info.put("notBefore", cert.getNotBefore().toString());
                info.put("notAfter", cert.getNotAfter().toString());
                info.put("sigAlgName", cert.getSigAlgName());
                info.put("publicKeyAlgorithm", cert.getPublicKey().getAlgorithm());
                info.put("derLength", der.length);
                return info;
            } catch (Exception ignore) {
                // 不是证书，继续尝试公钥
            }

            // 尝试解析为公钥
            PublicKey pk = tryParsePublicKey(der);
            if (pk != null) {
                info.put("type", "公钥");
                info.put("algorithm", pk.getAlgorithm());
                info.put("format", pk.getFormat());
                info.put("encodedLength", pk.getEncoded().length);
                info.put("derLength", der.length);
                return info;
            }

            info.put("type", "未知");
            info.put("note", "无法识别为证书或公钥，已按 DER 长度返回");
            info.put("derLength", der.length);
        } catch (Exception e) {
            info.put("type", "解析失败");
            info.put("error", e.getMessage());
        }
        return info;
    }

    private PublicKey tryParsePublicKey(byte[] der) {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        String[] algorithms = {"RSA", "EC", "SM2", "DSA"};
        for (String alg : algorithms) {
            try {
                KeyFactory kf = KeyFactory.getInstance(alg, "BC");
                return kf.generatePublic(spec);
            } catch (Exception ignore) {
                // 尝试下一种算法
            }
        }
        return null;
    }
}
