package com.smtool.module.operation;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * TLS 1.2 / TLCP 密钥派生服务：
 * MasterSecret = PRF(PreMasterSecret, label1, ClientRandom || ServerRandom, 48)
 * KeyBlock     = PRF(MasterSecret, label2, ServerRandom || ClientRandom, keyBlockLength)
 * 内部复用 {@link PrfService#pHash} 实现。
 */
@Service
public class TlsKeyService {

    /** 分组套件默认 KeyBlock 长度：MAC*2 + ENC*2 + IV*2 = 20+20+16+16+16+16 = 104（SHA256/SM3 场景） */
    private static final int BLOCK_KEY_BLOCK_LENGTH = 104;
    /** AEAD（GCM）套件默认 KeyBlock 长度：KEY*2 + IV*2 = 16+16+4+4 = 40 */
    private static final int AEAD_KEY_BLOCK_LENGTH = 40;

    /** 执行 TLS 密钥派生 */
    public Map<String, Object> derive(TlsKeyRequest req) throws Exception {
        byte[] preMaster = decodePreMaster(req.getPreMasterSecret(), req.getPreMasterSecretFormat());
        byte[] clientRandom = normalizeAndDecodeHex(req.getClientRandom());
        byte[] serverRandom = normalizeAndDecodeHex(req.getServerRandom());
        String hash = req.getHash();

        // masterSecret = PRF(preMaster, label1, clientRandom || serverRandom, 48)
        byte[] masterSeed = concat(req.getLabel1().getBytes(StandardCharsets.UTF_8),
                concat(clientRandom, serverRandom));
        byte[] masterSecret = PrfService.pHash(
                PrfService.newDigest(hash), preMaster, masterSeed, 48);

        Map<String, Object> result = new HashMap<>();
        result.put("masterSecret", encode(masterSecret, req.getFormatOut()));
        result.put("masterSecretLength", masterSecret.length);
        result.put("hash", hash);

        // keyBlock = PRF(masterSecret, label2, serverRandom || clientRandom, keyBlockLength)
        if ("keyblock".equalsIgnoreCase(req.getOperation())) {
            int keyBlockLength = resolveKeyBlockLength(req);
            byte[] keySeed = concat(req.getLabel2().getBytes(StandardCharsets.UTF_8),
                    concat(serverRandom, clientRandom));
            byte[] keyBlock = PrfService.pHash(
                    PrfService.newDigest(hash), masterSecret, keySeed, keyBlockLength);
            result.put("keyBlock", encode(keyBlock, req.getFormatOut()));
            result.put("keyBlockLength", keyBlock.length);
        }

        return result;
    }

    /** 解析 PreMasterSecret，支持 hex / base64 / string */
    private byte[] decodePreMaster(String input, String format) {
        if (input == null || input.isBlank()) {
            return new byte[0];
        }
        if ("string".equalsIgnoreCase(format) || "utf8".equalsIgnoreCase(format)) {
            return input.getBytes(StandardCharsets.UTF_8);
        }
        String normalized = input;
        if ("hex".equalsIgnoreCase(format)) {
            normalized = normalizeHex(input);
        }
        return CodecUtil.decode(normalized, format);
    }

    /** 规整并解码十六进制字符串 */
    private byte[] normalizeAndDecodeHex(String hex) {
        return CodecUtil.decode(normalizeHex(hex), "hex");
    }

    /** 规整十六进制字符串：移除空白、冒号、0x 前缀；长度为奇数时前面补 0 */
    private String normalizeHex(String hex) {
        if (hex == null) return "";
        String s = hex.replaceAll("[\\s:,]", "").replaceAll("(?i)^0x", "");
        if (s.length() % 2 == 1) {
            s = "0" + s;
        }
        return s;
    }

    /** 确定 KeyBlock 长度 */
    private int resolveKeyBlockLength(TlsKeyRequest req) {
        if (req.getKeyBlockLength() > 0) {
            return req.getKeyBlockLength();
        }
        return "aead".equalsIgnoreCase(req.getSuiteType())
                ? AEAD_KEY_BLOCK_LENGTH
                : BLOCK_KEY_BLOCK_LENGTH;
    }

    /** 按指定格式编码输出 */
    private String encode(byte[] data, String format) {
        return CodecUtil.encode(data, format);
    }

    /** 字节数组拼接 */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}
