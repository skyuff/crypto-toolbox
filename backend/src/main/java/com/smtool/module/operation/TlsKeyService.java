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

    /** 确定 KeyBlock 长度：用户显式指定优先；否则按 hash 与 suiteType 动态计算。 */
    private int resolveKeyBlockLength(TlsKeyRequest req) {
        if (req.getKeyBlockLength() > 0) {
            return req.getKeyBlockLength();
        }
        String suiteType = req.getSuiteType();
        if (suiteType != null && "aead".equalsIgnoreCase(suiteType.trim())) {
            return AEAD_KEY_BLOCK_LENGTH;
        }
        int macLen = PrfService.newDigest(req.getHash()).getDigestSize();
        int[] keyIv = cipherKeyIvSizes(suiteType);
        return 2 * (macLen + keyIv[0] + keyIv[1]);
    }

    /** 根据 suiteType 推断对称密钥长度与 IV 长度（字节）。 */
    private int[] cipherKeyIvSizes(String suiteType) {
        String s = suiteType == null ? "" : suiteType.trim().toLowerCase();
        if (s.contains("sm4")) {
            return new int[]{16, 16};
        }
        if (s.contains("aes")) {
            int keyLen;
            if (s.contains("128")) {
                keyLen = 16;
            } else if (s.contains("192")) {
                keyLen = 24;
            } else if (s.contains("256")) {
                keyLen = 32;
            } else {
                keyLen = 16; // 默认 AES-128
            }
            return new int[]{keyLen, 16};
        }
        // 默认按 SM4-CBC 处理
        return new int[]{16, 16};
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
