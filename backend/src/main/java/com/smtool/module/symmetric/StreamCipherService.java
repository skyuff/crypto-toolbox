package com.smtool.module.symmetric;

import com.smtool.util.CodecUtil;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.Zuc128Engine;
import org.bouncycastle.crypto.engines.Zuc256Engine;
import org.bouncycastle.crypto.macs.Zuc128Mac;
import org.bouncycastle.crypto.macs.Zuc256Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * 序列（流）密码服务：ZUC-128 / ZUC-256 加解密与完整性 MAC。
 * ZUC 为对称序列密码，加解密操作相同（明密文与密钥流异或），operation 仅表示语义。
 */
@Service
public class StreamCipherService {

    /**
     * ZUC 加解密。ZUC-128 使用 16 字节密钥 + 16 字节 IV；
     * ZUC-256 使用 32 字节密钥 + 25 字节 IV。
     */
    public Map<String, Object> crypt(SymmetricRequest req) throws Exception {
        String alg = normalize(req.getAlgorithm());
        byte[] key = CodecUtil.decode(req.getKey(), req.getKeyFormat());
        byte[] iv = CodecUtil.decode(req.getIv(), req.getIvFormat());
        byte[] input = CodecUtil.decode(req.getInput(), req.getInputFormat());

        StreamCipher engine;
        if ("ZUC-256".equals(alg)) {
            validate(alg, key.length, iv.length);
            engine = new Zuc256Engine();
        } else {
            validate(alg, key.length, iv.length);
            engine = new Zuc128Engine();
        }
        engine.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] out = new byte[input.length];
        engine.processBytes(input, 0, input.length, out, 0);

        Map<String, Object> result = new HashMap<>();
        result.put("algorithm", alg);
        result.put("output", CodecUtil.encode(out, req.getOutputFormat()));
        result.put("outputLength", out.length);
        return result;
    }

    /**
     * ZUC 完整性 MAC（128-EIA3 / ZUC-256 MAC）。
     * ZUC-128 MAC 输出 32 bit（4 字节）；ZUC-256 MAC 支持 32/64/128 bit，默认 128 bit。
     */
    public Map<String, Object> mac(SymmetricRequest req) throws Exception {
        String alg = normalize(req.getAlgorithm());
        byte[] key = CodecUtil.decode(req.getKey(), req.getKeyFormat());
        byte[] iv = CodecUtil.decode(req.getIv(), req.getIvFormat());
        byte[] input = CodecUtil.decode(req.getInput(), req.getInputFormat());

        org.bouncycastle.crypto.Mac mac;
        int macBits;
        if ("ZUC-256".equals(alg)) {
            validate(alg, key.length, iv.length);
            // tagLength 复用请求字段：32 / 64 / 128，默认 128
            macBits = req.getTagLength() == null ? 128 : req.getTagLength();
            if (macBits != 32 && macBits != 64 && macBits != 128) {
                throw new IllegalArgumentException("ZUC-256 MAC 长度只能为 32/64/128 bit");
            }
            mac = new Zuc256Mac(macBits);
        } else {
            validate(alg, key.length, iv.length);
            macBits = 32;
            mac = new Zuc128Mac();
        }
        mac.init(new ParametersWithIV(new KeyParameter(key), iv));
        mac.update(input, 0, input.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);

        Map<String, Object> result = new HashMap<>();
        result.put("algorithm", alg);
        result.put("macBits", macBits);
        result.put("mac", CodecUtil.encode(out, req.getOutputFormat()));
        result.put("macLength", out.length);
        return result;
    }

    private String normalize(String alg) {
        String a = alg == null ? "" : alg.trim().toUpperCase().replace("_", "-");
        return switch (a) {
            case "ZUC-256", "ZUC256" -> "ZUC-256";
            case "ZUC", "ZUC-128", "ZUC128" -> "ZUC-128";
            default -> throw new IllegalArgumentException("不支持的序列密码算法: " + alg);
        };
    }

    private void validate(String alg, int keyLen, int ivLen) {
        if ("ZUC-256".equals(alg)) {
            if (keyLen != 32) throw new IllegalArgumentException("ZUC-256 密钥应为 32 字节，实际 " + keyLen);
            if (ivLen != 25) throw new IllegalArgumentException("ZUC-256 IV 应为 25 字节，实际 " + ivLen);
        } else {
            if (keyLen != 16) throw new IllegalArgumentException("ZUC-128 密钥应为 16 字节，实际 " + keyLen);
            if (ivLen != 16) throw new IllegalArgumentException("ZUC-128 IV 应为 16 字节，实际 " + ivLen);
        }
    }
}
