package com.smtool.module.other;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 工作模式检测服务。
 * 对密文做无需密钥的静态合规检测：
 * 1) ECB 特征检测——按分组切块统计重复分组（重复分组是 ECB 模式泄露特征）；
 * 2) 长度对齐检测——分组密码密文应为分组大小整数倍；
 * 3) 两组密文对比——检测共同分组、相似度，辅助判断工作模式。
 */
@Service
public class CipherModeService {

    /** 执行密文静态检测 */
    public Map<String, Object> detect(CipherModeRequest req) {
        int blockSize = req.getBlockSize() <= 0 ? 16 : req.getBlockSize();
        byte[] data1 = decode(req.getCiphertext1(), req.getFormat1());
        byte[] data2 = decode(req.getCiphertext2(), req.getFormat2());

        List<Map<String, String>> findings = new ArrayList<>();

        // 单组检测：密文 1
        SingleResult r1 = analyzeSingle(data1, blockSize, "密文 1");
        findings.addAll(r1.findings);

        // 单组检测：密文 2
        SingleResult r2 = analyzeSingle(data2, blockSize, "密文 2");
        findings.addAll(r2.findings);

        // 两组密文对比分析
        CompareResult compare = analyzeCompare(data1, data2, blockSize);
        findings.addAll(compare.findings);

        Map<String, Object> map = new LinkedHashMap<>();
        map.put("blockSize", blockSize);
        map.put("blockCount1", r1.blockCount);
        map.put("duplicateBlocks1", r1.duplicateBlocks);
        map.put("isBlockAligned1", r1.blockAligned);
        map.put("suspectedEcb1", r1.suspectedEcb);
        map.put("blockCount2", r2.blockCount);
        map.put("duplicateBlocks2", r2.duplicateBlocks);
        map.put("isBlockAligned2", r2.blockAligned);
        map.put("suspectedEcb2", r2.suspectedEcb);
        map.put("commonBlocks", compare.commonBlocks);
        map.put("similarity", compare.similarity);
        map.put("findings", findings);
        return map;
    }

    /** 解析输入为字节数组 */
    private byte[] decode(String ciphertext, String format) {
        if (ciphertext == null || ciphertext.isBlank()) {
            return new byte[0];
        }
        return CodecUtil.decode(ciphertext,
                format == null || format.isBlank() ? "hex" : format);
    }

    /** 单组密文分析 */
    private SingleResult analyzeSingle(byte[] data, int blockSize, String name) {
        List<Map<String, String>> findings = new ArrayList<>();

        // 长度对齐检测
        boolean blockAligned = data.length > 0 && data.length % blockSize == 0;
        if (data.length == 0) {
            findings.add(finding("length", "warn", name + " 为空，无法进行有效检测"));
        } else if (!blockAligned) {
            findings.add(finding("length", "info",
                    name + " 长度 " + data.length + " 字节不是分组大小 " + blockSize
                            + " 的整数倍，可能是流模式(CTR/CFB/OFB)或含认证标签(GCM)的密文"));
        } else {
            findings.add(finding("length", "info",
                    name + " 长度 " + data.length + " 字节是分组大小 " + blockSize + " 的整数倍"));
        }

        // ECB 重复分组检测
        int blockCount = blockAligned ? data.length / blockSize : 0;
        int duplicateBlocks = 0;
        boolean suspectedEcb = false;
        if (blockAligned && blockCount > 1) {
            Set<String> seen = new HashSet<>();
            for (int i = 0; i < blockCount; i++) {
                byte[] block = Arrays.copyOfRange(data, i * blockSize, (i + 1) * blockSize);
                String key = CodecUtil.toHex(block);
                if (!seen.add(key)) {
                    duplicateBlocks++;
                }
            }
            suspectedEcb = duplicateBlocks > 0;
            if (suspectedEcb) {
                findings.add(finding("ecb", "risk",
                        name + " 检测到 " + duplicateBlocks + " 个重复分组，疑似 ECB 模式，存在模式泄露风险"));
            } else {
                findings.add(finding("ecb", "info",
                        name + " 未检测到重复分组，未见明显 ECB 模式泄露特征"));
            }
        } else if (blockAligned) {
            findings.add(finding("ecb", "info", name + " 分组数量不足，无法判断是否存在重复分组"));
        }

        SingleResult r = new SingleResult();
        r.blockCount = blockCount;
        r.duplicateBlocks = duplicateBlocks;
        r.blockAligned = blockAligned;
        r.suspectedEcb = suspectedEcb;
        r.findings = findings;
        return r;
    }

    /** 两组密文对比分析 */
    private CompareResult analyzeCompare(byte[] data1, byte[] data2, int blockSize) {
        List<Map<String, String>> findings = new ArrayList<>();
        CompareResult result = new CompareResult();

        if (data1.length == 0 || data2.length == 0) {
            findings.add(finding("compare", "info", "缺少一组密文，无法进行对比分析"));
            result.commonBlocks = 0;
            result.similarity = 0.0;
            result.findings = findings;
            return result;
        }

        boolean aligned1 = data1.length % blockSize == 0;
        boolean aligned2 = data2.length % blockSize == 0;
        if (!aligned1 || !aligned2) {
            findings.add(finding("compare", "info",
                    "至少一组密文长度未按分组大小对齐，对比结果仅供参考"));
        }

        Set<String> blocks1 = extractBlocks(data1, blockSize);
        Set<String> blocks2 = extractBlocks(data2, blockSize);

        Set<String> common = new HashSet<>(blocks1);
        common.retainAll(blocks2);
        result.commonBlocks = common.size();

        Set<String> union = new HashSet<>(blocks1);
        union.addAll(blocks2);
        result.similarity = union.isEmpty() ? 0.0
                : Math.round((double) common.size() / union.size() * 10000) / 100.0;

        if (result.commonBlocks > 0) {
            findings.add(finding("compare", "risk",
                    "两组密文存在 " + result.commonBlocks + " 个相同分组，分组相似度 " + result.similarity
                            + "%，在相同密钥 ECB/CBC 等模式下可能泄露明文结构"));
        } else {
            findings.add(finding("compare", "info",
                    "两组密文未发现相同分组，工作模式泄露特征不明显"));
        }

        result.findings = findings;
        return result;
    }

    /** 按分组大小提取所有分组（不完整的末尾分组丢弃） */
    private Set<String> extractBlocks(byte[] data, int blockSize) {
        Set<String> set = new HashSet<>();
        int count = data.length / blockSize;
        for (int i = 0; i < count; i++) {
            byte[] block = Arrays.copyOfRange(data, i * blockSize, (i + 1) * blockSize);
            set.add(CodecUtil.toHex(block));
        }
        return set;
    }

    /** 构造单条检测结论 */
    private Map<String, String> finding(String item, String level, String message) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("item", item);
        f.put("level", level);
        f.put("message", message);
        return f;
    }

    private static class SingleResult {
        int blockCount;
        int duplicateBlocks;
        boolean blockAligned;
        boolean suspectedEcb;
        List<Map<String, String>> findings;
    }

    private static class CompareResult {
        int commonBlocks;
        double similarity;
        List<Map<String, String>> findings;
    }
}
