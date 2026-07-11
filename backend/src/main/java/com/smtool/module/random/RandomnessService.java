package com.smtool.module.random;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * 随机数检测服务：实现 GM/T 0005 / NIST SP800-22 中的 28 种随机性检测方法。
 *
 * <p>纯本地计算，不依赖外部库；其中 erfc / erf / igamc 等采用 Abramowitz-Stegun / Numerical Recipes 近似自行实现。
 * 每项检测的判定阈值统一取显著性水平 α = 0.01，即 pValue >= 0.01 为通过。</p>
 */
@Service
public class RandomnessService {

    /** 显著性水平 α */
    private static final double ALPHA = 0.01;

    /** 28 种检测方法元数据（编号、名称、描述） */
    private static final List<MethodMeta> METHODS = List.of(
            new MethodMeta(1, "单比特频数检测", "检测序列中0和1的出现次数是否近似相等。"),
            new MethodMeta(2, "块内频数检测", "检测序列中任意长度子块内1的比例是否接近1/2。"),
            new MethodMeta(3, "游程检测", "检测序列中0游程和1游程总数是否满足随机性要求。"),
            new MethodMeta(4, "块内最长游程检测", "检测子块内最长1游程的分布是否符合随机序列期望。"),
            new MethodMeta(5, "二元矩阵秩检测", "检测序列中子矩阵的秩分布，评估线性相关性。"),
            new MethodMeta(6, "重叠模板匹配检测", "检测特定模板在序列中重叠出现的次数。"),
            new MethodMeta(7, "累积和检测（前向）", "检测序列前向累积和偏离零的程度。"),
            new MethodMeta(8, "累积和检测（后向）", "检测序列后向累积和偏离零的程度。"),
            new MethodMeta(9, "随机游程检测", "检测序列中部分和的随机游程特征。"),
            new MethodMeta(10, "随机游程变量检测", "检测序列中部分和在各状态停留的次数。"),
            new MethodMeta(11, "扑克检测 m=4", "将序列分成长度为4的子段，检测各类模式出现频率。"),
            new MethodMeta(12, "扑克检测 m=8", "将序列分成长度为8的子段，检测各类模式出现频率。"),
            new MethodMeta(13, "序列检测 m=2", "检测序列中长度为2的重叠模式出现频率。"),
            new MethodMeta(14, "序列检测 m=3", "检测序列中长度为3的重叠模式出现频率。"),
            new MethodMeta(15, "序列检测 m=4", "检测序列中长度为4的重叠模式出现频率。"),
            new MethodMeta(16, "序列检测 m=5", "检测序列中长度为5的重叠模式出现频率。"),
            new MethodMeta(17, "近似熵检测 m=2", "检测长度为2的重叠模式与自身连接模式的近似熵。"),
            new MethodMeta(18, "近似熵检测 m=3", "检测长度为3的重叠模式与自身连接模式的近似熵。"),
            new MethodMeta(19, "近似熵检测 m=4", "检测长度为4的重叠模式与自身连接模式的近似熵。"),
            new MethodMeta(20, "非重叠模板匹配检测 B=000000001", "检测非重叠模板000000001在子块中的出现次数。"),
            new MethodMeta(21, "非重叠模板匹配检测 B=000000011", "检测非重叠模板000000011在子块中的出现次数。"),
            new MethodMeta(22, "近似熵检测 m=5", "检测长度为5的重叠模式与自身连接模式的近似熵。"),
            new MethodMeta(23, "非重叠模板匹配检测 B=000000101", "检测非重叠模板000000101在子块中的出现次数。"),
            new MethodMeta(24, "线性复杂度检测 m=500", "检测子块线性复杂度的分布，m=500。"),
            new MethodMeta(25, "线性复杂度检测 m=1000", "检测子块线性复杂度的分布，m=1000。"),
            new MethodMeta(26, "非重叠模板匹配检测 B=000001001", "检测非重叠模板000001001在子块中的出现次数。"),
            new MethodMeta(27, "Maurer通用统计检测 L=7,Q=1280", "检测序列的可压缩性，L=7，Q=1280。"),
            new MethodMeta(28, "离散傅里叶变换检测", "检测序列频谱中峰值的分布，识别周期性模式。")
    );

    /** 执行检测。 */
    public Map<String, Object> test(RandomnessRequest req) {
        byte[] data = CodecUtil.decode(req.getInput(), req.getFormat());
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("输入数据为空，无法进行随机性检测");
        }
        int[] bits = toBits(data);
        int n = bits.length;
        if (n < 8) {
            throw new IllegalArgumentException("输入数据不足 1 字节，无法进行随机性检测");
        }

        Set<Integer> selected = new HashSet<>();
        if (req.getSelectedMethods() != null) {
            selected.addAll(req.getSelectedMethods());
        }
        boolean all = selected.isEmpty();

        List<Map<String, Object>> tests = new ArrayList<>();
        for (MethodMeta meta : METHODS) {
            if (!all && !selected.contains(meta.id)) {
                continue;
            }
            Map<String, Object> r = runMethod(meta.id, bits, n);
            if (r != null) {
                r.put("id", meta.id);
                r.put("name", meta.name);
                r.put("description", meta.description);
                tests.add(r);
            }
        }

        long applicableCount = tests.stream()
                .filter(t -> Boolean.TRUE.equals(t.get("applicable")))
                .count();
        long passCount = tests.stream()
                .filter(t -> Boolean.TRUE.equals(t.get("applicable")) && Boolean.TRUE.equals(t.get("pass")))
                .count();
        double passRate = applicableCount == 0 ? 0.0 : (double) passCount / applicableCount;
        boolean overallPass = applicableCount == 0 || passRate >= 0.95;

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("bitLength", n);
        result.put("overallPass", overallPass);
        result.put("passRate", passRate);
        result.put("applicableCount", applicableCount);
        result.put("passCount", passCount);
        result.put("tests", tests);
        return result;
    }

    /** 获取所有检测方法元数据（供前端展示）。 */
    public List<Map<String, Object>> listMethods() {
        List<Map<String, Object>> list = new ArrayList<>();
        for (MethodMeta meta : METHODS) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", meta.id);
            m.put("name", meta.name);
            m.put("description", meta.description);
            list.add(m);
        }
        return list;
    }

    private Map<String, Object> runMethod(int id, int[] bits, int n) {
        return switch (id) {
            case 1 -> monobit(bits, n);
            case 2 -> frequencyWithinBlock(bits, n);
            case 3 -> runs(bits, n);
            case 4 -> longestRunOfOnes(bits, n);
            case 5 -> binaryMatrixRank(bits, n);
            case 6 -> overlappingTemplateMatching(bits, n);
            case 7 -> cumulativeSums(bits, n, true);
            case 8 -> cumulativeSums(bits, n, false);
            case 9 -> randomExcursions(bits, n);
            case 10 -> randomExcursionsVariant(bits, n);
            case 11 -> poker(bits, n, 4);
            case 12 -> poker(bits, n, 8);
            case 13 -> serial(bits, n, 2);
            case 14 -> serial(bits, n, 3);
            case 15 -> serial(bits, n, 4);
            case 16 -> serial(bits, n, 5);
            case 17 -> approximateEntropy(bits, n, 2);
            case 18 -> approximateEntropy(bits, n, 3);
            case 19 -> approximateEntropy(bits, n, 4);
            case 20 -> nonOverlappingTemplateMatching(bits, n, "000000001");
            case 21 -> nonOverlappingTemplateMatching(bits, n, "000000011");
            case 22 -> approximateEntropy(bits, n, 5);
            case 23 -> nonOverlappingTemplateMatching(bits, n, "000000101");
            case 24 -> linearComplexity(bits, n, 500);
            case 25 -> linearComplexity(bits, n, 1000);
            case 26 -> nonOverlappingTemplateMatching(bits, n, "000001001");
            case 27 -> maurerUniversal(bits, n, 7, 1280);
            case 28 -> discreteFourierTransform(bits, n);
            default -> null;
        };
    }

    // ==================== 各项检测实现 ====================

    /** 1) 单比特频数检测（Monobit）。 */
    private Map<String, Object> monobit(int[] bits, int n) {
        long s = 0;
        for (int b : bits) {
            s += (b == 1) ? 1 : -1;
        }
        double sObs = Math.abs(s) / Math.sqrt(n);
        double pValue = erfc(sObs / Math.sqrt(2.0));
        String detail = "0/1 个数差绝对值|S|=" + Math.abs(s) + "，统计量 sObs=" + fmt(sObs);
        return item(pValue, detail);
    }

    /** 2) 块内频数检测（Frequency within Block）。 */
    private Map<String, Object> frequencyWithinBlock(int[] bits, int n) {
        int m = 100;
        if (n < m) {
            m = Math.max(1, n / 8);
            if (m < 1) m = n;
        }
        int numBlocks = n / m;
        if (numBlocks < 1) {
            numBlocks = 1;
            m = n;
        }
        double sum = 0.0;
        for (int i = 0; i < numBlocks; i++) {
            int ones = 0;
            for (int j = 0; j < m; j++) {
                ones += bits[i * m + j];
            }
            double pi = (double) ones / m;
            sum += (pi - 0.5) * (pi - 0.5);
        }
        double chiSq = 4.0 * m * sum;
        double pValue = igamc(numBlocks / 2.0, chiSq / 2.0);
        String detail = "块大小M=" + m + "，块数N=" + numBlocks + "，卡方χ²=" + fmt(chiSq);
        return item(pValue, detail);
    }

    /** 3) 游程检测（Runs Test）。 */
    private Map<String, Object> runs(int[] bits, int n) {
        int ones = 0;
        for (int b : bits) {
            ones += b;
        }
        double pi = (double) ones / n;
        double tau = 2.0 / Math.sqrt(n);
        if (Math.abs(pi - 0.5) >= tau) {
            String detail = "序列 1 的比例 π=" + fmt(pi) + " 不满足前置条件(|π-0.5|<" + fmt(tau) + ")，游程检测不适用";
            return item(null, detail, false);
        }
        int vn = 1;
        for (int i = 1; i < n; i++) {
            if (bits[i] != bits[i - 1]) {
                vn++;
            }
        }
        double num = Math.abs(vn - 2.0 * n * pi * (1 - pi));
        double den = 2.0 * Math.sqrt(2.0 * n) * pi * (1 - pi);
        double pValue = erfc(num / den);
        String detail = "游程总数Vn=" + vn + "，1 的比例π=" + fmt(pi);
        return item(pValue, detail);
    }

    /** 4) 最长游程检测（Longest Run of Ones in a Block）。 */
    private Map<String, Object> longestRunOfOnes(int[] bits, int n) {
        int m, k, numBlocks;
        double[] pi;
        int[] vClasses;
        if (n < 128) {
            String detail = "数据长度不足 128 比特，最长游程检测不适用（当前 " + n + " 比特）";
            return item(null, detail, false);
        } else if (n < 6272) {
            m = 8;
            k = 3;
            numBlocks = n / m;
            pi = new double[]{0.2148, 0.3672, 0.2305, 0.1875};
            vClasses = new int[]{1, 2, 3, 4};
        } else if (n < 750000) {
            m = 128;
            k = 5;
            numBlocks = n / m;
            pi = new double[]{0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124};
            vClasses = new int[]{4, 5, 6, 7, 8, 9};
        } else {
            m = 10000;
            k = 6;
            numBlocks = n / m;
            pi = new double[]{0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727};
            vClasses = new int[]{10, 11, 12, 13, 14, 15, 16};
        }

        int[] v = new int[k + 1];
        for (int i = 0; i < numBlocks; i++) {
            int longest = 0;
            int cur = 0;
            for (int j = 0; j < m; j++) {
                if (bits[i * m + j] == 1) {
                    cur++;
                    longest = Math.max(longest, cur);
                } else {
                    cur = 0;
                }
            }
            int idx = classifyLongest(longest, vClasses);
            v[idx]++;
        }

        double chiSq = 0.0;
        for (int i = 0; i <= k; i++) {
            double expect = numBlocks * pi[i];
            chiSq += (v[i] - expect) * (v[i] - expect) / expect;
        }
        double pValue = igamc(k / 2.0, chiSq / 2.0);
        StringBuilder vs = new StringBuilder();
        for (int i = 0; i <= k; i++) {
            vs.append(v[i]);
            if (i < k) vs.append(",");
        }
        String detail = "块大小M=" + m + "，块数N=" + numBlocks + "，分布[" + vs + "]，卡方χ²=" + fmt(chiSq);
        return item(pValue, detail);
    }

    /** 5) 二元矩阵秩检测（Binary Matrix Rank）。 */
    private Map<String, Object> binaryMatrixRank(int[] bits, int n) {
        int M = 32;
        int Q = 32;
        if (n < M * Q * 38) {
            String detail = "数据长度不足 " + (M * Q * 38) + " 比特，二元矩阵秩检测不适用（当前 " + n + " 比特）";
            return item(null, detail, false);
        }
        int N = n / (M * Q);
        int fM = 0, fMm1 = 0, fRest = 0;
        for (int i = 0; i < N; i++) {
            int[][] matrix = new int[M][Q];
            for (int r = 0; r < M; r++) {
                for (int c = 0; c < Q; c++) {
                    matrix[r][c] = bits[i * M * Q + r * Q + c];
                }
            }
            int rank = binaryRank(matrix, M, Q);
            if (rank == M) fM++;
            else if (rank == M - 1) fMm1++;
            else fRest++;
        }

        // M=Q 时二元矩阵秩分布的精确极限概率
        double pM = 1.0;
        for (int i = 1; i <= M; i++) {
            pM *= (1.0 - 1.0 / Math.pow(2, i));
        }
        double pMm1 = 2.0 * pM;
        double pRest = 1.0 - pM - pMm1;
        if (pRest <= 0) pRest = 1e-10;

        double chiSq = Math.pow(fM - N * pM, 2) / (N * pM)
                + Math.pow(fMm1 - N * pMm1, 2) / (N * pMm1)
                + Math.pow(fRest - N * pRest, 2) / (N * pRest);
        double pValue = Math.exp(-chiSq / 2.0);
        String detail = "矩阵数N=" + N + "，满秩=" + fM + "，秩-1=" + fMm1 + "，其他=" + fRest + "，χ²=" + fmt(chiSq);
        return item(pValue, detail);
    }

    /** 6) 重叠模板匹配检测（Overlapping Template Matching）。 */
    private Map<String, Object> overlappingTemplateMatching(int[] bits, int n) {
        int m = 9;
        String templateStr = "111111111";
        int[] template = templateToBits(templateStr);
        int blockSize = 1032;
        if (n < blockSize * 2) {
            String detail = "数据长度不足 " + (blockSize * 2) + " 比特，重叠模板匹配检测不适用（当前 " + n + " 比特）";
            return item(null, detail, false);
        }
        int K = 5;
        double[] lambda = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0};
        double[] pi = new double[]{0.364091, 0.185659, 0.139381, 0.100571, 0.070432, 0.139865};
        int N = n / blockSize;
        int[] v = new int[K + 1];
        for (int i = 0; i < N; i++) {
            int count = 0;
            for (int j = 0; j <= blockSize - m; j++) {
                boolean match = true;
                for (int k = 0; k < m; k++) {
                    if (bits[i * blockSize + j + k] != template[k]) {
                        match = false;
                        break;
                    }
                }
                if (match) count++;
            }
            if (count <= 4) v[count]++;
            else v[5]++;
        }
        double chiSq = 0.0;
        for (int i = 0; i <= K; i++) {
            chiSq += Math.pow(v[i] - N * pi[i], 2) / (N * pi[i]);
        }
        double pValue = igamc(K / 2.0, chiSq / 2.0);
        String detail = "块数N=" + N + "，模板=" + templateStr + "，命中分布=" + Arrays.toString(v) + "，χ²=" + fmt(chiSq);
        return item(pValue, detail);
    }

    /** 7/8) 累积和检测（Cumulative Sums）。 */
    private Map<String, Object> cumulativeSums(int[] bits, int n, boolean forward) {
        int z = 0;
        int sum = 0;
        if (forward) {
            for (int b : bits) {
                sum += (b == 1) ? 1 : -1;
                z = Math.max(z, Math.abs(sum));
            }
        } else {
            for (int i = n - 1; i >= 0; i--) {
                sum += (bits[i] == 1) ? 1 : -1;
                z = Math.max(z, Math.abs(sum));
            }
        }
        double pValue = cusumPValue(z, n);
        String detail = (forward ? "前向" : "后向") + "模式最大部分和绝对值z=" + z;
        return item(pValue, detail);
    }

    /** 9) 随机游程检测（Random Excursions）。 */
    private Map<String, Object> randomExcursions(int[] bits, int n) {
        int[] states = {-4, -3, -2, -1, 1, 2, 3, 4};
        List<Integer> xList = new ArrayList<>();
        int sum = 0;
        xList.add(0);
        for (int b : bits) {
            sum += (b == 1) ? 1 : -1;
            xList.add(sum);
        }

        int[] cycleStart = new int[xList.size()];
        int cycles = 0;
        for (int i = 0; i < xList.size(); i++) {
            if (xList.get(i) == 0) {
                cycleStart[cycles++] = i;
            }
        }
        int J = cycles - 1; // 实际周期数（零穿越次数）
        if (J < 500) {
            return item(null, "零穿越次数不足，随机游程检测不适用（当前 " + J + " 个周期，需至少 500 个）", false);
        }

        double[] pValues = new double[states.length];
        StringBuilder detail = new StringBuilder();
        for (int sIdx = 0; sIdx < states.length; sIdx++) {
            int x = states[sIdx];
            int[] v = new int[6];
            for (int c = 0; c < J; c++) {
                int start = cycleStart[c];
                int end = cycleStart[c + 1];
                int count = 0;
                for (int i = start + 1; i < end; i++) {
                    if (xList.get(i) == x) count++;
                }
                if (count >= 5) v[5]++;
                else v[count]++;
            }
            double[] prob = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0};
            // P(x,k) 概率（针对 x=±1..±4 的随机游程访问次数分布）
            for (int k = 0; k < 5; k++) {
                prob[k] = randomExcursionProb(x, k);
            }
            prob[5] = 1.0 - prob[0] - prob[1] - prob[2] - prob[3] - prob[4];
            if (prob[5] < 0) prob[5] = 0; // 防止浮点误差导致负概率
            double chiSq = 0.0;
            for (int k = 0; k < 6; k++) {
                chiSq += Math.pow(v[k] - J * prob[k], 2) / (J * prob[k]);
            }
            pValues[sIdx] = igamc(5.0 / 2.0, chiSq / 2.0);
            detail.append("x=").append(x).append(":p=").append(fmt(pValues[sIdx])).append(";");
        }
        double minP = Arrays.stream(pValues).min().orElse(0.0);
        return item(minP, detail.toString());
    }

    /** 10) 随机游程变量检测（Random Excursions Variant）。 */
    private Map<String, Object> randomExcursionsVariant(int[] bits, int n) {
        int[] states = {-9, -8, -7, -6, -5, -4, -3, -2, -1, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        List<Integer> xList = new ArrayList<>();
        int sum = 0;
        xList.add(0);
        for (int b : bits) {
            sum += (b == 1) ? 1 : -1;
            xList.add(sum);
        }

        int cycles = 0;
        for (int v : xList) {
            if (v == 0) cycles++;
        }
        int J = cycles - 1; // 实际周期数（零穿越次数）
        if (J < 500) {
            return item(null, "零穿越次数不足，随机游程变量检测不适用（当前 " + J + " 个周期，需至少 500 个）", false);
        }

        List<Double> validPValues = new ArrayList<>();
        StringBuilder detail = new StringBuilder();
        for (int sIdx = 0; sIdx < states.length; sIdx++) {
            int x = states[sIdx];
            int count = 0;
            for (int v : xList) {
                if (v == x) count++;
            }
            if (count < 5) {
                detail.append("x=").append(x).append(":cnt=").append(count).append(",N/A;");
                continue;
            }
            double numerator = Math.abs(count - J);
            double denominator = Math.sqrt(2.0 * J * (4.0 * Math.abs(x) - 2.0));
            double pValue = erfc(numerator / denominator);
            validPValues.add(pValue);
            detail.append("x=").append(x).append(":cnt=").append(count).append(",p=").append(fmt(pValue)).append(";");
        }
        if (validPValues.isEmpty()) {
            return item(null, "所有状态访问次数均不足 5 次，随机游程变量检测不适用", false);
        }
        double minP = validPValues.stream().mapToDouble(Double::doubleValue).min().orElse(0.0);
        return item(minP, detail.toString());
    }

    /** 11/12) 扑克检测（Poker Test）。 */
    private Map<String, Object> poker(int[] bits, int n, int m) {
        if (n < m * 20 || n % m != 0) {
            String detail = "数据长度不足或不满足 m=" + m + " 整除，扑克检测不适用（当前 " + n + " 比特）";
            return item(null, detail, false);
        }
        int k = n / m;
        Map<String, Integer> freq = new HashMap<>();
        for (int i = 0; i < k; i++) {
            StringBuilder pattern = new StringBuilder();
            for (int j = 0; j < m; j++) {
                pattern.append(bits[i * m + j]);
            }
            freq.merge(pattern.toString(), 1, Integer::sum);
        }
        double sum = 0.0;
        for (int count : freq.values()) {
            sum += count * count;
        }
        double v = (Math.pow(2, m) / (double) k) * sum - k;
        double pValue = igamc((Math.pow(2, m) - 1) / 2.0, v / 2.0);
        String detail = "m=" + m + "，段数k=" + k + "，不同模式数=" + freq.size() + "，统计量V=" + fmt(v);
        return item(pValue, detail);
    }

    /** 13-16) 序列检测（Serial Test）。 */
    private Map<String, Object> serial(int[] bits, int n, int m) {
        if (n < m + 1 || n < Math.pow(2, m) * 5) {
            String detail = "数据长度不足，序列检测 m=" + m + " 不适用（当前 " + n + " 比特）";
            return item(null, detail, false);
        }
        double psi2M = psi2(bits, n, m);
        double psi2Mm1 = psi2(bits, n, m - 1);
        double dPsi = psi2M - psi2Mm1;
        double pValue1 = igamc(Math.pow(2, m - 2), dPsi / 2.0);
        double pValue;
        String detail;
        if (m >= 3) {
            double psi2Mm2 = psi2(bits, n, m - 2);
            double dPsi2 = psi2M - 2 * psi2Mm1 + psi2Mm2;
            double pValue2 = igamc(Math.pow(2, m - 3), dPsi2 / 2.0);
            pValue = Math.min(pValue1, pValue2);
            detail = "m=" + m + "，ψ²=" + fmt(psi2M) + "，Δψ²=" + fmt(dPsi) + "，Δ²ψ²=" + fmt(dPsi2);
        } else {
            // m=2 时 Δ²ψ² 的自由度小于 1，仅采用 Δψ² 的 P-value
            pValue = pValue1;
            detail = "m=" + m + "，ψ²=" + fmt(psi2M) + "，Δψ²=" + fmt(dPsi);
        }
        return item(pValue, detail);
    }

    private double psi2(int[] bits, int n, int m) {
        if (m <= 0) return 0.0;
        Map<String, Integer> freq = new HashMap<>();
        for (int i = 0; i < n; i++) {
            StringBuilder pattern = new StringBuilder();
            for (int j = 0; j < m; j++) {
                pattern.append(bits[(i + j) % n]);
            }
            freq.merge(pattern.toString(), 1, Integer::sum);
        }
        double sum = 0.0;
        for (int count : freq.values()) {
            sum += (double) count * count;
        }
        return (sum * Math.pow(2, m) / n) - n;
    }

    /** 17-19,22) 近似熵检测（Approximate Entropy）。 */
    private Map<String, Object> approximateEntropy(int[] bits, int n, int m) {
        if (n < Math.pow(2, m) * 10) {
            String detail = "数据长度不足，近似熵检测 m=" + m + " 不适用（当前 " + n + " 比特）";
            return item(null, detail, false);
        }
        double apEn = computeApEn(bits, n, m);
        double chiSq = 2.0 * n * (Math.log(2) - apEn);
        int df = (int) Math.pow(2, m);
        double pValue = igamc(df / 2.0, chiSq / 2.0);
        String detail = "m=" + m + "，近似熵=" + fmt(apEn) + "，χ²=" + fmt(chiSq);
        return item(pValue, detail);
    }

    private double computeApEn(int[] bits, int n, int m) {
        Map<String, Integer> freq1 = new HashMap<>();
        Map<String, Integer> freq2 = new HashMap<>();
        for (int i = 0; i < n; i++) {
            StringBuilder p1 = new StringBuilder();
            for (int j = 0; j < m; j++) {
                p1.append(bits[(i + j) % n]);
            }
            freq1.merge(p1.toString(), 1, Integer::sum);
            StringBuilder p2 = new StringBuilder();
            for (int j = 0; j < m + 1; j++) {
                p2.append(bits[(i + j) % n]);
            }
            freq2.merge(p2.toString(), 1, Integer::sum);
        }
        double sum1 = 0.0;
        for (int count : freq1.values()) {
            sum1 += count * Math.log(count);
        }
        double sum2 = 0.0;
        for (int count : freq2.values()) {
            sum2 += count * Math.log(count);
        }
        return sum1 / n - sum2 / n;
    }

    /** 20,21,23,26) 非重叠模板匹配检测（Non-overlapping Template Matching）。 */
    private Map<String, Object> nonOverlappingTemplateMatching(int[] bits, int n, String templateStr) {
        int m = templateStr.length();
        int[] template = templateToBits(templateStr);
        int blockSize = Math.max(m * 10, n / 100);
        if (blockSize < m * 4) blockSize = m * 4;
        if (n < blockSize * 2) {
            String detail = "数据长度不足，非重叠模板匹配检测不适用（当前 " + n + " 比特）";
            return item(null, detail, false);
        }
        int N = n / blockSize;
        double lambda = (blockSize - m + 1) / Math.pow(2.0, m);
        double eta = lambda / 2.0;
        double[] pi = new double[6];
        for (int i = 0; i < 5; i++) {
            pi[i] = Math.exp(-lambda) * Math.pow(lambda, i) / factorial(i);
        }
        pi[5] = 1.0 - pi[0] - pi[1] - pi[2] - pi[3] - pi[4];

        int[] v = new int[6];
        for (int i = 0; i < N; i++) {
            int count = 0;
            int j = 0;
            while (j <= blockSize - m) {
                boolean match = true;
                for (int k = 0; k < m; k++) {
                    if (bits[i * blockSize + j + k] != template[k]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    count++;
                    j += m;
                } else {
                    j++;
                }
            }
            if (count >= 5) v[5]++;
            else v[count]++;
        }
        double chiSq = 0.0;
        for (int i = 0; i < 6; i++) {
            chiSq += Math.pow(v[i] - N * pi[i], 2) / (N * pi[i]);
        }
        double pValue = igamc(5.0 / 2.0, chiSq / 2.0);
        String detail = "模板=" + templateStr + "，块数N=" + N + "，块大小=" + blockSize + "，命中分布=" + Arrays.toString(v) + "，χ²=" + fmt(chiSq);
        return item(pValue, detail);
    }

    /** 24/25) 线性复杂度检测（Linear Complexity）。 */
    private Map<String, Object> linearComplexity(int[] bits, int n, int m) {
        if (n < m * 10) {
            String detail = "数据长度不足，线性复杂度检测 m=" + m + " 不适用（当前 " + n + " 比特）";
            return item(null, detail, false);
        }
        int N = n / m;
        double mu = m / 2.0 + (9.0 + Math.pow(-1, m + 1)) / 36.0 - 1.0 / Math.pow(2, m) * (m / 3.0 + 2.0 / 9.0);
        int[] v = new int[7];
        for (int i = 0; i < N; i++) {
            int[] block = new int[m];
            System.arraycopy(bits, i * m, block, 0, m);
            int lc = berlekampMassey(block);
            double t = Math.pow(-1, m) * (lc - mu) + 2.0 / 9.0;
            if (t <= -2.5) v[0]++;
            else if (t <= -1.5) v[1]++;
            else if (t <= -0.5) v[2]++;
            else if (t <= 0.5) v[3]++;
            else if (t <= 1.5) v[4]++;
            else if (t <= 2.5) v[5]++;
            else v[6]++;
        }
        double[] pi = {0.010417, 0.03125, 0.125, 0.5, 0.25, 0.0625, 0.020833};
        double chiSq = 0.0;
        for (int i = 0; i < 7; i++) {
            chiSq += Math.pow(v[i] - N * pi[i], 2) / (N * pi[i]);
        }
        double pValue = igamc(6.0 / 2.0, chiSq / 2.0);
        String detail = "m=" + m + "，块数N=" + N + "，线性复杂度分布=" + Arrays.toString(v) + "，χ²=" + fmt(chiSq);
        return item(pValue, detail);
    }

    /** 27) Maurer通用统计检测（Maurer's Universal Statistical）。 */
    private Map<String, Object> maurerUniversal(int[] bits, int n, int L, int Q) {
        int K = n / L - Q;
        if (K <= 0 || Q <= 0) {
            String detail = "数据长度不足，Maurer通用统计检测 L=" + L + ",Q=" + Q + " 不适用（当前 " + n + " 比特）";
            return item(null, detail, false);
        }
        Map<Integer, Integer> table = new HashMap<>();
        for (int i = 0; i < Q; i++) {
            int value = 0;
            for (int j = 0; j < L; j++) {
                value = (value << 1) | bits[i * L + j];
            }
            table.put(value, i + 1);
        }
        double sum = 0.0;
        for (int i = Q; i < Q + K; i++) {
            int value = 0;
            for (int j = 0; j < L; j++) {
                value = (value << 1) | bits[i * L + j];
            }
            int prev = table.getOrDefault(value, 0);
            sum += Math.log(i + 1 - prev) / Math.log(2);
            table.put(value, i + 1);
        }
        double fn = sum / K;
        double expected = expectedMaurer(L);
        double c = 0.7 - 0.8 / L + (4.0 + 32.0 / L) * Math.pow(K, -3.0 / L) / 15.0;
        double variance = varianceMaurer(L);
        double sigma = c * Math.sqrt(variance / K);
        if (sigma == 0 || Double.isNaN(sigma)) sigma = 1e-10;
        double pValue = erfc(Math.abs(fn - expected) / (Math.sqrt(2) * sigma));
        String detail = "L=" + L + "，Q=" + Q + "，K=" + K + "，fn=" + fmt(fn) + "，期望=" + fmt(expected) + "，σ=" + fmt(sigma);
        return item(pValue, detail);
    }

    /** 28) 离散傅里叶变换检测（Discrete Fourier Transform）。 */
    private Map<String, Object> discreteFourierTransform(int[] bits, int n) {
        if (n < 1000) {
            String detail = "数据长度不足 1000 比特，离散傅里叶变换检测不适用（当前 " + n + " 比特）";
            return item(null, detail, false);
        }
        // 为保证 FFT 性能，取不超过 n 的最大 2 的幂进行计算
        int n2 = Integer.highestOneBit(n);
        if (n2 < 1024) n2 = 1024;
        double[] x = new double[n2];
        for (int i = 0; i < n2; i++) {
            x[i] = (bits[i] == 1) ? 1.0 : -1.0;
        }
        double[] real = Arrays.copyOf(x, n2);
        double[] imag = new double[n2];
        iterativeFFT(real, imag, false);

        int n0 = n2 / 2;
        double threshold = Math.sqrt(n2 * Math.log(1.0 / 0.05));
        int n1 = 0;
        for (int i = 0; i < n0; i++) {
            double magnitude = Math.sqrt(real[i] * real[i] + imag[i] * imag[i]);
            if (magnitude < threshold) {
                n1++;
            }
        }
        double d = (double) (n1 - 0.95 * n0) / Math.sqrt(n0 * 0.95 * 0.05 / 4.0);
        double pValue = erfc(Math.abs(d) / Math.sqrt(2.0));
        String detail = "有效长度=" + n2 + "，阈值=" + fmt(threshold) + "，低于阈值峰数N1=" + n1 + "，期望=" + fmt(0.95 * n0);
        return item(pValue, detail);
    }

    // ==================== 数学与工具函数 ====================

    private double randomExcursionProb(int x, int k) {
        double absX = Math.abs(x);
        if (k == 0) {
            return 1.0 - 1.0 / (2.0 * absX);
        }
        return (1.0 / (4.0 * x * x)) * Math.pow(1.0 - 1.0 / (2.0 * absX), k - 1);
    }

    private int berlekampMassey(int[] s) {
        int n = s.length;
        int[] c = new int[n];
        int[] b = new int[n];
        c[0] = 1;
        b[0] = 1;
        int l = 0;
        int m = -1;
        for (int i = 0; i < n; i++) {
            int discrepancy = 0;
            for (int j = 0; j <= l; j++) {
                discrepancy ^= c[j] & s[i - j];
            }
            if (discrepancy == 1) {
                int[] t = Arrays.copyOf(c, n);
                for (int j = 0; j < n - i + m; j++) {
                    c[i - m + j] ^= b[j];
                }
                if (l <= i / 2) {
                    l = i + 1 - l;
                    m = i;
                    b = t;
                }
            }
        }
        return l;
    }

    private int binaryRank(int[][] matrix, int M, int Q) {
        int rank = 0;
        int[] pivotCol = new int[M];
        Arrays.fill(pivotCol, -1);
        for (int row = 0, col = 0; row < M && col < Q; col++) {
            int pivot = -1;
            for (int r = row; r < M; r++) {
                if (matrix[r][col] == 1) {
                    pivot = r;
                    break;
                }
            }
            if (pivot == -1) continue;
            int[] tmp = matrix[row];
            matrix[row] = matrix[pivot];
            matrix[pivot] = tmp;
            pivotCol[rank++] = col;
            for (int r = 0; r < M; r++) {
                if (r != row && matrix[r][col] == 1) {
                    for (int c = col; c < Q; c++) {
                        matrix[r][c] ^= matrix[row][c];
                    }
                }
            }
            row++;
        }
        return rank;
    }

    private double expectedMaurer(int L) {
        return switch (L) {
            case 1 -> 0.7326495;
            case 2 -> 1.5374383;
            case 3 -> 2.4016068;
            case 4 -> 3.3112247;
            case 5 -> 4.2534266;
            case 6 -> 5.2177052;
            case 7 -> 6.1962507;
            case 8 -> 7.1836656;
            case 9 -> 8.1764248;
            case 10 -> 9.1723243;
            case 11 -> 10.170032;
            case 12 -> 11.168765;
            case 13 -> 12.168070;
            case 14 -> 13.167693;
            case 15 -> 14.167488;
            case 16 -> 15.167379;
            default -> L * Math.log(2) / Math.log(Math.E) - Math.log(2) / Math.log(Math.E) / 2.0;
        };
    }

    private double varianceMaurer(int L) {
        return switch (L) {
            case 1 -> 0.6905;
            case 2 -> 1.3383;
            case 3 -> 1.8885;
            case 4 -> 2.3458;
            case 5 -> 2.7045;
            case 6 -> 2.9540;
            case 7 -> 3.1254;
            case 8 -> 3.2381;
            case 9 -> 3.3112;
            case 10 -> 3.3563;
            case 11 -> 3.3844;
            case 12 -> 3.4011;
            case 13 -> 3.4101;
            case 14 -> 3.4160;
            case 15 -> 3.4199;
            case 16 -> 3.4223;
            default -> 3.5;
        };
    }

    private void iterativeFFT(double[] real, double[] imag, boolean inverse) {
        int n = real.length;
        if ((n & (n - 1)) != 0) {
            // 非2的幂，使用DFT
            dft(real, imag, inverse);
            return;
        }
        // 位反转置换
        int j = 0;
        for (int i = 1; i < n; i++) {
            int bit = n >> 1;
            for (; j >= bit; bit >>= 1) {
                j -= bit;
            }
            j += bit;
            if (i < j) {
                double temp = real[i];
                real[i] = real[j];
                real[j] = temp;
                temp = imag[i];
                imag[i] = imag[j];
                imag[j] = temp;
            }
        }
        // Cooley-Tukey
        for (int len = 2; len <= n; len <<= 1) {
            double ang = 2 * Math.PI / len * (inverse ? -1 : 1);
            double wlenR = Math.cos(ang);
            double wlenI = Math.sin(ang);
            for (int i = 0; i < n; i += len) {
                double wr = 1, wi = 0;
                for (int k = 0; k < len / 2; k++) {
                    int u = i + k;
                    int v = i + k + len / 2;
                    double ur = real[u], ui = imag[u];
                    double vr = real[v] * wr - imag[v] * wi;
                    double vi = real[v] * wi + imag[v] * wr;
                    real[u] = ur + vr;
                    imag[u] = ui + vi;
                    real[v] = ur - vr;
                    imag[v] = ui - vi;
                    double nextR = wr * wlenR - wi * wlenI;
                    double nextI = wr * wlenI + wi * wlenR;
                    wr = nextR;
                    wi = nextI;
                }
            }
        }
        if (inverse) {
            for (int i = 0; i < n; i++) {
                real[i] /= n;
                imag[i] /= n;
            }
        }
    }

    private void dft(double[] real, double[] imag, boolean inverse) {
        int n = real.length;
        double[] outR = new double[n];
        double[] outI = new double[n];
        double sign = inverse ? 1 : -1;
        for (int k = 0; k < n; k++) {
            for (int t = 0; t < n; t++) {
                double angle = 2 * Math.PI * t * k / n * sign;
                outR[k] += real[t] * Math.cos(angle) - imag[t] * Math.sin(angle);
                outI[k] += real[t] * Math.sin(angle) + imag[t] * Math.cos(angle);
            }
        }
        System.arraycopy(outR, 0, real, 0, n);
        System.arraycopy(outI, 0, imag, 0, n);
        if (inverse) {
            for (int i = 0; i < n; i++) {
                real[i] /= n;
                imag[i] /= n;
            }
        }
    }

    private int[] templateToBits(String template) {
        int[] bits = new int[template.length()];
        for (int i = 0; i < template.length(); i++) {
            bits[i] = template.charAt(i) - '0';
        }
        return bits;
    }

    private long factorial(int n) {
        long result = 1;
        for (int i = 2; i <= n; i++) {
            result *= i;
        }
        return result;
    }

    /** 累加和检测的 P-value 计算。 */
    private double cusumPValue(int z, int n) {
        double sqrtN = Math.sqrt(n);
        double sum1 = 0.0;
        int start = (int) Math.floor((-(double) n / z + 1) / 4.0);
        int end = (int) Math.floor(((double) n / z - 1) / 4.0);
        for (int k = start; k <= end; k++) {
            sum1 += normalCdf((4 * k + 1) * z / sqrtN) - normalCdf((4 * k - 1) * z / sqrtN);
        }
        double sum2 = 0.0;
        start = (int) Math.floor((-(double) n / z - 3) / 4.0);
        end = (int) Math.floor(((double) n / z - 1) / 4.0);
        for (int k = start; k <= end; k++) {
            sum2 += normalCdf((4 * k + 3) * z / sqrtN) - normalCdf((4 * k + 1) * z / sqrtN);
        }
        double p = 1.0 - sum1 + sum2;
        if (p < 0) p = 0;
        else if (p > 1) p = 1;
        return p;
    }

    private double normalCdf(double x) {
        return 0.5 * (1.0 + erf(x / Math.sqrt(2.0)));
    }

    private double erfc(double x) {
        double z = Math.abs(x);
        double t = 1.0 / (1.0 + 0.5 * z);
        double ans = t * Math.exp(-z * z - 1.26551223
                + t * (1.00002368
                + t * (0.37409196
                + t * (0.09678418
                + t * (-0.18628806
                + t * (0.27886807
                + t * (-1.13520398
                + t * (1.48851587
                + t * (-0.82215223
                + t * 0.17087277)))))))));
        return x >= 0.0 ? ans : 2.0 - ans;
    }

    private double erf(double x) {
        return 1.0 - erfc(x);
    }

    private double igamc(double a, double x) {
        if (x < 0.0 || a <= 0.0) {
            return 1.0;
        }
        if (x == 0.0) {
            return 1.0;
        }
        if (x < a + 1.0) {
            return 1.0 - gser(a, x);
        }
        return gcf(a, x);
    }

    private double gser(double a, double x) {
        double gln = logGamma(a);
        double ap = a;
        double sum = 1.0 / a;
        double del = sum;
        for (int n = 1; n <= 1000; n++) {
            ap += 1.0;
            del *= x / ap;
            sum += del;
            if (Math.abs(del) < Math.abs(sum) * 1e-15) {
                break;
            }
        }
        return sum * Math.exp(-x + a * Math.log(x) - gln);
    }

    private double gcf(double a, double x) {
        double gln = logGamma(a);
        double b = x + 1.0 - a;
        double c = 1.0 / 1.0e-30;
        double d = 1.0 / b;
        double h = d;
        for (int i = 1; i <= 1000; i++) {
            double an = -i * (i - a);
            b += 2.0;
            d = an * d + b;
            if (Math.abs(d) < 1e-30) d = 1e-30;
            c = b + an / c;
            if (Math.abs(c) < 1e-30) c = 1e-30;
            d = 1.0 / d;
            double del = d * c;
            h *= del;
            if (Math.abs(del - 1.0) < 1e-15) {
                break;
            }
        }
        return Math.exp(-x + a * Math.log(x) - gln) * h;
    }

    private double logGamma(double x) {
        double[] cof = {
                76.18009172947146, -86.50532032941677, 24.01409824083091,
                -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5
        };
        double y = x;
        double tmp = x + 5.5;
        tmp -= (x + 0.5) * Math.log(tmp);
        double ser = 1.000000000190015;
        for (int j = 0; j < 6; j++) {
            y += 1.0;
            ser += cof[j] / y;
        }
        return -tmp + Math.log(2.5066282746310005 * ser / x);
    }

    private int classifyLongest(int longest, int[] vClasses) {
        if (longest <= vClasses[0]) return 0;
        int last = vClasses.length - 1;
        if (longest >= vClasses[last]) return last;
        for (int i = 1; i < last; i++) {
            if (longest == vClasses[i]) return i;
        }
        return last;
    }

    private int[] toBits(byte[] data) {
        int[] bits = new int[data.length * 8];
        for (int i = 0; i < data.length; i++) {
            int b = data[i] & 0xFF;
            for (int j = 0; j < 8; j++) {
                bits[i * 8 + j] = (b >> (7 - j)) & 1;
            }
        }
        return bits;
    }

    private Map<String, Object> item(Double pValue, String detail, boolean applicable) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("pValue", pValue);
        m.put("pass", applicable ? pValue >= ALPHA : null);
        m.put("applicable", applicable);
        m.put("detail", detail);
        return m;
    }

    private Map<String, Object> item(double pValue, String detail) {
        return item(pValue, detail, true);
    }

    private String fmt(double v) {
        if (Double.isNaN(v) || Double.isInfinite(v)) return String.valueOf(v);
        return String.format("%.6f", v);
    }

    private record MethodMeta(int id, String name, String description) {
    }
}
