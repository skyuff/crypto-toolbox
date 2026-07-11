package com.smtool.module.random;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RandomnessServiceTest {

    private final RandomnessService service = new RandomnessService();

    @Test
    void testApplicableResultsAreUsedForOverallPass() {
        // 100 字节 = 800 比特，远小于多数检测项要求，会触发大量 N/A
        // 但单比特频数检测等仍可执行
        byte[] data = new byte[100];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i & 0xFF);
        }
        RandomnessRequest req = new RandomnessRequest();
        req.setInput(bytesToHex(data));
        req.setFormat("hex");
        req.setSelectedMethods(List.of(1, 2, 3, 4, 5)); // 1 可执行，其余大概率 N/A

        Map<String, Object> result = service.test(req);
        List<Map<String, Object>> tests = (List<Map<String, Object>>) result.get("tests");

        long naCount = tests.stream().filter(t -> Boolean.FALSE.equals(t.get("applicable"))).count();
        long applicableCount = tests.stream().filter(t -> Boolean.TRUE.equals(t.get("applicable"))).count();

        assertTrue(naCount > 0, "应存在不适用项");
        assertTrue(applicableCount > 0, "应存在适用项");

        // 总体结论应只依据适用项
        boolean expectedOverall = tests.stream()
                .filter(t -> Boolean.TRUE.equals(t.get("applicable")))
                .allMatch(t -> Boolean.TRUE.equals(t.get("pass")));
        assertEquals(expectedOverall, result.get("overallPass"));
    }

    @Test
    void testNotApplicableHasNullPassAndPValue() {
        // 8 比特，触发多项不适用
        RandomnessRequest req = new RandomnessRequest();
        req.setInput("ff");
        req.setFormat("hex");
        req.setSelectedMethods(List.of(4)); // 最长游程检测要求 >=128 比特

        Map<String, Object> result = service.test(req);
        List<Map<String, Object>> tests = (List<Map<String, Object>>) result.get("tests");
        assertEquals(1, tests.size());

        Map<String, Object> test = tests.get(0);
        assertFalse(Boolean.TRUE.equals(test.get("applicable")));
        assertNull(test.get("pass"));
        assertNull(test.get("pValue"));
        assertEquals(true, result.get("overallPass")); // 无适用项时视为通过
    }

    @Test
    void testRandomExcursionsApplicableWithSufficientData() {
        // 使用固定种子生成可重复的伪随机序列（8000000 比特，确保 J >= 500）
        byte[] data = new byte[1000000];
        SecureRandom sr = new SecureRandom();
        sr.setSeed(12345L);
        sr.nextBytes(data);

        RandomnessRequest req = new RandomnessRequest();
        req.setInput(bytesToHex(data));
        req.setFormat("hex");
        req.setSelectedMethods(List.of(9, 10)); // 随机游程检测、随机游程变量检测

        Map<String, Object> result = service.test(req);
        List<Map<String, Object>> tests = (List<Map<String, Object>>) result.get("tests");
        assertEquals(2, tests.size());

        for (Map<String, Object> test : tests) {
            assertTrue(Boolean.TRUE.equals(test.get("applicable")),
                    "足够长度的伪随机数据应满足随机游程检测前置条件: " + test.get("name"));
        }
    }

    @Test
    void testRandomExcursionsNotApplicableWithShortData() {
        // 32 字节（256 比特）远不足以达到 J >= 500，应判定为不适用
        RandomnessRequest req = new RandomnessRequest();
        req.setInput("7fcc5bda80c00189494e74669563019c8e08ca4d69953756f3ab0d892a735e28");
        req.setFormat("hex");
        req.setSelectedMethods(List.of(9, 10));

        Map<String, Object> result = service.test(req);
        List<Map<String, Object>> tests = (List<Map<String, Object>>) result.get("tests");
        assertEquals(2, tests.size());

        for (Map<String, Object> test : tests) {
            assertFalse(Boolean.TRUE.equals(test.get("applicable")),
                    "短数据应不满足随机游程检测前置条件: " + test.get("name"));
            assertNull(test.get("pass"));
            assertNull(test.get("pValue"));
        }
    }

    private String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
