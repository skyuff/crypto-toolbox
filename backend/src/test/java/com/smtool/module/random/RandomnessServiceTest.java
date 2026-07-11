package com.smtool.module.random;

import org.junit.jupiter.api.Test;

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

    private String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
