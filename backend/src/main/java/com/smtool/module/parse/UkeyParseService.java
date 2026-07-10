package com.smtool.module.parse;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * UKey APDU 结构化解析服务：
 * 1) command APDU：解析 CLA/INS/P1/P2 及 ISO7816 短格式 Lc/Data/Le，映射常见 INS 含义；
 * 2) response APDU：解析 Data + SW1 SW2，映射常见状态字含义。
 */
@Service
public class UkeyParseService {

    /** 常见 INS 指令含义映射 */
    private static final Map<Integer, String> INS_NAMES = new LinkedHashMap<>();
    /** 常见状态字（SW1SW2）含义映射 */
    private static final Map<Integer, String> SW_NAMES = new LinkedHashMap<>();

    static {
        INS_NAMES.put(0x0E, "ERASE BINARY");
        INS_NAMES.put(0x20, "VERIFY");
        INS_NAMES.put(0x22, "MANAGE SECURITY ENVIRONMENT");
        INS_NAMES.put(0x24, "CHANGE REFERENCE DATA");
        INS_NAMES.put(0x2A, "PERFORM SECURITY OPERATION");
        INS_NAMES.put(0x44, "ACTIVATE FILE");
        INS_NAMES.put(0x46, "GENERATE ASYMMETRIC KEY PAIR");
        INS_NAMES.put(0x70, "MANAGE CHANNEL");
        INS_NAMES.put(0x82, "EXTERNAL AUTHENTICATE");
        INS_NAMES.put(0x84, "GET CHALLENGE");
        INS_NAMES.put(0x86, "GENERAL AUTHENTICATE");
        INS_NAMES.put(0x88, "INTERNAL AUTHENTICATE");
        INS_NAMES.put(0xA4, "SELECT");
        INS_NAMES.put(0xB0, "READ BINARY");
        INS_NAMES.put(0xB2, "READ RECORD");
        INS_NAMES.put(0xC0, "GET RESPONSE");
        INS_NAMES.put(0xCA, "GET DATA");
        INS_NAMES.put(0xD0, "WRITE BINARY");
        INS_NAMES.put(0xD6, "UPDATE BINARY");
        INS_NAMES.put(0xDA, "PUT DATA");
        INS_NAMES.put(0xE0, "CREATE FILE");
        INS_NAMES.put(0xE4, "DELETE FILE");

        SW_NAMES.put(0x9000, "成功（正常处理完成）");
        SW_NAMES.put(0x6100, "成功，还有 SW2 字节可用 GET RESPONSE 取回");
        SW_NAMES.put(0x6281, "返回数据可能出错（部分损坏）");
        SW_NAMES.put(0x6282, "文件到达末尾，读取字节不足");
        SW_NAMES.put(0x6283, "选中文件已失效");
        SW_NAMES.put(0x6300, "认证失败");
        SW_NAMES.put(0x6581, "写入 EEPROM 失败");
        SW_NAMES.put(0x6700, "长度错误（Lc/Le 不正确）");
        SW_NAMES.put(0x6982, "安全状态不满足");
        SW_NAMES.put(0x6983, "认证方法被锁定");
        SW_NAMES.put(0x6984, "引用数据无效");
        SW_NAMES.put(0x6985, "使用条件不满足");
        SW_NAMES.put(0x6986, "命令不允许（无当前 EF）");
        SW_NAMES.put(0x6A80, "数据域参数不正确");
        SW_NAMES.put(0x6A81, "功能不支持");
        SW_NAMES.put(0x6A82, "文件未找到");
        SW_NAMES.put(0x6A83, "记录未找到");
        SW_NAMES.put(0x6A84, "文件空间不足");
        SW_NAMES.put(0x6A86, "P1/P2 参数不正确");
        SW_NAMES.put(0x6A88, "引用数据未找到");
        SW_NAMES.put(0x6B00, "参数错误（P1/P2 之外）");
        SW_NAMES.put(0x6D00, "INS 无效或不支持");
        SW_NAMES.put(0x6E00, "CLA 不支持");
        SW_NAMES.put(0x6F00, "无精确诊断的其他错误");
    }

    /** 解析入口 */
    public Map<String, Object> parse(UkeyParseRequest req) {
        byte[] data = CodecUtil.decode(req.getInput(), req.getFormat() == null ? "hex" : req.getFormat());
        String type = req.getType() == null ? "command" : req.getType().trim().toLowerCase();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("totalBytes", data.length);
        result.put("apduType", type);

        if ("response".equals(type)) {
            result.putAll(parseResponseApdu(data));
        } else {
            result.putAll(parseCommandApdu(data));
        }
        return result;
    }

    /** 解析 command APDU（ISO7816-4 短格式），返回结果中包含 consumedBytes 表示实际消费的字节数 */
    public Map<String, Object> parseCommandApdu(byte[] data) {
        Map<String, Object> m = new LinkedHashMap<>();
        ByteReader r = new ByteReader(data);

        int cla = r.u8();
        int ins = r.u8();
        int p1 = r.u8();
        int p2 = r.u8();
        m.put("CLA", cla < 0 ? null : String.format("0x%02x", cla));
        m.put("INS", ins < 0 ? null
                : String.format("0x%02x", ins) + " (" + INS_NAMES.getOrDefault(ins, "未知/私有指令") + ")");
        m.put("P1", p1 < 0 ? null : String.format("0x%02x", p1));
        m.put("P2", p2 < 0 ? null : String.format("0x%02x", p2));

        // ISO7816 短格式的四种情形（Case 1~4）
        int remaining = r.remaining();
        if (remaining == 0) {
            // Case 1：仅 header，无 Lc/Data/Le
            m.put("case", "Case 1（无数据、无响应期望）");
        } else if (remaining == 1) {
            // Case 2：仅 Le
            int le = r.u8();
            m.put("case", "Case 2（无数据，期望响应）");
            m.put("Le", String.format("0x%02x", le) + " (" + (le == 0 ? 256 : le) + " 字节)");
        } else {
            // 有 Lc：先读 Lc，再读 Data，可能还有 Le
            int lc = r.u8();
            m.put("Lc", String.format("0x%02x", lc) + " (" + lc + " 字节)");
            if (lc > r.remaining()) {
                m.put("note", "Lc（" + lc + "）超过剩余字节数（" + r.remaining() + "），APDU 被截断");
            }
            byte[] body = r.bytes(lc);
            m.put("Data", CodecUtil.toHex(body));
            if (r.has(1)) {
                // Case 4：Data + Le
                int le = r.u8();
                m.put("case", "Case 4（有数据，期望响应）");
                m.put("Le", String.format("0x%02x", le) + " (" + (le == 0 ? 256 : le) + " 字节)");
            } else {
                m.put("case", "Case 3（有数据，无响应期望）");
            }
        }

        m.put("consumedBytes", r.position());
        if (r.isTruncated()) {
            m.put("truncated", true);
        }
        return m;
    }

    /** 解析 response APDU：Data + SW1 SW2 */
    public Map<String, Object> parseResponseApdu(byte[] data) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (data.length < 2) {
            m.put("note", "响应 APDU 至少应包含 2 字节状态字（SW1 SW2）");
            m.put("truncated", true);
            m.put("raw", CodecUtil.toHex(data));
            return m;
        }
        int len = data.length;
        byte[] body = new byte[len - 2];
        System.arraycopy(data, 0, body, 0, len - 2);
        int sw1 = data[len - 2] & 0xFF;
        int sw2 = data[len - 1] & 0xFF;
        int sw = (sw1 << 8) | sw2;

        m.put("Data", CodecUtil.toHex(body));
        m.put("SW1", String.format("0x%02x", sw1));
        m.put("SW2", String.format("0x%02x", sw2));
        m.put("statusWord", String.format("0x%04x", sw) + " (" + describeSw(sw1, sw2) + ")");
        m.put("success", sw == 0x9000);
        m.put("consumedBytes", len);
        return m;
    }

    /** 描述状态字含义：优先精确匹配，其次匹配 SW1 类别 */
    private String describeSw(int sw1, int sw2) {
        int sw = (sw1 << 8) | sw2;
        if (SW_NAMES.containsKey(sw)) {
            return SW_NAMES.get(sw);
        }
        // SW1 类别匹配（如 0x61xx / 0x6Cxx）
        int high = sw & 0xFF00;
        if (high == 0x6100) {
            return "成功，还有 " + sw2 + " 字节可用 GET RESPONSE 取回";
        }
        if (high == 0x6C00) {
            return "Le 长度错误，正确长度为 " + sw2 + " 字节";
        }
        if (SW_NAMES.containsKey(high)) {
            return SW_NAMES.get(high);
        }
        return "未知状态字";
    }
}
