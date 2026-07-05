package com.smtool.module.tool;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 字节逆序服务：整体逆序或按 unit 字节分组做组内逆序（用于大小端转换）。
 */
@Service
public class ByteOrderService {

    public Map<String, Object> reverse(ByteOrderRequest req) {
        String format = req.getFormat() == null || req.getFormat().isBlank() ? "hex" : req.getFormat();
        String formatOut = req.getFormatOut() == null || req.getFormatOut().isBlank() ? "hex" : req.getFormatOut();
        int unit = req.getUnit() == 0 ? 1 : req.getUnit();
        if (unit != 1 && unit != 2 && unit != 4 && unit != 8) {
            throw new IllegalArgumentException("unit 仅支持 1/2/4/8");
        }

        String normalizedInput = req.getInput();
        if ("hex".equalsIgnoreCase(format) && normalizedInput != null) {
            normalizedInput = normalizeHex(normalizedInput);
        }

        byte[] data = CodecUtil.decode(normalizedInput, format);
        if (data.length % unit != 0) {
            throw new IllegalArgumentException("输入长度(" + data.length + " 字节)必须是 unit(" + unit + ") 的整数倍");
        }

        byte[] out;
        if (unit == 1) {
            // 整体字节逆序
            out = new byte[data.length];
            for (int i = 0; i < data.length; i++) {
                out[i] = data[data.length - 1 - i];
            }
        } else {
            // 按每 unit 字节分组做组内逆序
            out = new byte[data.length];
            for (int g = 0; g < data.length; g += unit) {
                for (int i = 0; i < unit; i++) {
                    out[g + i] = data[g + unit - 1 - i];
                }
            }
        }

        Map<String, Object> map = new LinkedHashMap<>();
        map.put("result", CodecUtil.encode(out, formatOut));
        map.put("byteLength", out.length);
        map.put("unit", unit);
        return map;
    }

    /**
     * 规整十六进制字符串：移除空白、冒号、0x 前缀；长度为奇数时前面补 0。
     */
    private String normalizeHex(String hex) {
        String s = hex.replaceAll("[\\s:,]", "").replaceAll("(?i)^0x", "");
        if (s.length() % 2 == 1) {
            s = "0" + s;
        }
        return s;
    }
}
