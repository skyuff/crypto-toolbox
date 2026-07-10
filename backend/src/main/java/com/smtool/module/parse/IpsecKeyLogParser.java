package com.smtool.module.parse;

import com.smtool.util.CodecUtil;

import java.io.BufferedReader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 解析 IKE 解密密钥日志文件。
 *
 * <p>支持格式（每行一条）：
 * <pre>
 * # 注释
 * IKEv1 <initiator_spi_hex> <responder_spi_hex> <skeyid_e_hex> [<skeyid_a_hex>] [<iv_hex>]
 * </pre>
 *
 * <p>示例：
 * <pre>
 * IKEv1 eede2c0f56370401 171de3dfab50c16c 00112233445566778899aabbccddeeff 00112233445566778899aabbccddeeff 00112233445566778899aabbccddeeff
 * </pre>
 */
public class IpsecKeyLogParser {

    public List<IpsecKeyLogEntry> parse(String content) {
        List<IpsecKeyLogEntry> entries = new ArrayList<>();
        if (content == null || content.isBlank()) {
            return entries;
        }
        BufferedReader reader = new BufferedReader(new StringReader(content));
        String line;
        int lineNo = 0;
        try {
            while ((line = reader.readLine()) != null) {
                lineNo++;
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                IpsecKeyLogEntry entry = parseLine(line, lineNo);
                if (entry != null) {
                    entries.add(entry);
                }
            }
        } catch (Exception ignored) {
        }
        return entries;
    }

    private IpsecKeyLogEntry parseLine(String line, int lineNo) {
        String[] parts = line.split("\\s+");
        if (parts.length < 4 || parts.length > 6) {
            return null;
        }
        String version = parts[0];
        if (!"IKEv1".equalsIgnoreCase(version)) {
            return null;
        }
        String initSpi = parts[1].toLowerCase();
        String respSpi = parts[2].toLowerCase();
        byte[] skeyidE = hex(parts[3]);
        if (skeyidE == null) {
            return null;
        }
        byte[] skeyidA = parts.length > 4 ? hex(parts[4]) : new byte[0];
        if (skeyidA == null) {
            skeyidA = new byte[0];
        }
        byte[] iv = parts.length > 5 ? hex(parts[5]) : new byte[0];
        if (iv == null) {
            iv = new byte[0];
        }
        return new IpsecKeyLogEntry(initSpi, respSpi, skeyidE, skeyidA, iv);
    }

    private byte[] hex(String s) {
        try {
            return CodecUtil.fromHex(s);
        } catch (Exception e) {
            return null;
        }
    }
}
