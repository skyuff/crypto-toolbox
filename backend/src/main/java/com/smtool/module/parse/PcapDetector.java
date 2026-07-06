package com.smtool.module.parse;

import java.io.InputStream;

/**
 * 根据文件 Magic 识别抓包文件格式。
 */
public class PcapDetector {

    public enum Format {
        PCAP,
        PCAPNG,
        UNKNOWN
    }

    /**
     * 读取输入流前 4 字节判断格式。
     */
    public static Format detect(InputStream in) throws Exception {
        byte[] magic = new byte[4];
        int read = in.read(magic);
        if (read < 4) {
            return Format.UNKNOWN;
        }
        return detect(magic);
    }

    public static Format detect(byte[] magic) {
        if (magic.length < 4) {
            return Format.UNKNOWN;
        }
        // pcap: 0xa1b2c3d4 (little-endian) or 0xd4c3b2a1 (big-endian)
        if ((magic[0] == (byte) 0xa1 && magic[1] == (byte) 0xb2 && magic[2] == (byte) 0xc3 && magic[3] == (byte) 0xd4)
                || (magic[0] == (byte) 0xd4 && magic[1] == (byte) 0xc3 && magic[2] == (byte) 0xb2 && magic[3] == (byte) 0xa1)
                || (magic[0] == (byte) 0xa1 && magic[1] == (byte) 0xb2 && magic[2] == (byte) 0xcd && magic[3] == (byte) 0x34)
                || (magic[0] == (byte) 0x34 && magic[1] == (byte) 0xcd && magic[2] == (byte) 0xb2 && magic[3] == (byte) 0xa1)) {
            return Format.PCAP;
        }
        // pcapng: Section Header Block type 0x0a0d0d0a
        if (magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a) {
            return Format.PCAPNG;
        }
        return Format.UNKNOWN;
    }
}
