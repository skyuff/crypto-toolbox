package com.smtool.module.parse;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * 读取传统 pcap 文件（Magic + Global Header + Packet Records）。
 */
public class PcapReader {

    private final DataInputStream in;
    private final boolean littleEndian;
    private final int linkType;

    public PcapReader(InputStream in) throws IOException {
        this.in = new DataInputStream(in);
        byte[] magic = new byte[4];
        this.in.readFully(magic);
        if (magic[0] == (byte) 0xa1 && magic[1] == (byte) 0xb2 && magic[2] == (byte) 0xc3 && magic[3] == (byte) 0xd4) {
            this.littleEndian = false;
        } else if (magic[0] == (byte) 0xd4 && magic[1] == (byte) 0xc3 && magic[2] == (byte) 0xb2 && magic[3] == (byte) 0xa1) {
            this.littleEndian = true;
        } else if (magic[0] == (byte) 0xa1 && magic[1] == (byte) 0xb2 && magic[2] == (byte) 0xcd && magic[3] == (byte) 0x34) {
            // nanosecond resolution, big-endian
            this.littleEndian = false;
        } else if (magic[0] == (byte) 0x34 && magic[1] == (byte) 0xcd && magic[2] == (byte) 0xb2 && magic[3] == (byte) 0xa1) {
            // nanosecond resolution, little-endian
            this.littleEndian = true;
        } else {
            throw new IOException("Invalid pcap magic: " + bytesToHex(magic));
        }
        // skip version (2+2), thiszone (4), sigfigs (4), snaplen (4)
        in.skipNBytes(16);
        this.linkType = readInt();
    }

    public PcapReader(byte[] data) throws IOException {
        this(new ByteArrayInputStream(data));
    }

    public List<PcapPacket> readAll() throws IOException {
        List<PcapPacket> list = new ArrayList<>();
        while (true) {
            PcapPacket pkt = readNext();
            if (pkt == null) {
                break;
            }
            list.add(pkt);
        }
        return list;
    }

    public PcapPacket readNext() throws IOException {
        try {
            int tsSec = readInt();
            int tsUsec = readInt();
            int inclLen = readInt();
            int origLen = readInt();
            if (inclLen < 0 || inclLen > 65535) {
                throw new IOException("Invalid packet length: " + inclLen);
            }
            byte[] data = new byte[inclLen];
            in.readFully(data);

            PcapPacket pkt = new PcapPacket();
            pkt.setTimestampMicros(tsSec * 1_000_000L + tsUsec);
            pkt.setLinkType(linkType);
            pkt.setRaw(data);
            PacketParser.parse(pkt);

            // pcap record 的 packet data 按 32 位对齐，跳过尾部填充字节
            int pad = (4 - (inclLen % 4)) % 4;
            if (pad > 0) {
                in.skipNBytes(pad);
            }
            return pkt;
        } catch (IOException e) {
            return null;
        }
    }

    private int readInt() throws IOException {
        int b1 = in.readUnsignedByte();
        int b2 = in.readUnsignedByte();
        int b3 = in.readUnsignedByte();
        int b4 = in.readUnsignedByte();
        if (littleEndian) {
            return (b4 << 24) | (b3 << 16) | (b2 << 8) | b1;
        }
        return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
