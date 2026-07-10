package com.smtool.module.parse;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PacketParserTest {

    @Test
    void testParseEspOverLinuxSll() {
        byte[] raw = new byte[64];
        // Linux SLL header
        raw[14] = 0x08;
        raw[15] = 0x00;
        // IPv4 header at offset 16
        raw[16] = 0x45;
        raw[16 + 9] = 50; // ESP
        raw[16 + 12] = 10;
        raw[16 + 13] = 0;
        raw[16 + 14] = 0;
        raw[16 + 15] = 1;
        raw[16 + 16] = 10;
        raw[16 + 17] = 0;
        raw[16 + 18] = 0;
        raw[16 + 19] = 2;
        // ESP header at offset 36: SPI=0x12345678, Seq=0x0000000a
        raw[36] = 0x12;
        raw[36 + 1] = 0x34;
        raw[36 + 2] = 0x56;
        raw[36 + 3] = 0x78;
        raw[36 + 4] = 0x00;
        raw[36 + 5] = 0x00;
        raw[36 + 6] = 0x00;
        raw[36 + 7] = 0x0a;

        PcapPacket pkt = new PcapPacket();
        pkt.setRaw(raw);
        pkt.setLinkType(PacketOffsetUtil.LINKTYPE_LINUX_SLL);
        PacketParser.parse(pkt);

        assertEquals("esp", pkt.getProtocol());
        assertEquals(50, pkt.getNetworkProtocol());
        assertEquals("10.0.0.1", pkt.getSrcIp());
        assertEquals("10.0.0.2", pkt.getDstIp());
        assertEquals(0x12345678L, pkt.getEspSpi());
        assertEquals(0x0aL, pkt.getEspSequence());
        assertNotNull(pkt.getPayload());
        assertEquals(raw.length - 44, pkt.getPayload().length);
    }

    @Test
    void testParseUdpOverEthernet() {
        byte[] raw = new byte[54];
        raw[12] = 0x08;
        raw[13] = 0x00;
        raw[14] = 0x45;
        raw[14 + 9] = 17; // UDP
        raw[14 + 12] = (byte) 192;
        raw[14 + 13] = (byte) 168;
        raw[14 + 14] = 1;
        raw[14 + 15] = 1;
        raw[14 + 16] = (byte) 192;
        raw[14 + 17] = (byte) 168;
        raw[14 + 18] = 1;
        raw[14 + 19] = 2;
        // UDP header at 34: src=500, dst=500, len=20
        raw[34] = 0x01;
        raw[34 + 1] = (byte) 0xf4;
        raw[34 + 2] = 0x01;
        raw[34 + 3] = (byte) 0xf4;
        raw[34 + 4] = 0x00;
        raw[34 + 5] = 0x14;
        raw[34 + 6] = 0x00;
        raw[34 + 7] = 0x00;
        // payload
        raw[42] = 0x01;
        raw[43] = 0x02;
        raw[44] = 0x03;
        raw[45] = 0x04;

        PcapPacket pkt = new PcapPacket();
        pkt.setRaw(raw);
        pkt.setLinkType(PacketOffsetUtil.LINKTYPE_ETHERNET);
        PacketParser.parse(pkt);

        assertEquals("udp", pkt.getProtocol());
        assertEquals(500, pkt.getSrcPort());
        assertEquals(500, pkt.getDstPort());
        assertEquals(12, pkt.getPayload().length);
    }

    @Test
    void testParseUnsupportedLinkType() {
        byte[] raw = new byte[20];
        PcapPacket pkt = new PcapPacket();
        pkt.setRaw(raw);
        pkt.setLinkType(999);
        PacketParser.parse(pkt);

        assertEquals("other", pkt.getProtocol());
        assertNull(pkt.getSrcIp());
    }
}
