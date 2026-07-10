package com.smtool.module.parse;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PacketOffsetUtilTest {

    @Test
    void testEthernetIpv4Udp() {
        byte[] raw = new byte[54];
        // Ethernet header
        raw[12] = 0x08;
        raw[13] = 0x00;
        // IPv4 header: version 4, IHL 5, protocol UDP
        raw[14] = 0x45;
        raw[14 + 9] = 17;
        raw[14 + 12] = (byte) 192;
        raw[14 + 13] = (byte) 168;
        raw[14 + 14] = 1;
        raw[14 + 15] = 1;
        raw[14 + 16] = (byte) 192;
        raw[14 + 17] = (byte) 168;
        raw[14 + 18] = 1;
        raw[14 + 19] = 2;
        // UDP ports
        raw[34] = 0x01;
        raw[34 + 1] = (byte) 0xf4; // 500
        PacketOffsetUtil.Result r = PacketOffsetUtil.parse(raw, PacketOffsetUtil.LINKTYPE_ETHERNET);
        assertTrue(r.supported);
        assertEquals(14, r.networkOffset);
        assertEquals(34, r.transportOffset);
        assertEquals(17, r.ipProtocol);
        assertEquals("192.168.1.1", r.srcIp);
        assertEquals("192.168.1.2", r.dstIp);
    }

    @Test
    void testLinuxSllIpv4Udp() {
        byte[] raw = new byte[56];
        // Linux SLL header: 16 bytes, etherType at offset 14
        raw[14] = 0x08;
        raw[15] = 0x00;
        // IPv4 header at offset 16
        raw[16] = 0x45;
        raw[16 + 9] = 17;
        raw[16 + 12] = 10;
        raw[16 + 13] = 0;
        raw[16 + 14] = 0;
        raw[16 + 15] = 1;
        raw[16 + 16] = 10;
        raw[16 + 17] = 0;
        raw[16 + 18] = 0;
        raw[16 + 19] = 2;
        PacketOffsetUtil.Result r = PacketOffsetUtil.parse(raw, PacketOffsetUtil.LINKTYPE_LINUX_SLL);
        assertTrue(r.supported);
        assertEquals(16, r.networkOffset);
        assertEquals(36, r.transportOffset);
        assertEquals(17, r.ipProtocol);
        assertEquals("10.0.0.1", r.srcIp);
        assertEquals("10.0.0.2", r.dstIp);
    }

    @Test
    void testRawIpv4Esp() {
        // LINKTYPE_RAW: 帧直接从 IPv4 头开始，没有链路层头
        byte[] raw = new byte[64];
        raw[0] = 0x45; // IPv4 version 4, IHL 5
        raw[9] = 50; // ESP
        PacketOffsetUtil.Result r = PacketOffsetUtil.parse(raw, PacketOffsetUtil.LINKTYPE_RAW);
        assertTrue(r.supported);
        assertEquals(0, r.networkOffset);
        assertEquals(20, r.transportOffset);
        assertEquals(50, r.ipProtocol);
    }

    @Test
    void testEthernetVlanIpv4Tcp() {
        byte[] raw = new byte[58];
        raw[12] = (byte) 0x81;
        raw[13] = 0x00;
        raw[16] = 0x08;
        raw[17] = 0x00;
        raw[18] = 0x45;
        raw[18 + 9] = 6; // TCP
        PacketOffsetUtil.Result r = PacketOffsetUtil.parse(raw, PacketOffsetUtil.LINKTYPE_ETHERNET);
        assertTrue(r.supported);
        assertEquals(18, r.networkOffset);
        assertEquals(38, r.transportOffset);
        assertEquals(6, r.ipProtocol);
    }

    @Test
    void testIpv6WithRoutingHeaderThenEsp() {
        byte[] raw = new byte[80];
        // Ethernet header
        raw[12] = (byte) 0x86;
        raw[13] = (byte) 0xdd;
        // IPv6 header at offset 14
        raw[14] = 0x60; // version
        raw[14 + 6] = 43; // next header = Routing
        // src/dst
        for (int i = 0; i < 16; i++) {
            raw[14 + 8 + i] = 1;
            raw[14 + 24 + i] = 2;
        }
        // Routing header at offset 54
        raw[54] = 50; // next header = ESP
        raw[54 + 1] = 1; // header ext length = 1 -> (1+1)*8 = 16 bytes
        PacketOffsetUtil.Result r = PacketOffsetUtil.parse(raw, PacketOffsetUtil.LINKTYPE_ETHERNET);
        assertTrue(r.supported);
        assertEquals(14, r.networkOffset);
        assertEquals(70, r.transportOffset); // 14 + 40 + 16
        assertEquals(50, r.ipProtocol);
    }

    @Test
    void testNullIpv4Udp() {
        // BSD NULL/Loopback: 4-byte family, little-endian AF_INET=2
        byte[] raw = new byte[64];
        raw[0] = 2;
        raw[1] = 0;
        raw[2] = 0;
        raw[3] = 0;
        raw[4] = 0x45; // IPv4 at offset 4
        raw[4 + 9] = 17; // UDP
        PacketOffsetUtil.Result r = PacketOffsetUtil.parse(raw, PacketOffsetUtil.LINKTYPE_NULL);
        assertTrue(r.supported);
        assertEquals(4, r.networkOffset);
        assertEquals(24, r.transportOffset);
        assertEquals(17, r.ipProtocol);
    }

    @Test
    void testPppIpv6Esp() {
        // PPP: 2-byte protocol, 0x0057 = IPv6
        byte[] raw = new byte[80];
        raw[0] = 0x00;
        raw[1] = 0x57;
        raw[2] = 0x60; // IPv6 at offset 2
        raw[2 + 6] = 50; // ESP
        // src/dst
        for (int i = 0; i < 16; i++) {
            raw[2 + 8 + i] = 1;
            raw[2 + 24 + i] = 2;
        }
        PacketOffsetUtil.Result r = PacketOffsetUtil.parse(raw, PacketOffsetUtil.LINKTYPE_PPP);
        assertTrue(r.supported);
        assertEquals(2, r.networkOffset);
        assertEquals(42, r.transportOffset);
        assertEquals(50, r.ipProtocol);
    }

    @Test
    void test80211DataSnapIpv4Udp() {
        // 802.11 Data frame + LLC/SNAP + IPv4/UDP
        byte[] raw = new byte[80];
        raw[0] = 0x08; // Data frame (type=2), subtype=0
        raw[1] = 0x00; // flags=0
        // MAC header 24 bytes (address fields ignored)
        // LLC/SNAP at offset 24
        raw[24] = (byte) 0xAA; // DSAP
        raw[25] = (byte) 0xAA; // SSAP
        raw[26] = 0x03; // Control
        raw[27] = 0x00; // OUI
        raw[28] = 0x00;
        raw[29] = 0x00;
        raw[30] = 0x08; // EtherType IPv4
        raw[31] = 0x00;
        // IPv4 header at offset 32
        raw[32] = 0x45;
        raw[32 + 9] = 17; // UDP
        PacketOffsetUtil.Result r = PacketOffsetUtil.parse(raw, PacketOffsetUtil.LINKTYPE_IEEE802_11);
        assertTrue(r.supported);
        assertEquals(32, r.networkOffset);
        assertEquals(52, r.transportOffset);
        assertEquals(17, r.ipProtocol);
    }

    @Test
    void testUnsupportedLinkType() {
        byte[] raw = new byte[20];
        PacketOffsetUtil.Result r = PacketOffsetUtil.parse(raw, 999);
        assertFalse(r.supported);
    }
}
