package com.smtool.module.parse;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class IpsecKeyLogParserTest {

    @Test
    void testParseKeyLog() {
        String content = """
                # IKE key log example
                IKEv1 eede2c0f56370401 171de3dfab50c16c 00112233445566778899aabbccddeeff 00112233445566778899aabbccddeeff 00112233445566778899aabbccddeeff
                """;
        IpsecKeyLogParser parser = new IpsecKeyLogParser();
        List<IpsecKeyLogEntry> entries = parser.parse(content);
        assertEquals(1, entries.size());
        IpsecKeyLogEntry entry = entries.get(0);
        assertEquals("eede2c0f56370401", entry.getInitiatorSpi());
        assertEquals("171de3dfab50c16c", entry.getResponderSpi());
        assertEquals(16, entry.getSkeyidE().length);
        assertEquals(16, entry.getSkeyidA().length);
        assertEquals(16, entry.getIv().length);
        assertTrue(entry.matches("eede2c0f56370401", "171de3dfab50c16c"));
        assertTrue(entry.matches("171de3dfab50c16c", "eede2c0f56370401"));
    }

    @Test
    void testParseMinimalLine() {
        String content = "IKEv1 aabbccdd11223344 55667788aabbccdd 00112233445566778899aabbccddeeff\n";
        IpsecKeyLogParser parser = new IpsecKeyLogParser();
        List<IpsecKeyLogEntry> entries = parser.parse(content);
        assertEquals(1, entries.size());
        assertEquals(16, entries.get(0).getSkeyidE().length);
        assertEquals(0, entries.get(0).getSkeyidA().length);
        assertEquals(0, entries.get(0).getIv().length);
    }

    @Test
    void testParseEmptyAndComments() {
        String content = """
                # only comments and blanks

                # IKEv1 invalid
                """;
        IpsecKeyLogParser parser = new IpsecKeyLogParser();
        List<IpsecKeyLogEntry> entries = parser.parse(content);
        assertTrue(entries.isEmpty());
    }
}
