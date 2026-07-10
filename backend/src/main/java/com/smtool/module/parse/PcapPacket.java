package com.smtool.module.parse;

/**
 * 统一抓包文件中的数据包模型。
 */
public class PcapPacket {

    /** 捕获时间戳（微秒） */
    private long timestampMicros;
    /** 链路层类型，如 1=Ethernet */
    private int linkType;
    /** 源 IP */
    private String srcIp;
    /** 目的 IP */
    private String dstIp;
    /** 源端口，非 TCP/UDP 时为 -1 */
    private int srcPort = -1;
    /** 目的端口，非 TCP/UDP 时为 -1 */
    private int dstPort = -1;
    /** 传输层协议：tcp / udp / esp / ah / icmp / other */
    private String protocol = "other";
    /** IP 协议号：6/17/50/51/1/58 等，-1 表示未知 */
    private int networkProtocol = -1;
    /** 网络层（IP 头）起始偏移 */
    private int networkOffset = -1;
    /** 传输层/载荷协议头起始偏移 */
    private int transportOffset = -1;
    /** 传输层 payload */
    private byte[] payload;
    /** 原始链路层数据 */
    private byte[] raw;

    /** ESP SPI（网络字节序转无符号 long），非 ESP 包为 -1 */
    private long espSpi = -1;
    /** ESP Sequence Number（网络字节序转无符号 long），非 ESP 包为 -1 */
    private long espSequence = -1;
    /** AH SPI（网络字节序转无符号 long），非 AH 包为 -1 */
    private long ahSpi = -1;
    /** AH Sequence Number（网络字节序转无符号 long），非 AH 包为 -1 */
    private long ahSequence = -1;

    public long getTimestampMicros() {
        return timestampMicros;
    }

    public void setTimestampMicros(long timestampMicros) {
        this.timestampMicros = timestampMicros;
    }

    public int getLinkType() {
        return linkType;
    }

    public void setLinkType(int linkType) {
        this.linkType = linkType;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public void setSrcIp(String srcIp) {
        this.srcIp = srcIp;
    }

    public String getDstIp() {
        return dstIp;
    }

    public void setDstIp(String dstIp) {
        this.dstIp = dstIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public byte[] getPayload() {
        return payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = payload;
    }

    public byte[] getRaw() {
        return raw;
    }

    public void setRaw(byte[] raw) {
        this.raw = raw;
    }

    public int getNetworkProtocol() {
        return networkProtocol;
    }

    public void setNetworkProtocol(int networkProtocol) {
        this.networkProtocol = networkProtocol;
    }

    public int getNetworkOffset() {
        return networkOffset;
    }

    public void setNetworkOffset(int networkOffset) {
        this.networkOffset = networkOffset;
    }

    public int getTransportOffset() {
        return transportOffset;
    }

    public void setTransportOffset(int transportOffset) {
        this.transportOffset = transportOffset;
    }

    public long getEspSpi() {
        return espSpi;
    }

    public void setEspSpi(long espSpi) {
        this.espSpi = espSpi;
    }

    public long getEspSequence() {
        return espSequence;
    }

    public void setEspSequence(long espSequence) {
        this.espSequence = espSequence;
    }

    public long getAhSpi() {
        return ahSpi;
    }

    public void setAhSpi(long ahSpi) {
        this.ahSpi = ahSpi;
    }

    public long getAhSequence() {
        return ahSequence;
    }

    public void setAhSequence(long ahSequence) {
        this.ahSequence = ahSequence;
    }
}
