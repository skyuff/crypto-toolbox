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
    /** 传输层协议：tcp / udp / other */
    private String protocol = "other";
    /** 传输层 payload */
    private byte[] payload;
    /** 原始链路层数据 */
    private byte[] raw;

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
}
