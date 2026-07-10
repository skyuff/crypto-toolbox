package com.smtool.module.parse;

import java.util.ArrayList;
import java.util.List;

/**
 * IPSec ESP/AH 数据面 SA 统计信息。
 */
public class IpsecDataPlaneSa {

    /** 协议：ESP 或 AH */
    private String protocol;
    /** SPI 数值（无符号） */
    private long spi;
    /** SPI 十六进制字符串 */
    private String spiHex;

    /** 源 IP */
    private String srcIp;
    /** 目的 IP */
    private String dstIp;

    /** 包数 */
    private long packetCount;
    /** 总字节数（IP 载荷长度，取 UDP 长度或 raw 长度） */
    private long byteCount;

    /** 首个序列号 */
    private long firstSeq = -1;
    /** 最后一个序列号 */
    private long lastSeq = -1;

    /** 首次出现时间戳（微秒） */
    private long firstSeenMicros = -1;
    /** 最后出现时间戳（微秒） */
    private long lastSeenMicros = -1;

    /** 前 N 个序列号（用于展示，避免过多） */
    private List<Long> sampleSequenceNumbers = new ArrayList<>();

    /** 是否已关联到控制面会话 */
    private boolean associated;

    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }

    public long getSpi() { return spi; }
    public void setSpi(long spi) { this.spi = spi; }

    public String getSpiHex() { return spiHex; }
    public void setSpiHex(String spiHex) { this.spiHex = spiHex; }

    public String getSrcIp() { return srcIp; }
    public void setSrcIp(String srcIp) { this.srcIp = srcIp; }

    public String getDstIp() { return dstIp; }
    public void setDstIp(String dstIp) { this.dstIp = dstIp; }

    public long getPacketCount() { return packetCount; }
    public void setPacketCount(long packetCount) { this.packetCount = packetCount; }

    public long getByteCount() { return byteCount; }
    public void setByteCount(long byteCount) { this.byteCount = byteCount; }

    public long getFirstSeq() { return firstSeq; }
    public void setFirstSeq(long firstSeq) { this.firstSeq = firstSeq; }

    public long getLastSeq() { return lastSeq; }
    public void setLastSeq(long lastSeq) { this.lastSeq = lastSeq; }

    public long getFirstSeenMicros() { return firstSeenMicros; }
    public void setFirstSeenMicros(long firstSeenMicros) { this.firstSeenMicros = firstSeenMicros; }

    public long getLastSeenMicros() { return lastSeenMicros; }
    public void setLastSeenMicros(long lastSeenMicros) { this.lastSeenMicros = lastSeenMicros; }

    public List<Long> getSampleSequenceNumbers() { return sampleSequenceNumbers; }
    public void setSampleSequenceNumbers(List<Long> sampleSequenceNumbers) { this.sampleSequenceNumbers = sampleSequenceNumbers; }

    public boolean isAssociated() { return associated; }
    public void setAssociated(boolean associated) { this.associated = associated; }
}
