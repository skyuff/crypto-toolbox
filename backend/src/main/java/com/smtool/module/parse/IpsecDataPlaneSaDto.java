package com.smtool.module.parse;

import java.util.ArrayList;
import java.util.List;

/**
 * IPSec ESP/AH 数据面 SA 前端展示 DTO。
 */
public class IpsecDataPlaneSaDto {

    private String protocol;
    private long spi;
    private String spiHex;
    private String srcIp;
    private String dstIp;
    private long packetCount;
    private long byteCount;
    private long firstSeq = -1;
    private long lastSeq = -1;
    private long firstSeenMicros = -1;
    private long lastSeenMicros = -1;
    private List<Long> sampleSequenceNumbers = new ArrayList<>();

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
}
