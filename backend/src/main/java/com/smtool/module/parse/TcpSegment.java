package com.smtool.module.parse;

/**
 * TCP 片段。
 */
public class TcpSegment {

    private final long seq;
    private final long ack;
    private final byte[] payload;
    private final int flags;
    private final long timestampMicros;

    public TcpSegment(long seq, long ack, byte[] payload, int flags, long timestampMicros) {
        this.seq = seq;
        this.ack = ack;
        this.payload = payload;
        this.flags = flags;
        this.timestampMicros = timestampMicros;
    }

    public long getSeq() {
        return seq;
    }

    public long getAck() {
        return ack;
    }

    public byte[] getPayload() {
        return payload;
    }

    public int getFlags() {
        return flags;
    }

    public long getTimestampMicros() {
        return timestampMicros;
    }

    public long getEndSeq() {
        return seq + (payload == null ? 0 : payload.length);
    }
}
