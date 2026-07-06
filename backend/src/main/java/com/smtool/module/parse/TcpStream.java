package com.smtool.module.parse;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 单向 TCP 流重组：支持乱序、重叠与缺段的 best-effort 重组。
 */
public class TcpStream {

    private final List<TcpSegment> segments = new ArrayList<>();
    private long startTime = Long.MAX_VALUE;
    private long endTime = 0;

    public void addSegment(TcpSegment segment) {
        if (segment.getPayload() == null || segment.getPayload().length == 0) {
            return;
        }
        segments.add(segment);
        if (segment.getTimestampMicros() < startTime) {
            startTime = segment.getTimestampMicros();
        }
        if (segment.getTimestampMicros() > endTime) {
            endTime = segment.getTimestampMicros();
        }
    }

    /**
     * 按 SEQ 排序并去重后的有效 payload 字节。
     * <p>
     * 以所有 segment 中最小 SEQ 为基准，将每个 segment 映射到相对偏移。
     * 重叠区域保留后到的 segment（覆盖写），缺段位置保持 0x00。
     */
    public byte[] getReassembledData() {
        if (segments.isEmpty()) {
            return new byte[0];
        }
        segments.sort(Comparator.comparingLong(TcpSegment::getSeq));

        long baseSeq = segments.get(0).getSeq();
        long maxEnd = baseSeq;
        for (TcpSegment seg : segments) {
            long end = seg.getEndSeq();
            if (end > maxEnd) {
                maxEnd = end;
            }
        }

        int totalLen = (int) (maxEnd - baseSeq);
        if (totalLen <= 0) {
            return new byte[0];
        }

        byte[] buffer = new byte[totalLen];
        for (TcpSegment seg : segments) {
            byte[] payload = seg.getPayload();
            if (payload == null || payload.length == 0) {
                continue;
            }
            long segStart = seg.getSeq();
            int offset = (int) (segStart - baseSeq);
            int srcPos = 0;
            int len = payload.length;
            if (offset < 0) {
                // segment 起始位置早于基准，截断前面多余部分
                srcPos = -offset;
                len = payload.length - srcPos;
                offset = 0;
            }
            if (srcPos < 0 || srcPos >= payload.length) {
                continue;
            }
            int avail = buffer.length - offset;
            if (avail <= 0) {
                continue;
            }
            len = Math.min(len, avail);
            if (len > 0) {
                System.arraycopy(payload, srcPos, buffer, offset, len);
            }
        }
        return buffer;
    }

    public long getStartTime() {
        return startTime == Long.MAX_VALUE ? 0 : startTime;
    }

    public long getEndTime() {
        return endTime;
    }
}
