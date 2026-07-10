package com.smtool.module.parse;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 单向 TCP 流重组：支持乱序、重叠与缺段的 best-effort 重组。
 */
public class TcpStream {

    /** 最大重组长度，防止大流量时 long 强转 int 溢出为负数 */
    private static final int MAX_REASSEMBLED_LEN = 50 * 1024 * 1024;

    private final List<TcpSegment> segments = new ArrayList<>();
    private final List<int[]> gaps = new ArrayList<>();
    private long startTime = Long.MAX_VALUE;
    private long endTime = 0;
    private Long synBaseSeq;
    private Long minSeq;

    public void addSegment(TcpSegment segment) {
        long seq = segment.getSeq();
        int flags = segment.getFlags() & 0xff;
        if (minSeq == null || seq < minSeq) {
            minSeq = seq;
        }
        // 优先使用 SYN 段的 seq+1 作为基准（即使 SYN 段没有 payload 也记录）
        if ((flags & 0x02) != 0) {
            long candidate = seq + 1;
            if (synBaseSeq == null || candidate < synBaseSeq) {
                synBaseSeq = candidate;
            }
        }
        if (segment.getPayload() == null || segment.getPayload().length == 0) {
            return;
        }
        // 跳过 SYN/RST 控制包，避免某些抓包中 SYN-ACK 携带的 padding 被拼接到重组流开头
        if ((flags & 0x02) != 0 || (flags & 0x04) != 0) {
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
     * 以 SYN 段 seq+1 为基准（无 SYN 时使用最小 SEQ），将每个 segment 映射到相对偏移。
     * 重叠区域保留后到的 segment（覆盖写），缺段位置保持 0x00。
     * 重组长度超过 {@link #MAX_REASSEMBLED_LEN} 时截断，避免 int 溢出。
     */
    public byte[] getReassembledData() {
        gaps.clear();
        if (segments.isEmpty()) {
            return new byte[0];
        }
        // 同一起始 SEQ 时按到达时间排序，保证后到的 segment 覆盖先到的
        segments.sort(Comparator.comparingLong(TcpSegment::getSeq)
                .thenComparingLong(TcpSegment::getTimestampMicros));

        long baseSeq = synBaseSeq != null ? synBaseSeq
                : (minSeq != null ? minSeq : segments.get(0).getSeq());
        long maxEnd = baseSeq;
        for (TcpSegment seg : segments) {
            long end = seg.getEndSeq();
            if (end > maxEnd) {
                maxEnd = end;
            }
        }

        long totalLenLong = maxEnd - baseSeq;
        if (totalLenLong <= 0) {
            return new byte[0];
        }
        if (totalLenLong > MAX_REASSEMBLED_LEN) {
            totalLenLong = MAX_REASSEMBLED_LEN;
        }
        int totalLen = (int) totalLenLong;

        byte[] buffer = new byte[totalLen];
        long covered = 0; // 已覆盖到的相对偏移
        for (TcpSegment seg : segments) {
            byte[] payload = seg.getPayload();
            if (payload == null || payload.length == 0) {
                continue;
            }
            long segRelStart = seg.getSeq() - baseSeq;
            if (segRelStart >= totalLen) {
                continue;
            }

            int offset = (int) segRelStart;
            int srcPos = 0;
            int len = payload.length;
            if (segRelStart < 0) {
                // segment 起始位置早于基准，截断前面多余部分
                srcPos = (int) -segRelStart;
                len = payload.length - srcPos;
                offset = 0;
            }
            if (srcPos < 0 || srcPos >= payload.length) {
                continue;
            }
            int avail = totalLen - offset;
            if (avail <= 0) {
                continue;
            }
            len = Math.min(len, avail);
            if (len > 0) {
                // 记录缺段
                if (offset > covered) {
                    gaps.add(new int[]{(int) covered, offset});
                    covered = offset;
                }
                System.arraycopy(payload, srcPos, buffer, offset, len);
                long segRelEnd = (long) offset + len;
                if (segRelEnd > covered) {
                    covered = segRelEnd;
                }
            }
        }
        if (covered < totalLen) {
            gaps.add(new int[]{(int) covered, totalLen});
        }
        return buffer;
    }

    /**
     * 返回本次重组后检测到的缺段区间列表（相对偏移，左闭右开）。
     */
    public List<int[]> getGaps() {
        return new ArrayList<>(gaps);
    }

    public long getStartTime() {
        return startTime == Long.MAX_VALUE ? 0 : startTime;
    }

    public long getEndTime() {
        return endTime;
    }
}
