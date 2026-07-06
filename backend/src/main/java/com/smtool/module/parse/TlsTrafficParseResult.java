package com.smtool.module.parse;

import java.util.List;

/**
 * TLS 流量包解析结果 DTO。
 */
public class TlsTrafficParseResult {

    private int sessionCount;
    private long parseTimeMs;
    private List<TlsSessionDto> sessions;

    public int getSessionCount() {
        return sessionCount;
    }

    public void setSessionCount(int sessionCount) {
        this.sessionCount = sessionCount;
    }

    public long getParseTimeMs() {
        return parseTimeMs;
    }

    public void setParseTimeMs(long parseTimeMs) {
        this.parseTimeMs = parseTimeMs;
    }

    public List<TlsSessionDto> getSessions() {
        return sessions;
    }

    public void setSessions(List<TlsSessionDto> sessions) {
        this.sessions = sessions;
    }
}
