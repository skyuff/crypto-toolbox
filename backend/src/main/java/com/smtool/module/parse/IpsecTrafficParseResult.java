package com.smtool.module.parse;

import java.util.List;

/**
 * IPSEC / IKE 流量包解析结果 DTO。
 */
public class IpsecTrafficParseResult {

    private int sessionCount;
    private long parseTimeMs;
    private List<IpsecSessionDto> sessions;

    public int getSessionCount() { return sessionCount; }
    public void setSessionCount(int sessionCount) { this.sessionCount = sessionCount; }
    public long getParseTimeMs() { return parseTimeMs; }
    public void setParseTimeMs(long parseTimeMs) { this.parseTimeMs = parseTimeMs; }
    public List<IpsecSessionDto> getSessions() { return sessions; }
    public void setSessions(List<IpsecSessionDto> sessions) { this.sessions = sessions; }
}
