package com.smtool.module.parse;

import java.util.List;

/**
 * SSH 流量包解析结果 DTO。
 */
public class SshTrafficParseResult {

    private int sessionCount;
    private long parseTimeMs;
    private List<SshSessionDto> sessions;

    public int getSessionCount() { return sessionCount; }
    public void setSessionCount(int sessionCount) { this.sessionCount = sessionCount; }
    public long getParseTimeMs() { return parseTimeMs; }
    public void setParseTimeMs(long parseTimeMs) { this.parseTimeMs = parseTimeMs; }
    public List<SshSessionDto> getSessions() { return sessions; }
    public void setSessions(List<SshSessionDto> sessions) { this.sessions = sessions; }
}
