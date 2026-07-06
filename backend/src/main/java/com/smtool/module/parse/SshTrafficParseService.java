package com.smtool.module.parse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * SSH 流量包解析总控服务。
 */
@Service
public class SshTrafficParseService {

    private static final Logger log = LoggerFactory.getLogger(SshTrafficParseService.class);

    private final TcpReassemblyService tcpReassemblyService;
    private final SshSessionAnalyzer sshSessionAnalyzer;
    private final SshSessionMapper sessionMapper;

    public SshTrafficParseService(TcpReassemblyService tcpReassemblyService,
                                  SshSessionAnalyzer sshSessionAnalyzer,
                                  SshSessionMapper sessionMapper) {
        this.tcpReassemblyService = tcpReassemblyService;
        this.sshSessionAnalyzer = sshSessionAnalyzer;
        this.sessionMapper = sessionMapper;
    }

    public SshTrafficParseResult parse(MultipartFile file) throws Exception {
        long start = System.currentTimeMillis();
        byte[] data = readAllBytes(file.getInputStream());

        List<PcapPacket> packets;
        PcapDetector.Format format = PcapDetector.detect(data);
        if (format == PcapDetector.Format.PCAP) {
            PcapReader reader = new PcapReader(data);
            packets = reader.readAll();
        } else if (format == PcapDetector.Format.PCAPNG) {
            PcapngReader reader = new PcapngReader(data);
            packets = reader.readAll();
        } else {
            throw new IllegalArgumentException("不支持的文件格式，仅支持 pcap / pcapng");
        }

        Map<TcpReassemblyService.SessionKey, TcpReassemblyService.BidirectionalStream> streams
                = tcpReassemblyService.reassemble(packets);
        log.info("SSH traffic parse: format={}, packets={}, streams={}", format, packets.size(), streams.size());

        List<SshSession> sessions = new ArrayList<>();
        for (TcpReassemblyService.BidirectionalStream stream : streams.values()) {
            SshSession session = sshSessionAnalyzer.analyze(stream);
            if (session != null) {
                sessions.add(session);
            }
        }

        sessions.sort(Comparator.comparingLong(s -> Math.min(
                streamStartTime(streams, s.getSessionKey()), Long.MAX_VALUE)));

        List<SshSessionDto> dtos = new ArrayList<>();
        for (SshSession session : sessions) {
            dtos.add(sessionMapper.toDto(session));
        }

        long parseTime = System.currentTimeMillis() - start;

        SshTrafficParseResult result = new SshTrafficParseResult();
        result.setSessionCount(dtos.size());
        result.setParseTimeMs(parseTime);
        result.setSessions(dtos);
        return result;
    }

    private long streamStartTime(Map<TcpReassemblyService.SessionKey, TcpReassemblyService.BidirectionalStream> streams,
                                 String sessionKey) {
        for (Map.Entry<TcpReassemblyService.SessionKey, TcpReassemblyService.BidirectionalStream> e : streams.entrySet()) {
            if (e.getKey().toString().equals(sessionKey)) {
                return Math.min(e.getValue().aToB.getStartTime(), e.getValue().bToA.getStartTime());
            }
        }
        return Long.MAX_VALUE;
    }

    private byte[] readAllBytes(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }
}
