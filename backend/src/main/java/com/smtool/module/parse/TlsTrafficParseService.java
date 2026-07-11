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
 * TLS/TLCP 流量包解析总控服务。
 */
@Service
public class TlsTrafficParseService {

    private static final Logger log = LoggerFactory.getLogger(TlsTrafficParseService.class);

    private final TcpReassemblyService tcpReassemblyService;
    private final TlsSessionAnalyzer tlsSessionAnalyzer;
    private final TlsSessionMapper sessionMapper;

    public TlsTrafficParseService(TcpReassemblyService tcpReassemblyService,
                                  TlsSessionAnalyzer tlsSessionAnalyzer,
                                  TlsSessionMapper sessionMapper) {
        this.tcpReassemblyService = tcpReassemblyService;
        this.tlsSessionAnalyzer = tlsSessionAnalyzer;
        this.sessionMapper = sessionMapper;
    }

    public TlsTrafficParseResult parse(MultipartFile file) throws Exception {
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
        log.info(" Traffic parse: format={}, packets={}, streams={}", format, packets.size(), streams.size());
        for (TcpReassemblyService.BidirectionalStream s : streams.values()) {
            log.info(" Stream {}: aToB bytes={}, bToA bytes={}", s.key,
                    s.aToB.getReassembledData().length, s.bToA.getReassembledData().length);
        }

        List<TlsSession> sessions = new ArrayList<>();
        for (TcpReassemblyService.BidirectionalStream stream : streams.values()) {
            TlsSession session = tlsSessionAnalyzer.analyze(stream);
            log.info(" Analyze stream {}: session={}", stream.key, session != null);
            if (session != null) {
                sessions.add(session);
            }
        }

        sessions.sort(Comparator.comparingLong(s -> Math.min(
                streamStartTime(streams, s.getSessionKey()), Long.MAX_VALUE)));

        List<TlsSessionDto> dtos = new ArrayList<>();
        for (TlsSession session : sessions) {
            TlsSessionDto dto = sessionMapper.toDto(session);
            if (!dto.isHandshakeCompleted()) {
                log.info(" Filter out incomplete TLS handshake session: {}", dto.getId());
                continue;
            }
            dtos.add(dto);
        }

        long parseTime = System.currentTimeMillis() - start;

        TlsTrafficParseResult result = new TlsTrafficParseResult();
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
