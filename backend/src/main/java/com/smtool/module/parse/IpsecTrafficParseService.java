package com.smtool.module.parse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * IPSEC / IKE 流量包解析总控服务。
 */
@Service
public class IpsecTrafficParseService {

    private static final Logger log = LoggerFactory.getLogger(IpsecTrafficParseService.class);

    private final IpsecSessionAnalyzer ipsecSessionAnalyzer;
    private final IpsecSessionMapper sessionMapper;
    private final IpsecParseService ipsecParseService;

    public IpsecTrafficParseService(IpsecSessionAnalyzer ipsecSessionAnalyzer,
                                    IpsecSessionMapper sessionMapper,
                                    IpsecParseService ipsecParseService) {
        this.ipsecSessionAnalyzer = ipsecSessionAnalyzer;
        this.sessionMapper = sessionMapper;
        this.ipsecParseService = ipsecParseService;
    }

    public IpsecTrafficParseResult parse(MultipartFile file) throws Exception {
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

        Map<String, List<PcapPacket>> sessionPackets = groupSessions(packets);
        log.info("IPSEC traffic parse: format={}, packets={}, sessions={}", format, packets.size(), sessionPackets.size());

        List<IpsecSession> sessions = new ArrayList<>();
        for (Map.Entry<String, List<PcapPacket>> e : sessionPackets.entrySet()) {
            IpsecSession session = ipsecSessionAnalyzer.analyze(e.getKey(), e.getValue());
            if (session != null) {
                sessions.add(session);
            }
        }

        sessions.sort(Comparator.comparingLong(s -> sessionStartTime(sessionPackets, s.getSessionKey())));

        List<IpsecSessionDto> dtos = new ArrayList<>();
        for (IpsecSession session : sessions) {
            dtos.add(sessionMapper.toDto(session));
        }

        long parseTime = System.currentTimeMillis() - start;
        IpsecTrafficParseResult result = new IpsecTrafficParseResult();
        result.setSessionCount(dtos.size());
        result.setParseTimeMs(parseTime);
        result.setSessions(dtos);
        return result;
    }

    /**
     * 按 IKE 会话对 UDP/500 或 UDP/4500 包分组。
     */
    private Map<String, List<PcapPacket>> groupSessions(List<PcapPacket> packets) {
        Map<String, List<PcapPacket>> groups = new LinkedHashMap<>();
        Map<String, Long> firstTimestamp = new HashMap<>();

        for (PcapPacket pkt : packets) {
            if (!"udp".equals(pkt.getProtocol())) {
                continue;
            }
            int srcPort = pkt.getSrcPort();
            int dstPort = pkt.getDstPort();
            if (srcPort != 500 && srcPort != 4500 && dstPort != 500 && dstPort != 4500) {
                continue;
            }

            byte[] isakmp = extractIsakmpPayload(pkt);
            if (isakmp.length < 28) {
                continue;
            }

            Map<String, Object> parsed = ipsecParseService.parseMessage(isakmp);
            Map<String, Object> header = (Map<String, Object>) parsed.get("header");
            if (header == null) {
                continue;
            }

            String initiatorSpi = (String) header.get("initiatorSpi");
            String responderSpi = (String) header.get("responderSpi");
            String exchangeType = (String) header.get("exchangeType");
            String flags = (String) header.get("flags");
            String sortedIps = sortedIpPair(pkt.getSrcIp(), pkt.getDstIp());

            String keyByInitiator = sortedIps + ":" + initiatorSpi;
            String keyByResponder = (responderSpi != null && !isAllZeroSpi(responderSpi))
                    ? sortedIps + ":" + responderSpi : null;

            boolean isInitiating = isInitiatingMessage(responderSpi, exchangeType, flags);

            String key;
            if (groups.containsKey(keyByInitiator)) {
                key = keyByInitiator;
            } else if (keyByResponder != null && groups.containsKey(keyByResponder)) {
                key = keyByResponder;
            } else if (isInitiating) {
                key = keyByInitiator;
            } else {
                key = keyByInitiator;
            }

            groups.computeIfAbsent(key, k -> new ArrayList<>()).add(pkt);
            firstTimestamp.merge(key, pkt.getTimestampMicros(), Math::min);
        }

        // 按首包时间排序
        List<Map.Entry<String, Long>> sorted = new ArrayList<>(firstTimestamp.entrySet());
        sorted.sort(Map.Entry.comparingByValue());
        Map<String, List<PcapPacket>> ordered = new LinkedHashMap<>();
        for (Map.Entry<String, Long> e : sorted) {
            ordered.put(e.getKey(), groups.get(e.getKey()));
        }
        return ordered;
    }

    private boolean isInitiatingMessage(String responderSpi, String exchangeType, String flags) {
        if (responderSpi == null || !isAllZeroSpi(responderSpi)) {
            return false;
        }
        if (exchangeType == null) {
            return false;
        }
        // IKEv2 IKE_SA_INIT 或 IKEv1 Main Mode/Aggressive 的首包 responder cookie/SPI 为 0
        boolean initialExchange = exchangeType.contains("IKE_SA_INIT")
                || exchangeType.contains("Identity Protection")
                || exchangeType.contains("Aggressive");
        if (!initialExchange) {
            return false;
        }
        // IKEv2 首包 flags 含 Initiator 不含 Response
        if (flags != null && flags.contains("Response")) {
            return false;
        }
        return true;
    }

    private boolean isAllZeroSpi(String hex) {
        return hex != null && hex.replaceAll("0", "").isEmpty();
    }

    private String sortedIpPair(String a, String b) {
        if (a == null || b == null) {
            return (a == null ? "" : a) + "-" + (b == null ? "" : b);
        }
        return a.compareTo(b) <= 0 ? a + "-" + b : b + "-" + a;
    }

    /** 从 UDP payload 中提取 ISAKMP 消息（处理 NAT-T Non-ESP Marker）。 */
    private byte[] extractIsakmpPayload(PcapPacket pkt) {
        byte[] payload = pkt.getPayload();
        if (payload == null) {
            return new byte[0];
        }
        if (pkt.getSrcPort() == 4500 || pkt.getDstPort() == 4500) {
            if (payload.length > 4 && payload[0] == 0 && payload[1] == 0 && payload[2] == 0 && payload[3] == 0) {
                byte[] stripped = new byte[payload.length - 4];
                System.arraycopy(payload, 4, stripped, 0, stripped.length);
                return stripped;
            }
        }
        return payload;
    }

    private long sessionStartTime(Map<String, List<PcapPacket>> groups, String sessionKey) {
        List<PcapPacket> list = groups.get(sessionKey);
        if (list == null || list.isEmpty()) {
            return Long.MAX_VALUE;
        }
        long min = Long.MAX_VALUE;
        for (PcapPacket pkt : list) {
            min = Math.min(min, pkt.getTimestampMicros());
        }
        return min;
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
