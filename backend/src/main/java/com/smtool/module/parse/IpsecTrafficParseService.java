package com.smtool.module.parse;

import com.smtool.module.cert.CertCheckService;
import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * IPSEC 流量包解析服务：识别 IKE 控制面会话并聚合 ESP/AH 数据面 SA。
 */
@Service
public class IpsecTrafficParseService {

    private final IpsecSessionAnalyzer ipsecSessionAnalyzer;
    private final IpsecSessionMapper ipsecSessionMapper;
    private final CertCheckService certCheckService;

    public IpsecTrafficParseService(IpsecSessionAnalyzer ipsecSessionAnalyzer,
                                    IpsecSessionMapper ipsecSessionMapper,
                                    CertCheckService certCheckService) {
        this.ipsecSessionAnalyzer = ipsecSessionAnalyzer;
        this.ipsecSessionMapper = ipsecSessionMapper;
        this.certCheckService = certCheckService;
    }

    /**
     * 解析上传的 pcap/pcapng 文件。
     */
    public IpsecTrafficParseResult parse(MultipartFile file) throws Exception {
        return parse(file, null, null, null);
    }

    /**
     * 解析上传的 pcap/pcapng 文件，可选传入 IKE 解密密钥日志。
     */
    public IpsecTrafficParseResult parse(MultipartFile file, MultipartFile keyLogFile) throws Exception {
        return parse(file, keyLogFile, null, null);
    }

    /**
     * 解析上传的 pcap/pcapng 文件，可选传入 IKE 解密密钥日志或国密证书链补录。
     */
    public IpsecTrafficParseResult parse(MultipartFile file, MultipartFile keyLogFile,
                                         MultipartFile[] initiatorCertFiles,
                                         MultipartFile[] responderCertFiles) throws Exception {
        long start = System.currentTimeMillis();
        byte[] data = file.getBytes();

        List<IpsecKeyLogEntry> keyLogs = parseKeyLog(keyLogFile);

        List<PcapPacket> packets = readPackets(data);

        // 分类：IKE 控制面、ESP/AH 数据面、其他
        List<PcapPacket> ikePackets = new ArrayList<>();
        List<PcapPacket> dataPlanePackets = new ArrayList<>();
        for (PcapPacket pkt : packets) {
            String proto = pkt.getProtocol();
            if ("udp".equals(proto) && (pkt.getSrcPort() == 500 || pkt.getSrcPort() == 4500
                    || pkt.getDstPort() == 500 || pkt.getDstPort() == 4500)) {
                ikePackets.add(pkt);
            } else if ("esp".equals(proto) || "ah".equals(proto)) {
                dataPlanePackets.add(pkt);
            }
        }

        // IKE 控制面会话
        List<IpsecSession> sessions = groupSessions(ikePackets, keyLogs);

        // ESP/AH 数据面 SA 聚合
        List<IpsecDataPlaneSa> dataPlaneSas = aggregateDataPlaneSas(dataPlanePackets);
        associateDataPlaneToSessions(sessions, dataPlaneSas);

        // 为未关联的数据面 SA 创建独立会话
        for (IpsecDataPlaneSa sa : dataPlaneSas) {
            if (!sa.isAssociated()) {
                sessions.add(createDataPlaneOnlySession(sa));
            }
        }

        // 过滤掉仅含加密 IKE 消息、无任何可解析协商参数的会话，避免前端出现空行
        sessions.removeIf(this::isUnparseableEncryptedSession);

        sessions.sort(Comparator.comparingLong(this::sessionStartMicros));

        // 补录上传的国密 / 标准 X.509 证书文件到每个会话
        List<IpsecCertificateInfo> uploadedInitiatorCerts = parseCertificateFiles(initiatorCertFiles);
        List<IpsecCertificateInfo> uploadedResponderCerts = parseCertificateFiles(responderCertFiles);
        if (!uploadedInitiatorCerts.isEmpty() || !uploadedResponderCerts.isEmpty()) {
            for (IpsecSession session : sessions) {
                appendUploadedCerts(session.getInitiatorCertificates(), uploadedInitiatorCerts);
                appendUploadedCerts(session.getResponderCertificates(), uploadedResponderCerts);
            }
        }

        List<IpsecSessionDto> dtos = new ArrayList<>();
        for (IpsecSession session : sessions) {
            dtos.add(ipsecSessionMapper.toDto(session));
        }

        IpsecTrafficParseResult result = new IpsecTrafficParseResult();
        result.setSessions(dtos);
        result.setSessionCount(dtos.size());
        result.setParseTimeMs(System.currentTimeMillis() - start);
        return result;
    }

    private List<IpsecKeyLogEntry> parseKeyLog(MultipartFile keyLogFile) throws Exception {
        if (keyLogFile == null || keyLogFile.isEmpty()) {
            return new ArrayList<>();
        }
        String content = new String(keyLogFile.getBytes(), java.nio.charset.StandardCharsets.UTF_8);
        return new IpsecKeyLogParser().parse(content);
    }

    /**
     * 解析上传的证书文件列表（.cer/.pem/.crt），复用 CertCheckService 的国密 X.509 解析能力。
     */
    private List<IpsecCertificateInfo> parseCertificateFiles(MultipartFile[] files) throws Exception {
        List<IpsecCertificateInfo> certs = new ArrayList<>();
        if (files == null || files.length == 0) {
            return certs;
        }
        for (MultipartFile file : files) {
            if (file == null || file.isEmpty()) {
                continue;
            }
            IpsecCertificateInfo info = parseCertificateFile(file);
            if (info != null) {
                certs.add(info);
            }
        }
        return certs;
    }

    private IpsecCertificateInfo parseCertificateFile(MultipartFile file) {
        try {
            byte[] der = file.getBytes();
            // 简单支持 PEM：去掉头尾和空白后按 base64 解码
            String text = new String(der, java.nio.charset.StandardCharsets.UTF_8).trim();
            if (text.startsWith("-----BEGIN")) {
                String base64 = text.replaceAll("-----BEGIN[^-]*-----", "")
                        .replaceAll("-----END[^-]*-----", "")
                        .replaceAll("\\s+", "");
                der = Base64.getDecoder().decode(base64);
            }
            Map<String, Object> certInfo = certCheckService.check(der);
            IpsecCertificateInfo cert = new IpsecCertificateInfo();
            cert.setVersion((String) certInfo.get("version"));
            cert.setSerialNumber((String) certInfo.get("serialNumber"));
            cert.setSubject((String) certInfo.get("subject"));
            cert.setIssuer((String) certInfo.get("issuer"));
            cert.setNotBefore((String) certInfo.get("notBefore"));
            cert.setNotAfter((String) certInfo.get("notAfter"));
            Map<String, Object> sigAlg = (Map<String, Object>) certInfo.get("signatureAlgorithm");
            cert.setSignatureAlgorithm(sigAlg != null ? (String) sigAlg.get("name") : null);
            cert.setPublicKeyAlgorithm((String) certInfo.get("publicKeyAlgorithm"));
            List<Map<String, Object>> extensions = (List<Map<String, Object>>) certInfo.get("extensions");
            if (extensions != null) {
                for (Map<String, Object> ext : extensions) {
                    String extOid = (String) ext.get("oid");
                    String extName = (String) ext.get("name");
                    if ("2.5.29.15".equals(extOid) || "keyUsage".equals(extName) || "密钥用法".equals(extName)) {
                        cert.setKeyUsage((String) ext.get("description"));
                        break;
                    }
                }
            }
            cert.setDerBase64(Base64.getEncoder().encodeToString(der));
            return cert;
        } catch (Exception e) {
            return null;
        }
    }

    private void appendUploadedCerts(List<IpsecCertificateInfo> target, List<IpsecCertificateInfo> source) {
        int startIndex = target.size();
        for (IpsecCertificateInfo cert : source) {
            cert.setIndex(startIndex++);
            target.add(cert);
        }
    }

    private List<PcapPacket> readPackets(byte[] data) throws Exception {
        PcapDetector.Format format = PcapDetector.detect(data);
        List<PcapPacket> packets;
        if (format == PcapDetector.Format.PCAPNG) {
            packets = new PcapngReader(data).readAll();
        } else {
            packets = new PcapReader(data).readAll();
        }
        // 对 IPv4 分片进行重组，避免 ISAKMP 证书载荷等大消息被 IP 分片截断
        packets = IpFragmentReassembler.reassemble(packets);
        // 重组后的新报文需要重新解析以填充 srcIp/dstIp/port/payload 等字段
        for (PcapPacket pkt : packets) {
            PacketParser.parse(pkt);
        }
        return packets;
    }

    /**
     * 按五元组 + IKE SPI 对 IKE 数据包分组，并调用 IpsecSessionAnalyzer 解析。
     */
    private List<IpsecSession> groupSessions(List<PcapPacket> packets, List<IpsecKeyLogEntry> keyLogs) {
        Map<String, List<PcapPacket>> groups = new HashMap<>();
        for (PcapPacket pkt : packets) {
            if (pkt.getPayload() == null || pkt.getPayload().length < 28) {
                continue;
            }
            byte[] isakmp = IpsecParseService.stripNattMarker(pkt.getPayload(), pkt.getSrcPort(), pkt.getDstPort());
            if (isakmp.length < 28) {
                continue;
            }
            String spi = CodecUtil.toHex(Arrays.copyOfRange(isakmp, 0, 8));
            String ipPair = sortedIpPair(pkt.getSrcIp(), pkt.getDstIp());
            String key = ipPair + ":" + spi;
            groups.computeIfAbsent(key, k -> new ArrayList<>()).add(pkt);
        }

        List<IpsecSession> sessions = new ArrayList<>();
        for (Map.Entry<String, List<PcapPacket>> entry : groups.entrySet()) {
            List<PcapPacket> pkts = entry.getValue();
            pkts.sort(Comparator.comparingLong(PcapPacket::getTimestampMicros));
            IpsecSession session = ipsecSessionAnalyzer.analyze(entry.getKey(), pkts, keyLogs);
            sessions.add(session);
        }
        return sessions;
    }

    private String sortedIpPair(String a, String b) {
        return a.compareTo(b) <= 0 ? a + "-" + b : b + "-" + a;
    }

    /**
     * 聚合 ESP/AH 数据包为数据面 SA。
     */
    private List<IpsecDataPlaneSa> aggregateDataPlaneSas(List<PcapPacket> packets) {
        Map<String, IpsecDataPlaneSa> groups = new HashMap<>();
        for (PcapPacket pkt : packets) {
            long spi;
            long seq;
            String protocol;
            if ("esp".equals(pkt.getProtocol())) {
                spi = pkt.getEspSpi();
                seq = pkt.getEspSequence();
                protocol = "ESP";
            } else if ("ah".equals(pkt.getProtocol())) {
                spi = pkt.getAhSpi();
                seq = pkt.getAhSequence();
                protocol = "AH";
            } else {
                continue;
            }
            String key = sortedIpPair(pkt.getSrcIp(), pkt.getDstIp()) + ":" + protocol + ":" + spiHex(spi);
            IpsecDataPlaneSa sa = groups.computeIfAbsent(key, k -> {
                IpsecDataPlaneSa n = new IpsecDataPlaneSa();
                n.setProtocol(protocol);
                n.setSpi(spi);
                n.setSpiHex(spiHex(spi));
                n.setSrcIp(pkt.getSrcIp());
                n.setDstIp(pkt.getDstIp());
                return n;
            });

            sa.setPacketCount(sa.getPacketCount() + 1);
            int payloadBytes = pkt.getRaw().length - Math.max(0, pkt.getTransportOffset());
            sa.setByteCount(sa.getByteCount() + payloadBytes);

            if (sa.getFirstSeq() < 0) {
                sa.setFirstSeq(seq);
            }
            sa.setLastSeq(seq);

            long ts = pkt.getTimestampMicros();
            if (sa.getFirstSeenMicros() < 0 || ts < sa.getFirstSeenMicros()) {
                sa.setFirstSeenMicros(ts);
            }
            if (ts > sa.getLastSeenMicros()) {
                sa.setLastSeenMicros(ts);
            }

            if (sa.getSampleSequenceNumbers().size() < 10) {
                sa.getSampleSequenceNumbers().add(seq);
            }
        }
        return new ArrayList<>(groups.values());
    }

    private String spiHex(long spi) {
        return String.format("%08x", spi);
    }

    /**
     * 将数据面 SA 按 IP 对关联到最合适的 IKE 控制面会话。
     * 优先选择已完成第一阶段（含 SA/主模式）的会话，便于前端展示完整协商信息。
     */
    private void associateDataPlaneToSessions(List<IpsecSession> sessions, List<IpsecDataPlaneSa> dataPlaneSas) {
        for (IpsecDataPlaneSa sa : dataPlaneSas) {
            String saIpPair = sortedIpPair(sa.getSrcIp(), sa.getDstIp());
            IpsecSession bestMatch = null;
            for (IpsecSession session : sessions) {
                String sessionIpPair = sortedIpPair(session.getInitiatorIp(), session.getResponderIp());
                if (saIpPair.equals(sessionIpPair)) {
                    if (bestMatch == null || isBetterDataPlaneMatch(session, bestMatch)) {
                        bestMatch = session;
                    }
                }
            }
            if (bestMatch != null) {
                bestMatch.setHasDataPlane(true);
                bestMatch.getDataPlaneSas().add(sa);
                sa.setAssociated(true);
            }
        }
    }

    private boolean isBetterDataPlaneMatch(IpsecSession candidate, IpsecSession current) {
        boolean candidateHasPhase1 = hasPhase1ControlPlane(candidate);
        boolean currentHasPhase1 = hasPhase1ControlPlane(current);
        if (candidateHasPhase1 != currentHasPhase1) {
            return candidateHasPhase1;
        }
        return sessionStartMicros(candidate) < sessionStartMicros(current);
    }

    private boolean hasPhase1ControlPlane(IpsecSession session) {
        if (session.getMessages() == null || session.getMessages().isEmpty()) {
            return false;
        }
        for (Map<String, Object> msg : session.getMessages()) {
            Map<String, Object> header = (Map<String, Object>) msg.get("header");
            if (header == null) {
                continue;
            }
            String exchange = (String) header.get("exchangeType");
            if (exchange != null && exchange.contains("Identity Protection")) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断会话是否属于“完全无法解析的加密 IKE 会话”：
     * 有消息、所有消息均带 Encryption 标志、未提取到任何协商参数，且没有数据面 SA。
     */
    private boolean isUnparseableEncryptedSession(IpsecSession session) {
        if (session.getSelectedEncryption() != null
                || session.getSelectedIntegrity() != null
                || session.getSelectedDhGroup() != null
                || session.getSelectedAuthMethod() != null
                || (session.getDataPlaneSas() != null && !session.getDataPlaneSas().isEmpty())) {
            return false;
        }
        List<Map<String, Object>> messages = session.getMessages();
        if (messages == null || messages.isEmpty()) {
            return false;
        }
        for (Map<String, Object> msg : messages) {
            Map<String, Object> header = (Map<String, Object>) msg.get("header");
            if (header == null) {
                return false;
            }
            String flags = (String) header.get("flags");
            if (flags == null || !flags.contains("Encryption")) {
                return false;
            }
        }
        return true;
    }

    private IpsecSession createDataPlaneOnlySession(IpsecDataPlaneSa sa) {
        IpsecSession session = new IpsecSession();
        session.setSessionKey(saIpKey(sa));
        session.setInitiatorIp(sa.getSrcIp());
        session.setInitiatorPort(-1);
        session.setResponderIp(sa.getDstIp());
        session.setResponderPort(-1);
        session.setIkeVersion("IPSEC (" + sa.getProtocol() + " data plane)");
        session.setHasDataPlane(true);
        session.getDataPlaneSas().add(sa);
        sa.setAssociated(true);
        return session;
    }

    private String saIpKey(IpsecDataPlaneSa sa) {
        return sortedIpPair(sa.getSrcIp(), sa.getDstIp()) + ":" + sa.getProtocol() + ":" + sa.getSpiHex();
    }

    private long sessionStartMicros(IpsecSession session) {
        long min = Long.MAX_VALUE;
        if (session.getMessages() != null) {
            for (Map<String, Object> msg : session.getMessages()) {
                Object ts = msg.get("timestampMicros");
                if (ts instanceof Number n) {
                    min = Math.min(min, n.longValue());
                }
            }
        }
        for (IpsecDataPlaneSa sa : session.getDataPlaneSas()) {
            if (sa.getFirstSeenMicros() > 0) {
                min = Math.min(min, sa.getFirstSeenMicros());
            }
        }
        return min == Long.MAX_VALUE ? 0 : min;
    }
}
