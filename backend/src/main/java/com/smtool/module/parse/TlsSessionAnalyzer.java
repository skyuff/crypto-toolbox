package com.smtool.module.parse;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 将重组后的双向 TCP 流聚合为 TLS/TLCP 会话。
 */
@Service
public class TlsSessionAnalyzer {

    private final TlsParseService tlsParseService;
    private final TlsStreamParser tlsStreamParser;
    private final TlsCertificateExtractor certExtractor;

    public TlsSessionAnalyzer(TlsParseService tlsParseService,
                              TlsStreamParser tlsStreamParser,
                              TlsCertificateExtractor certExtractor) {
        this.tlsParseService = tlsParseService;
        this.tlsStreamParser = tlsStreamParser;
        this.certExtractor = certExtractor;
    }

    /**
     * 分析一条双向 TCP 流，若包含 TLS 握手则返回会话对象，否则返回 null。
     */
    public TlsSession analyze(TcpReassemblyService.BidirectionalStream stream) {
        byte[] dataAtoB = stream.aToB.getReassembledData();
        byte[] dataBtoA = stream.bToA.getReassembledData();

        System.out.println("[TLS-ANALYZE] stream=" + stream.key
                + " aToB=" + dataAtoB.length + " bToA=" + dataBtoA.length
                + " aToB-head=" + CodecUtil.toHex(dataAtoB.length > 20 ? java.util.Arrays.copyOf(dataAtoB, 20) : dataAtoB)
                + " bToA-head=" + CodecUtil.toHex(dataBtoA.length > 20 ? java.util.Arrays.copyOf(dataBtoA, 20) : dataBtoA));

        TlsStreamParser.StreamFeatures featuresAtoB = tlsStreamParser.extractFeatures(dataAtoB);
        TlsStreamParser.StreamFeatures featuresBtoA = tlsStreamParser.extractFeatures(dataBtoA);
        List<TlsStreamParser.HandshakeMessage> msgsAtoB = featuresAtoB.getHandshakes();
        List<TlsStreamParser.HandshakeMessage> msgsBtoA = featuresBtoA.getHandshakes();
        System.out.println("[TLS-ANALYZE] stream=" + stream.key
                + " hsAtoB=" + msgsAtoB.size() + " hsBtoA=" + msgsBtoA.size()
                + " ccsAtoB=" + featuresAtoB.isSawChangeCipherSpec() + " ccsBtoA=" + featuresBtoA.isSawChangeCipherSpec()
                + " appAtoB=" + featuresAtoB.isSawApplicationData() + " appBtoA=" + featuresBtoA.isSawApplicationData());

        // 确定方向：发送 ClientHello 的是 client
        boolean aIsClient = hasClientHello(msgsAtoB);
        boolean bIsClient = hasClientHello(msgsBtoA);
        if (!aIsClient && !bIsClient) {
            return null;
        }

        TlsSession session = new TlsSession();
        session.setSessionKey(stream.key.toString());

        List<TlsStreamParser.HandshakeMessage> clientMsgs;
        List<TlsStreamParser.HandshakeMessage> serverMsgs;
        TlsStreamParser.StreamFeatures clientFeatures;
        TlsStreamParser.StreamFeatures serverFeatures;
        if (aIsClient) {
            clientMsgs = msgsAtoB;
            serverMsgs = msgsBtoA;
            clientFeatures = featuresAtoB;
            serverFeatures = featuresBtoA;
            session.setClientIp(stream.key.ipA);
            session.setClientPort(stream.key.portA);
            session.setServerIp(stream.key.ipB);
            session.setServerPort(stream.key.portB);
        } else {
            clientMsgs = msgsBtoA;
            serverMsgs = msgsAtoB;
            clientFeatures = featuresBtoA;
            serverFeatures = featuresAtoB;
            session.setClientIp(stream.key.ipB);
            session.setClientPort(stream.key.portB);
            session.setServerIp(stream.key.ipA);
            session.setServerPort(stream.key.portA);
        }

        session.setSawClientChangeCipherSpec(clientFeatures.isSawChangeCipherSpec());
        session.setSawServerChangeCipherSpec(serverFeatures.isSawChangeCipherSpec());
        session.setSawApplicationData(clientFeatures.isSawApplicationData() || serverFeatures.isSawApplicationData());

        // 解析 client -> server 消息
        for (TlsStreamParser.HandshakeMessage msg : clientMsgs) {
            processClientMessage(session, msg);
        }
        // 解析 server -> client 消息
        for (TlsStreamParser.HandshakeMessage msg : serverMsgs) {
            processServerMessage(session, msg);
        }

        if (!session.isSawClientHello() && !session.isSawServerHello()) {
            return null;
        }
        return session;
    }

    private boolean hasClientHello(List<TlsStreamParser.HandshakeMessage> msgs) {
        for (TlsStreamParser.HandshakeMessage msg : msgs) {
            if (msg.getType() == 1) {
                return true;
            }
        }
        return false;
    }

    private void processClientMessage(TlsSession session, TlsStreamParser.HandshakeMessage msg) {
        switch (msg.getType()) {
            case 1 -> {
                try {
                    ByteReader r = new ByteReader(toHandshakeBytes(msg));
                    Map<String, Object> hs = tlsParseService.parseClientHello(r);
                    if (Boolean.TRUE.equals(hs.get("truncated"))) {
                        session.getNotes().add("ClientHello 解析被截断");
                        break;
                    }
                    session.setSawClientHello(true);
                    Object ver = hs.get("client_version_value");
                    if (ver instanceof Integer) {
                        session.setClientHelloVersion((Integer) ver);
                    }
                    session.setClientRandom((String) hs.get("random"));
                    session.setClientSessionId((String) hs.get("sessionId"));
                    session.setClientCompressionMethods((String) hs.get("compressionMethods"));
                    session.setClientCipherSuites(extractCipherSuites(hs));
                    session.setServerName(extractServerName(hs));
                    List<Map<String, Object>> clientExts = (List<Map<String, Object>>) hs.get("extensions");
                    if (clientExts != null) {
                        session.setClientExtensions(clientExts);
                    }
                } catch (Exception e) {
                    session.getNotes().add("ClientHello 解析失败: " + e.getMessage());
                }
            }
            case 11 -> {
                List<byte[]> certs = extractCertsWithFallback(msg.getPayload(), session.getClientHelloVersion());
                session.getClientCertChainDer().addAll(certs);
                session.setSawClientCertificate(true);
            }
            case 13 -> session.setSawCertificateRequest(true);
            case 20 -> session.setSawClientFinished(true);
        }
    }

    private void processServerMessage(TlsSession session, TlsStreamParser.HandshakeMessage msg) {
        switch (msg.getType()) {
            case 2 -> {
                try {
                    ByteReader r = new ByteReader(toHandshakeBytes(msg));
                    Map<String, Object> hs = tlsParseService.parseServerHello(r);
                    session.setSawServerHello(true);
                    // TLS 1.3 的 ServerHello legacy_version 固定为 0x0303，真实版本在 supported_versions 扩展中
                    Integer realVersion = extractSupportedVersion(hs);
                    if (realVersion == null) {
                        Object ver = hs.get("server_version_value");
                        if (ver instanceof Integer) {
                            realVersion = (Integer) ver;
                        }
                    }
                    session.setServerHelloVersion(realVersion);
                    session.setServerRandom((String) hs.get("random"));
                    session.setServerSessionId((String) hs.get("sessionId"));
                    session.setServerCompressionMethod((String) hs.get("compressionMethod"));
                    Map<String, Object> suite = (Map<String, Object>) hs.get("cipherSuite");
                    if (suite != null) {
                        String value = (String) suite.get("value");
                        if (value != null) {
                            session.setServerCipherSuite(Integer.parseInt(value.replace("0x", ""), 16));
                        }
                    }
                    List<Map<String, Object>> serverExts = (List<Map<String, Object>>) hs.get("extensions");
                    if (serverExts != null) {
                        session.setServerExtensions(serverExts);
                    }
                } catch (Exception e) {
                    session.getNotes().add("ServerHello 解析失败: " + e.getMessage());
                }
            }
            case 11 -> {
                List<byte[]> certs = extractCertsWithFallback(msg.getPayload(), session.getServerHelloVersion());
                session.getServerCertChainDer().addAll(certs);
            }
            case 12 -> session.setServerKeyExchange(parseServerKeyExchange(msg.getPayload(), session.getServerCipherSuite(), session.getServerHelloVersion()));
            case 13 -> session.setSawCertificateRequest(true);
            case 20 -> session.setSawServerFinished(true);
        }
    }

    private byte[] toHandshakeBytes(TlsStreamParser.HandshakeMessage msg) {
        byte[] payload = msg.getPayload();
        byte[] full = new byte[4 + payload.length];
        full[0] = (byte) msg.getType();
        full[1] = (byte) ((payload.length >> 16) & 0xff);
        full[2] = (byte) ((payload.length >> 8) & 0xff);
        full[3] = (byte) (payload.length & 0xff);
        System.arraycopy(payload, 0, full, 4, payload.length);
        return full;
    }

    private List<Integer> extractCipherSuites(Map<String, Object> hs) {
        List<Integer> list = new ArrayList<>();
        List<Map<String, Object>> suites = (List<Map<String, Object>>) hs.get("cipherSuites");
        if (suites == null) {
            return list;
        }
        for (Map<String, Object> s : suites) {
            String value = (String) s.get("value");
            if (value != null) {
                try {
                    list.add(Integer.parseInt(value.replace("0x", ""), 16));
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return list;
    }

    private String extractServerName(Map<String, Object> hs) {
        List<Map<String, Object>> exts = (List<Map<String, Object>>) hs.get("extensions");
        if (exts == null) {
            return null;
        }
        for (Map<String, Object> ext : exts) {
            String type = (String) ext.get("type");
            if (type == null || !type.startsWith("0x0000")) {
                continue;
            }
            String data = (String) ext.get("data");
            if (data == null || data.isBlank()) {
                return null;
            }
            try {
                byte[] bytes = CodecUtil.fromHex(data);
                if (bytes.length < 2) {
                    return null;
                }
                int listLen = ((bytes[0] & 0xff) << 8) | (bytes[1] & 0xff);
                int pos = 2;
                int end = Math.min(pos + listLen, bytes.length);
                while (pos + 3 <= end) {
                    int nameType = bytes[pos] & 0xff;
                    int nameLen = ((bytes[pos + 1] & 0xff) << 8) | (bytes[pos + 2] & 0xff);
                    pos += 3;
                    if (pos + nameLen > end) {
                        break;
                    }
                    if (nameType == 0) {
                        return new String(bytes, pos, nameLen, java.nio.charset.StandardCharsets.UTF_8);
                    }
                    pos += nameLen;
                }
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    private Map<String, Object> parseServerKeyExchange(byte[] payload, Integer serverCipherSuite, Integer version) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("rawHex", CodecUtil.toHex(payload));
        if (payload == null || payload.length == 0) {
            return result;
        }
        String algo = inferKeyExchangeAlgorithm(serverCipherSuite);
        result.put("algorithm", algo);
        try {
            if ("ECDHE".equals(algo) || "SM2".equals(algo) || "ECDH".equals(algo) || "SM2/ECDHE".equals(algo)) {
                parseEcdheServerKeyExchange(payload, result, version);
            } else if ("DHE".equals(algo) || "DH".equals(algo)) {
                parseDhServerKeyExchange(payload, result);
            } else if ("RSA".equals(algo)) {
                parseRsaServerKeyExchange(payload, result);
            }
        } catch (Exception e) {
            result.put("parseNote", "ServerKeyExchange 解析失败: " + e.getMessage());
        }
        return result;
    }

    private String inferKeyExchangeAlgorithm(Integer cipherSuite) {
        return cipherSuite == null ? "未知" : TlsCipherSuites.inferKeyExchangeAlgorithm(cipherSuite);
    }

    /**
     * 从 ServerHello 的 supported_versions 扩展中提取真实协议版本（TLS 1.3 需要）。
     */
    @SuppressWarnings("unchecked")
    private Integer extractSupportedVersion(Map<String, Object> hs) {
        List<Map<String, Object>> exts = (List<Map<String, Object>>) hs.get("extensions");
        if (exts == null) {
            return null;
        }
        for (Map<String, Object> ext : exts) {
            String type = (String) ext.get("type");
            if (type == null || !type.startsWith("0x002b")) {
                continue;
            }
            Object value = ext.get("selectedVersionValue");
            if (value instanceof Integer) {
                return (Integer) value;
            }
        }
        return null;
    }

    private void parseEcdheServerKeyExchange(byte[] payload, Map<String, Object> result, Integer version) {
        if (payload.length < 4) return;
        int curveType = payload[0] & 0xff;
        result.put("curveType", curveType == 1 ? "named_curve" : "unknown(" + curveType + ")");

        // named_curve：curve_type(1) + named_curve(2) + pubkey_len(1) + pubkey
        if (curveType == 1) {
            if (payload.length >= 3) {
                int namedCurve = ((payload[1] & 0xff) << 8) | (payload[2] & 0xff);
                result.put("namedCurve", "0x" + String.format("%04x", namedCurve));
            }
            if (payload.length >= 4) {
                int pubLen = payload[3] & 0xff;
                int pos = 4;
                if (pos + pubLen <= payload.length) {
                    byte[] pub = new byte[pubLen];
                    System.arraycopy(payload, pos, pub, 0, pubLen);
                    result.put("publicKeyHex", CodecUtil.toHex(pub));
                    pos += pubLen;
                }
                // TLS 1.2 / TLCP 才包含 SignatureAndHashAlgorithm；TLS 1.0/1.1 没有该字段
                boolean hasSigAlgo = version == null || version >= 0x0303 || version == 0x0101;
                if (hasSigAlgo) {
                    if (pos + 4 <= payload.length) {
                        int sigAlgo = ((payload[pos] & 0xff) << 8) | (payload[pos + 1] & 0xff);
                        result.put("signatureAlgorithm", "0x" + String.format("%04x", sigAlgo));
                        pos += 2;
                        int sigLen = ((payload[pos] & 0xff) << 8) | (payload[pos + 1] & 0xff);
                        pos += 2;
                        if (pos + sigLen <= payload.length) {
                            byte[] sig = new byte[sigLen];
                            System.arraycopy(payload, pos, sig, 0, sigLen);
                            result.put("signatureHex", CodecUtil.toHex(sig));
                        }
                    }
                } else {
                    if (pos + 2 <= payload.length) {
                        int sigLen = ((payload[pos] & 0xff) << 8) | (payload[pos + 1] & 0xff);
                        pos += 2;
                        if (pos + sigLen <= payload.length) {
                            byte[] sig = new byte[sigLen];
                            System.arraycopy(payload, pos, sig, 0, sigLen);
                            result.put("signatureHex", CodecUtil.toHex(sig));
                        }
                    }
                }
            }
        } else {
            // explicit_prime / explicit_char2 需要解析曲线参数，暂记录原始值
            result.put("parseNote", "显式曲线（curveType=" + curveType + "）参数解析未实现");
        }
    }

    private void parseDhServerKeyExchange(byte[] payload, Map<String, Object> result) {
        int pos = 0;
        pos = readMpint(payload, pos, result, "p");
        pos = readMpint(payload, pos, result, "g");
        readMpint(payload, pos, result, "Ys");
    }

    private void parseRsaServerKeyExchange(byte[] payload, Map<String, Object> result) {
        int pos = 0;
        pos = readMpint(payload, pos, result, "modulus");
        readMpint(payload, pos, result, "exponent");
    }

    private int readMpint(byte[] payload, int pos, Map<String, Object> result, String key) {
        if (pos + 2 > payload.length) return pos;
        int len = ((payload[pos] & 0xff) << 8) | (payload[pos + 1] & 0xff);
        pos += 2;
        if (len < 0 || pos + len > payload.length) return pos;
        byte[] value = new byte[len];
        System.arraycopy(payload, pos, value, 0, len);
        result.put(key + "Hex", CodecUtil.toHex(value));
        return pos + len;
    }

    /**
     * 按已识别版本提取证书链；版本未知时同时尝试 TLS 1.2 与 TLS 1.3 并合并去重结果。
     */
    private List<byte[]> extractCertsWithFallback(byte[] payload, Integer version) {
        try {
            if (version != null) {
                return certExtractor.extractCertificates(payload, version == 0x0304);
            }
            List<byte[]> v12 = certExtractor.extractCertificates(payload, false);
            List<byte[]> v13 = certExtractor.extractCertificates(payload, true);
            if (v12.isEmpty()) {
                return v13;
            }
            if (v13.isEmpty()) {
                return v12;
            }
            Set<String> seen = new HashSet<>();
            List<byte[]> merged = new ArrayList<>();
            for (byte[] cert : v12) {
                String key = Base64.getEncoder().encodeToString(cert);
                if (seen.add(key)) {
                    merged.add(cert);
                }
            }
            for (byte[] cert : v13) {
                String key = Base64.getEncoder().encodeToString(cert);
                if (seen.add(key)) {
                    merged.add(cert);
                }
            }
            return merged;
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }
}
