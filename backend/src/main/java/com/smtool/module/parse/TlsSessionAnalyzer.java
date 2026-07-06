package com.smtool.module.parse;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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

        List<TlsStreamParser.HandshakeMessage> msgsAtoB = tlsStreamParser.extractHandshakes(dataAtoB);
        List<TlsStreamParser.HandshakeMessage> msgsBtoA = tlsStreamParser.extractHandshakes(dataBtoA);
        System.out.println("[TLS-ANALYZE] stream=" + stream.key + " hsAtoB=" + msgsAtoB.size() + " hsBtoA=" + msgsBtoA.size());

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
        if (aIsClient) {
            clientMsgs = msgsAtoB;
            serverMsgs = msgsBtoA;
            session.setClientIp(stream.key.ipA);
            session.setClientPort(stream.key.portA);
            session.setServerIp(stream.key.ipB);
            session.setServerPort(stream.key.portB);
        } else {
            clientMsgs = msgsBtoA;
            serverMsgs = msgsAtoB;
            session.setClientIp(stream.key.ipB);
            session.setClientPort(stream.key.portB);
            session.setServerIp(stream.key.ipA);
            session.setServerPort(stream.key.portA);
        }

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
                List<byte[]> certs = certExtractor.extractCertificates(msg.getPayload());
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
                    Object ver = hs.get("server_version_value");
                    if (ver instanceof Integer) {
                        session.setServerHelloVersion((Integer) ver);
                    }
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
                List<byte[]> certs = certExtractor.extractCertificates(msg.getPayload());
                session.getServerCertChainDer().addAll(certs);
            }
            case 12 -> session.setServerKeyExchange(parseServerKeyExchange(msg.getPayload(), session.getServerCipherSuite()));
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
                    if (nameType == 0 && pos + nameLen <= end) {
                        return new String(bytes, pos, nameLen, java.nio.charset.StandardCharsets.UTF_8);
                    }
                    pos += nameLen;
                }
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    private Map<String, Object> parseServerKeyExchange(byte[] payload, Integer serverCipherSuite) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("rawHex", CodecUtil.toHex(payload));
        if (payload == null || payload.length == 0) {
            return result;
        }
        String algo = inferKeyExchangeAlgorithm(serverCipherSuite);
        result.put("algorithm", algo);
        try {
            if ("ECDHE".equals(algo) || "SM2".equals(algo) || "ECDH".equals(algo)) {
                parseEcdheServerKeyExchange(payload, result);
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
        if (cipherSuite == null) {
            return "未知";
        }
        int cs = cipherSuite;
        if ((cs & 0xff00) == 0xe000 || cs == 0x00c6 || cs == 0x00c7) {
            return "SM2";
        }
        String name = resolveCipherSuiteName(cs).toLowerCase();
        if (name.contains("ecdhe")) return "ECDHE";
        if (name.contains("ecdh")) return "ECDH";
        if (name.contains("dhe") || name.contains("dh")) return "DHE";
        if (name.contains("rsa")) return "RSA";
        return "未知";
    }

    private String resolveCipherSuiteName(int cs) {
        switch (cs) {
            case 0x0000: return "TLS_NULL_WITH_NULL_NULL";
            case 0x002f: return "TLS_RSA_WITH_AES_128_CBC_SHA";
            case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
            case 0x009c: return "TLS_RSA_WITH_AES_128_GCM_SHA256";
            case 0x009d: return "TLS_RSA_WITH_AES_256_GCM_SHA384";
            case 0xc013: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
            case 0xc014: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
            case 0xc02b: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
            case 0xc02c: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
            case 0xc02f: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
            case 0xc030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
            case 0xcca8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
            case 0xcca9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
            case 0x1301: return "TLS_AES_128_GCM_SHA256";
            case 0x1302: return "TLS_AES_256_GCM_SHA384";
            case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
            case 0x00ff: return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
            default: return "未知套件";
        }
    }

    private void parseEcdheServerKeyExchange(byte[] payload, Map<String, Object> result) {
        if (payload.length < 4) return;
        int curveType = payload[0] & 0xff;
        result.put("curveType", curveType == 1 ? "named_curve" : "unknown(" + curveType + ")");
        if (payload.length >= 3) {
            int namedCurve = ((payload[1] & 0xff) << 8) | (payload[2] & 0xff);
            result.put("namedCurve", "0x" + String.format("%04x", namedCurve));
        }
        if (payload.length >= 4) {
            int pubLen = payload[3] & 0xff;
            if (4 + pubLen <= payload.length) {
                byte[] pub = new byte[pubLen];
                System.arraycopy(payload, 4, pub, 0, pubLen);
                result.put("publicKeyHex", CodecUtil.toHex(pub));
            }
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
}
