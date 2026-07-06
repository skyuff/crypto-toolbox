package com.smtool.module.parse;

import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
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
}
