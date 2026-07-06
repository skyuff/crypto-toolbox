package com.smtool.module.parse;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * 分析双向 TCP 流，聚合 SSH 会话信息。
 */
@Service
public class SshSessionAnalyzer {

    private final SshStreamParser sshStreamParser;

    public SshSessionAnalyzer(SshStreamParser sshStreamParser) {
        this.sshStreamParser = sshStreamParser;
    }

    /**
     * 分析一条双向 TCP 流，若包含 SSH 协商则返回会话对象，否则返回 null。
     */
    public SshSession analyze(TcpReassemblyService.BidirectionalStream stream) {
        byte[] dataAtoB = stream.aToB.getReassembledData();
        byte[] dataBtoA = stream.bToA.getReassembledData();

        List<SshStreamParser.SshMessage> msgsAtoB = sshStreamParser.parseStream(dataAtoB);
        List<SshStreamParser.SshMessage> msgsBtoA = sshStreamParser.parseStream(dataBtoA);

        boolean aIsClient = hasBannerOrKexInit(msgsAtoB);
        boolean bIsClient = hasBannerOrKexInit(msgsBtoA);
        if (!aIsClient && !bIsClient) {
            return null;
        }

        SshSession session = new SshSession();
        session.setSessionKey(stream.key.toString());

        List<SshStreamParser.SshMessage> clientMsgs;
        List<SshStreamParser.SshMessage> serverMsgs;
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

        processClientMessages(session, clientMsgs);
        processServerMessages(session, serverMsgs);

        inferSelectedAlgorithms(session);

        if (session.getClientBanner() == null && session.getServerBanner() == null
                && !session.isSawClientKexInit() && !session.isSawServerKexInit()) {
            return null;
        }
        return session;
    }

    private boolean hasBannerOrKexInit(List<SshStreamParser.SshMessage> msgs) {
        for (SshStreamParser.SshMessage msg : msgs) {
            if ("banner".equals(msg.typeName) || msg.type == 20) {
                return true;
            }
        }
        return false;
    }

    private void processClientMessages(SshSession session, List<SshStreamParser.SshMessage> msgs) {
        for (SshStreamParser.SshMessage msg : msgs) {
            if ("banner".equals(msg.typeName)) {
                session.setClientBanner(msg.banner);
            } else if (msg.type == 20) {
                session.setSawClientKexInit(true);
                try {
                    Map<String, Object> kex = sshStreamParser.parseKexInit(msg.payload);
                    session.setClientKexAlgorithms(getList(kex, "kex_algorithms"));
                    session.setClientHostKeyAlgorithms(getList(kex, "server_host_key_algorithms"));
                    session.setClientEncryptionAlgorithms(getList(kex, "encryption_algorithms_client_to_server"));
                    session.setClientEncryptionAlgorithmsServerToClient(getList(kex, "encryption_algorithms_server_to_client"));
                    session.setClientMacAlgorithms(getList(kex, "mac_algorithms_client_to_server"));
                    session.setClientMacAlgorithmsServerToClient(getList(kex, "mac_algorithms_server_to_client"));
                    session.setClientCompressionAlgorithms(getList(kex, "compression_algorithms_client_to_server"));
                    session.setClientCompressionAlgorithmsServerToClient(getList(kex, "compression_algorithms_server_to_client"));
                } catch (Exception e) {
                    session.getNotes().add("客户端 KEXINIT 解析失败: " + e.getMessage());
                }
            } else if (msg.type == 30) {
                byte[] param = sshStreamParser.parseKexDhInit(msg.payload);
                if (param.length > 0) {
                    session.setClientDhInitParamHex(com.smtool.util.CodecUtil.toHex(param));
                }
            }
        }
    }

    private void processServerMessages(SshSession session, List<SshStreamParser.SshMessage> msgs) {
        for (SshStreamParser.SshMessage msg : msgs) {
            if ("banner".equals(msg.typeName)) {
                session.setServerBanner(msg.banner);
            } else if (msg.type == 20) {
                session.setSawServerKexInit(true);
                try {
                    Map<String, Object> kex = sshStreamParser.parseKexInit(msg.payload);
                    session.setServerKexAlgorithms(getList(kex, "kex_algorithms"));
                    session.setServerHostKeyAlgorithms(getList(kex, "server_host_key_algorithms"));
                    session.setServerEncryptionAlgorithmsClientToServer(getList(kex, "encryption_algorithms_client_to_server"));
                    session.setServerEncryptionAlgorithms(getList(kex, "encryption_algorithms_server_to_client"));
                    session.setServerMacAlgorithmsClientToServer(getList(kex, "mac_algorithms_client_to_server"));
                    session.setServerMacAlgorithms(getList(kex, "mac_algorithms_server_to_client"));
                    session.setServerCompressionAlgorithmsClientToServer(getList(kex, "compression_algorithms_client_to_server"));
                    session.setServerCompressionAlgorithms(getList(kex, "compression_algorithms_server_to_client"));
                } catch (Exception e) {
                    session.getNotes().add("服务端 KEXINIT 解析失败: " + e.getMessage());
                }
            } else if (msg.type == 31) {
                try {
                    SshStreamParser.KexDhReply reply = sshStreamParser.parseKexDhReply(msg.payload);
                    if (reply.publicKeyBlob != null && reply.publicKeyBlob.length > 0) {
                        session.setServerDhReplyParamHex(com.smtool.util.CodecUtil.toHex(reply.publicKeyBlob));
                        session.setServerPublicKeyHex(com.smtool.util.CodecUtil.toHex(reply.publicKeyBlob));
                        session.setServerPublicKeyType(sshStreamParser.parsePublicKeyType(reply.publicKeyBlob));
                    }
                    if (reply.signature != null) {
                        session.setServerSignatureType(reply.signature.type);
                        if (reply.signature.value != null) {
                            session.setServerSignatureValueHex(com.smtool.util.CodecUtil.toHex(reply.signature.value));
                        }
                    }
                } catch (Exception e) {
                    session.getNotes().add("服务端 KEXDH_REPLY 解析失败: " + e.getMessage());
                }
            } else if (msg.type == 21) {
                session.setSawNewKeys(true);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> getList(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (v instanceof List) {
            return (List<String>) v;
        }
        return new java.util.ArrayList<>();
    }

    private void inferSelectedAlgorithms(SshSession session) {
        session.setSelectedKexAlgorithm(firstCommon(session.getClientKexAlgorithms(), session.getServerKexAlgorithms()));
        session.setSelectedHostKeyAlgorithm(firstCommon(session.getClientHostKeyAlgorithms(), session.getServerHostKeyAlgorithms()));
        session.setSelectedEncryptionAlgorithmClientToServer(
                firstCommon(session.getClientEncryptionAlgorithms(), session.getServerEncryptionAlgorithmsClientToServer()));
        session.setSelectedEncryptionAlgorithmServerToClient(
                firstCommon(session.getClientEncryptionAlgorithmsServerToClient(), session.getServerEncryptionAlgorithms()));
        session.setSelectedMacAlgorithmClientToServer(
                firstCommon(session.getClientMacAlgorithms(), session.getServerMacAlgorithmsClientToServer()));
        session.setSelectedMacAlgorithmServerToClient(
                firstCommon(session.getClientMacAlgorithmsServerToClient(), session.getServerMacAlgorithms()));
        session.setSelectedCompressionAlgorithmClientToServer(
                firstCommon(session.getClientCompressionAlgorithms(), session.getServerCompressionAlgorithmsClientToServer()));
        session.setSelectedCompressionAlgorithmServerToClient(
                firstCommon(session.getClientCompressionAlgorithmsServerToClient(), session.getServerCompressionAlgorithms()));
    }

    private String firstCommon(List<String> clientList, List<String> serverList) {
        if (clientList == null || serverList == null) {
            return null;
        }
        for (String alg : clientList) {
            if (serverList.contains(alg)) {
                return alg;
            }
        }
        return null;
    }
}
