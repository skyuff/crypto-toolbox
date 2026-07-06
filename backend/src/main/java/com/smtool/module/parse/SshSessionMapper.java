package com.smtool.module.parse;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * SSH 会话模型 -> DTO 映射。
 */
@Service
public class SshSessionMapper {

    public SshSessionDto toDto(SshSession session) {
        SshSessionDto dto = new SshSessionDto();
        dto.setId(session.getSessionKey());

        String banner = session.getServerBanner() != null ? session.getServerBanner() : session.getClientBanner();
        dto.setProtocolVersion(parseProtocolVersion(banner));
        dto.setSoftwareVersion(parseSoftwareVersion(banner));
        dto.setLabel(detectLabel(banner));

        dto.setSrcIp(session.getClientIp());
        dto.setSrcPort(session.getClientPort());
        dto.setDstIp(session.getServerIp());
        dto.setDstPort(session.getServerPort());

        dto.setClientBanner(session.getClientBanner());
        dto.setServerBanner(session.getServerBanner());

        dto.setClientKexAlgorithms(session.getClientKexAlgorithms());
        dto.setClientHostKeyAlgorithms(session.getClientHostKeyAlgorithms());
        dto.setClientEncryptionAlgorithms(session.getClientEncryptionAlgorithms());
        dto.setClientMacAlgorithms(session.getClientMacAlgorithms());
        dto.setClientCompressionAlgorithms(session.getClientCompressionAlgorithms());

        dto.setServerKexAlgorithms(session.getServerKexAlgorithms());
        dto.setServerHostKeyAlgorithms(session.getServerHostKeyAlgorithms());
        dto.setServerEncryptionAlgorithms(session.getServerEncryptionAlgorithms());
        dto.setServerMacAlgorithms(session.getServerMacAlgorithms());
        dto.setServerCompressionAlgorithms(session.getServerCompressionAlgorithms());

        dto.setSelectedKexAlgorithm(session.getSelectedKexAlgorithm());
        dto.setSelectedHostKeyAlgorithm(session.getSelectedHostKeyAlgorithm());
        dto.setSelectedEncryptionAlgorithmClientToServer(session.getSelectedEncryptionAlgorithmClientToServer());
        dto.setSelectedEncryptionAlgorithmServerToClient(session.getSelectedEncryptionAlgorithmServerToClient());
        dto.setSelectedMacAlgorithmClientToServer(session.getSelectedMacAlgorithmClientToServer());
        dto.setSelectedMacAlgorithmServerToClient(session.getSelectedMacAlgorithmServerToClient());
        dto.setSelectedCompressionAlgorithmClientToServer(session.getSelectedCompressionAlgorithmClientToServer());
        dto.setSelectedCompressionAlgorithmServerToClient(session.getSelectedCompressionAlgorithmServerToClient());

        // 兼容旧字段：取 client->server 方向，若不存在则取 server->client
        dto.setSelectedEncryptionAlgorithm(or(session.getSelectedEncryptionAlgorithmClientToServer(),
                session.getSelectedEncryptionAlgorithmServerToClient()));
        dto.setSelectedMacAlgorithm(or(session.getSelectedMacAlgorithmClientToServer(),
                session.getSelectedMacAlgorithmServerToClient()));
        dto.setSelectedCompressionAlgorithm(or(session.getSelectedCompressionAlgorithmClientToServer(),
                session.getSelectedCompressionAlgorithmServerToClient()));

        dto.setClientDhInitParamHex(session.getClientDhInitParamHex());
        dto.setServerDhReplyParamHex(session.getServerDhReplyParamHex());
        dto.setServerPublicKeyType(session.getServerPublicKeyType());
        dto.setServerPublicKeyHex(session.getServerPublicKeyHex());
        dto.setServerSignatureType(session.getServerSignatureType());
        dto.setServerSignatureValueHex(session.getServerSignatureValueHex());

        dto.setClientAlgorithms(buildAlgorithms(session.getClientKexAlgorithms(),
                session.getClientHostKeyAlgorithms(),
                session.getClientEncryptionAlgorithms(),
                session.getClientMacAlgorithms(),
                session.getClientCompressionAlgorithms()));
        dto.setServerAlgorithms(buildAlgorithms(session.getServerKexAlgorithms(),
                session.getServerHostKeyAlgorithms(),
                session.getServerEncryptionAlgorithms(),
                session.getServerMacAlgorithms(),
                session.getServerCompressionAlgorithms()));

        dto.setGm(detectGm(session));
        dto.setNotes(new ArrayList<>(session.getNotes()));
        return dto;
    }

    private String or(String a, String b) {
        return a != null ? a : b;
    }

    private String parseProtocolVersion(String banner) {
        if (banner == null) {
            return null;
        }
        banner = banner.trim();
        // SSH 横幅格式：SSH-protoversion-softwareversion [SP comments]
        String[] parts = banner.split("-", 3);
        if (parts.length >= 2) {
            return parts[0] + "-" + parts[1];
        }
        return banner;
    }

    private String parseSoftwareVersion(String banner) {
        if (banner == null) {
            return null;
        }
        banner = banner.trim();
        String[] parts = banner.split("-", 3);
        if (parts.length >= 3) {
            int space = parts[2].indexOf(' ');
            return space > 0 ? parts[2].substring(0, space) : parts[2];
        }
        return null;
    }

    private String detectLabel(String banner) {
        if (banner == null) {
            return "SSH";
        }
        String lower = banner.toLowerCase();
        if (lower.startsWith("ssh-1.99") || lower.startsWith("ssh-2.0")) {
            return "SSH 2.0";
        }
        if (lower.startsWith("ssh-1.")) {
            return "SSH 1.x";
        }
        return "SSH";
    }

    private Map<String, List<String>> buildAlgorithms(List<String> kex, List<String> hostKey,
                                                       List<String> encryption, List<String> mac,
                                                       List<String> compression) {
        Map<String, List<String>> map = new LinkedHashMap<>();
        map.put("kex", kex);
        map.put("hostKey", hostKey);
        map.put("encryption", encryption);
        map.put("mac", mac);
        map.put("compression", compression);
        return map;
    }

    private boolean detectGm(SshSession session) {
        return containsGm(session.getSelectedKexAlgorithm())
                || containsGm(session.getSelectedHostKeyAlgorithm())
                || containsGm(session.getSelectedEncryptionAlgorithmClientToServer())
                || containsGm(session.getSelectedEncryptionAlgorithmServerToClient())
                || containsGm(session.getSelectedMacAlgorithmClientToServer())
                || containsGm(session.getSelectedMacAlgorithmServerToClient());
    }

    private boolean containsGm(String algorithm) {
        if (algorithm == null) {
            return false;
        }
        String lower = algorithm.toLowerCase();
        return lower.contains("sm2") || lower.contains("sm3") || lower.contains("sm4");
    }
}
