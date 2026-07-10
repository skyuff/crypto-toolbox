package com.smtool.module.parse;

import com.smtool.module.cert.CertCheckService;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 将 TlsSession 领域对象转换为前端展示 DTO。
 */
@Component
public class TlsSessionMapper {

    private final CertCheckService certCheckService;

    public TlsSessionMapper(CertCheckService certCheckService) {
        this.certCheckService = certCheckService;
    }

    public TlsSessionDto toDto(TlsSession session) {
        TlsSessionDto dto = new TlsSessionDto();
        dto.setId(session.getClientIp() + ":" + session.getClientPort() + " -> " + session.getServerIp() + ":" + session.getServerPort());
        dto.setSrcIp(session.getClientIp());
        dto.setSrcPort(session.getClientPort());
        dto.setDstIp(session.getServerIp());
        dto.setDstPort(session.getServerPort());

        int version = session.getServerHelloVersion() != null ? session.getServerHelloVersion()
                : (session.getClientHelloVersion() != null ? session.getClientHelloVersion() : 0);
        dto.setProtocolVersion(describeVersion(version));

        boolean gm = false;
        if (session.getServerCipherSuite() != null) {
            gm = TlsCipherSuites.isGmSuite(session.getServerCipherSuite());
            dto.setServerSelectedCipherSuite(buildCipherSuite(session.getServerCipherSuite()));
        }
        if (gm || (version == 0x0101)) {
            dto.setLabel("TLCP");
        } else if (version == 0x0304) {
            dto.setLabel("TLS 1.3");
        } else {
            dto.setLabel("TLS");
        }
        dto.setGm(gm || version == 0x0101);
        dto.setResult(dto.getLabel());

        // 握手完成判定：
        // 1) 直接看到明文 Finished（TLS 1.0/1.1 或部分未加密场景）
        // 2) 双向均出现 ChangeCipherSpec（TLS/TLCP 1.2 中 CCS 后立即发送 Finished，双向 CCS 即表示握手完成）
        // 3) 出现 Application Data（TLS 1.3 或已加密的 TLCP 1.2，表明密钥协商已完成）
        boolean handshakeCompleted = session.isSawServerHello()
                && (session.isSawServerFinished() || session.isSawClientFinished()
                || (session.isSawClientChangeCipherSpec() && session.isSawServerChangeCipherSpec())
                || session.isSawApplicationData());
        dto.setHandshakeCompleted(handshakeCompleted);

        if (session.isSawClientCertificate() || session.isSawCertificateRequest()) {
            dto.setAuthMode("双向认证");
        } else {
            dto.setAuthMode("单向认证");
        }

        dto.setClientRandom(session.getClientRandom());
        dto.setServerRandom(session.getServerRandom());
        dto.setClientSessionId(session.getClientSessionId());
        dto.setServerSessionId(session.getServerSessionId());
        dto.setServerName(session.getServerName());
        dto.setClientCipherSuites(mapCipherSuites(session.getClientCipherSuites()));
        dto.setClientCompressionMethods(session.getClientCompressionMethods());
        dto.setServerCompressionMethod(session.getServerCompressionMethod());
        dto.setClientExtensions(session.getClientExtensions());
        dto.setServerExtensions(session.getServerExtensions());
        dto.setServerKeyExchange(session.getServerKeyExchange());
        dto.setServerCertificateChain(mapCerts(session.getServerCertChainDer(), session.getNotes()));
        dto.setClientCertificateChain(mapCerts(session.getClientCertChainDer(), session.getNotes()));

        if (session.getServerCipherSuite() == null) {
            if (session.isSawClientHello()) {
                session.getNotes().add("未检测到服务端 ServerHello，无法确定服务端选择的密码套件。可能原因：服务端不支持该协议版本、连接被拒绝或抓包不完整。");
            } else {
                session.getNotes().add("未检测到客户端 ClientHello，无法识别为 TLS/TLCP 握手流量。");
            }
        }

        dto.setNotes(session.getNotes());
        return dto;
    }

    private List<Map<String, Object>> mapCipherSuites(List<Integer> cipherSuites) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (cipherSuites == null) {
            return list;
        }
        for (int cs : cipherSuites) {
            list.add(buildCipherSuite(cs));
        }
        return list;
    }

    private String describeVersion(int value) {
        if (value < 0) {
            return null;
        }
        Map<Integer, String> versions = new LinkedHashMap<>();
        versions.put(0x0300, "SSL 3.0");
        versions.put(0x0301, "TLS 1.0");
        versions.put(0x0302, "TLS 1.1");
        versions.put(0x0303, "TLS 1.2");
        versions.put(0x0304, "TLS 1.3");
        versions.put(0x0101, "GM/T TLCP 1.1");
        return String.format("0x%04x", value) + " [" + versions.getOrDefault(value, "未知版本") + "]";
    }

    private Map<String, Object> buildCipherSuite(int cs) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("value", String.format("0x%04x", cs));
        s.put("name", TlsCipherSuites.getName(cs));
        s.put("gm", TlsCipherSuites.isGmSuite(cs));
        return s;
    }

    private List<TlsCertificateDto> mapCerts(List<byte[]> certDers, List<String> notes) {
        List<TlsCertificateDto> list = new ArrayList<>();
        if (certDers == null) {
            return list;
        }
        for (int i = 0; i < certDers.size(); i++) {
            byte[] der = certDers.get(i);
            try {
                Map<String, Object> info = certCheckService.check(der);
                TlsCertificateDto dto = new TlsCertificateDto();
                dto.setVersion((String) info.get("version"));
                dto.setSerialNumber((String) info.get("serialNumber"));
                dto.setSubject((String) info.get("subject"));
                dto.setIssuer((String) info.get("issuer"));
                String notBefore = (String) info.get("notBefore");
                String notAfter = (String) info.get("notAfter");
                dto.setNotBefore(notBefore);
                dto.setNotAfter(notAfter);
                dto.setValidityPeriod(formatValidity(notBefore, notAfter));
                dto.setExpired(Boolean.TRUE.equals(info.get("expired")));
                dto.setSignatureAlgorithm((Map<String, Object>) info.get("signatureAlgorithm"));
                dto.setPublicKeyAlgorithm((String) info.get("publicKeyAlgorithm"));
                dto.setPublicKeyHex((String) info.get("publicKeyHex"));
                dto.setKeyUsage(extractKeyUsage(info));
                dto.setSm2(Boolean.TRUE.equals(info.get("isSm2")));
                dto.setDerBase64(java.util.Base64.getEncoder().encodeToString(der));
                dto.setExtensions((List<Map<String, Object>>) info.get("extensions"));
                dto.setChecks((List<Map<String, Object>>) info.get("checks"));
                list.add(dto);
            } catch (Exception e) {
                // 解析失败时不静默丢弃，保留原始 DER 并记录失败原因
                notes.add("证书#" + (i + 1) + "解析失败: " + e.getMessage());
                TlsCertificateDto fallback = new TlsCertificateDto();
                fallback.setSubject("证书解析失败");
                fallback.setDerBase64(java.util.Base64.getEncoder().encodeToString(der));
                list.add(fallback);
            }
        }
        return list;
    }

    private String extractKeyUsage(Map<String, Object> info) {
        List<Map<String, Object>> exts = (List<Map<String, Object>>) info.get("extensions");
        if (exts == null) {
            return null;
        }
        for (Map<String, Object> ext : exts) {
            if ("2.5.29.15".equals(ext.get("oid"))) {
                String desc = (String) ext.get("description");
                if (desc != null && desc.startsWith("密钥用法: ")) {
                    return desc.substring("密钥用法: ".length());
                }
                return desc;
            }
        }
        return null;
    }

    private String formatValidity(String notBefore, String notAfter) {
        if (notBefore == null && notAfter == null) {
            return null;
        }
        return (notBefore == null ? "-" : notBefore) + " ~ " + (notAfter == null ? "-" : notAfter);
    }
}
