package com.smtool.module.parse;

import com.smtool.module.cert.CertCheckService;
import com.smtool.util.CodecUtil;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 将 TlsSession 领域对象转换为前端展示 DTO。
 */
@Component
public class TlsSessionMapper {

    private final CertCheckService certCheckService;
    private final TlsParseService tlsParseService;

    public TlsSessionMapper(CertCheckService certCheckService, TlsParseService tlsParseService) {
        this.certCheckService = certCheckService;
        this.tlsParseService = tlsParseService;
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
        dto.setProtocolVersion(tlsParseService.describeVersion(version));

        boolean gm = false;
        if (session.getServerCipherSuite() != null) {
            gm = tlsParseService.isGmSuite(session.getServerCipherSuite());
            dto.setServerSelectedCipherSuite(tlsParseService.buildCipherSuite(session.getServerCipherSuite()));
        }
        if (gm || (version == 0x0101)) {
            dto.setLabel("TLCP");
        } else if (version == 0x0304) {
            dto.setLabel("TLS 1.3");
        } else {
            dto.setLabel("TLS");
        }

        dto.setHandshakeCompleted(session.isSawServerHello()
                && (session.isSawServerFinished() || session.isSawClientFinished()));

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
        dto.setServerCertificateChain(mapCerts(session.getServerCertChainDer()));
        dto.setClientCertificateChain(mapCerts(session.getClientCertChainDer()));
        dto.setNotes(session.getNotes());
        return dto;
    }

    private List<Map<String, Object>> mapCipherSuites(List<Integer> cipherSuites) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (cipherSuites == null) {
            return list;
        }
        for (int cs : cipherSuites) {
            list.add(tlsParseService.buildCipherSuite(cs));
        }
        return list;
    }

    private List<TlsCertificateDto> mapCerts(List<byte[]> certDers) {
        List<TlsCertificateDto> list = new ArrayList<>();
        if (certDers == null) {
            return list;
        }
        for (byte[] der : certDers) {
            try {
                Map<String, Object> info = certCheckService.check(der);
                TlsCertificateDto dto = new TlsCertificateDto();
                dto.setVersion((String) info.get("version"));
                dto.setSerialNumber((String) info.get("serialNumber"));
                dto.setSubject((String) info.get("subject"));
                dto.setIssuer((String) info.get("issuer"));
                dto.setNotBefore((String) info.get("notBefore"));
                dto.setNotAfter((String) info.get("notAfter"));
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
                // skip invalid cert
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
                return (String) ext.get("description");
            }
        }
        return null;
    }
}
