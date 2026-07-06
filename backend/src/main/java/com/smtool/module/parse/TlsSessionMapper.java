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
            gm = isGmSuite(session.getServerCipherSuite());
            dto.setServerSelectedCipherSuite(buildCipherSuite(session.getServerCipherSuite()));
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
        versions.put(0x0101, "GM/T TLCP 1.1（国密）");
        return String.format("0x%04x", value) + " (" + versions.getOrDefault(value, "未知版本") + ")";
    }

    private boolean isGmSuite(int cs) {
        if (cs < 0) {
            return false;
        }
        if ((cs & 0xff00) == 0xe000) {
            return true;
        }
        return cs == 0x00c6 || cs == 0x00c7;
    }

    private Map<String, Object> buildCipherSuite(int cs) {
        Map<Integer, String> cipherSuites = new LinkedHashMap<>();
        cipherSuites.put(0xe011, "ECC_SM4_SM3（国密）");
        cipherSuites.put(0xe013, "ECDHE_SM4_SM3（国密）");
        cipherSuites.put(0xe015, "ECC_SM4_GCM_SM3（国密）");
        cipherSuites.put(0xe019, "IBSDH_SM4_SM3（国密）");
        cipherSuites.put(0xe01c, "RSA_SM4_SM3（国密）");
        cipherSuites.put(0x00c6, "TLS_SM4_GCM_SM3（国密, TLS1.3）");
        cipherSuites.put(0x00c7, "TLS_SM4_CCM_SM3（国密, TLS1.3）");
        cipherSuites.put(0x0000, "TLS_NULL_WITH_NULL_NULL");
        cipherSuites.put(0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA");
        cipherSuites.put(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA");
        cipherSuites.put(0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256");
        cipherSuites.put(0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384");
        cipherSuites.put(0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        cipherSuites.put(0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        cipherSuites.put(0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        cipherSuites.put(0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
        cipherSuites.put(0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        cipherSuites.put(0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        cipherSuites.put(0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
        cipherSuites.put(0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
        cipherSuites.put(0x1301, "TLS_AES_128_GCM_SHA256（TLS1.3）");
        cipherSuites.put(0x1302, "TLS_AES_256_GCM_SHA384（TLS1.3）");
        cipherSuites.put(0x1303, "TLS_CHACHA20_POLY1305_SHA256（TLS1.3）");
        cipherSuites.put(0x00ff, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV");

        Map<String, Object> s = new LinkedHashMap<>();
        s.put("value", String.format("0x%04x", cs));
        s.put("name", cipherSuites.getOrDefault(cs, "未知套件"));
        s.put("gm", isGmSuite(cs));
        return s;
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
