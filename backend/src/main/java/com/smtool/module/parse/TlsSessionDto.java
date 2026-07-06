package com.smtool.module.parse;

import java.util.List;
import java.util.Map;

/**
 * TLS 会话 DTO。
 */
public class TlsSessionDto {

    private String id;
    private String protocolVersion;
    private String srcIp;
    private int srcPort;
    private String dstIp;
    private int dstPort;
    private String label;
    private String result;
    private boolean gm;
    private boolean handshakeCompleted;
    private String authMode;
    private Map<String, Object> serverSelectedCipherSuite;
    private String clientRandom;
    private String serverRandom;
    private String serverName;
    private List<Map<String, Object>> clientCipherSuites;
    private String clientCompressionMethods;
    private String serverCompressionMethod;
    private String clientSessionId;
    private String serverSessionId;
    private List<Map<String, Object>> clientExtensions;
    private List<Map<String, Object>> serverExtensions;
    private Map<String, Object> serverKeyExchange;
    private List<TlsCertificateDto> serverCertificateChain;
    private List<TlsCertificateDto> clientCertificateChain;
    private List<String> notes;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getProtocolVersion() {
        return protocolVersion;
    }

    public void setProtocolVersion(String protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public void setSrcIp(String srcIp) {
        this.srcIp = srcIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public String getDstIp() {
        return dstIp;
    }

    public void setDstIp(String dstIp) {
        this.dstIp = dstIp;
    }

    public int getDstPort() {
        return dstPort;
    }

    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public boolean isGm() {
        return gm;
    }

    public void setGm(boolean gm) {
        this.gm = gm;
    }

    public boolean isHandshakeCompleted() {
        return handshakeCompleted;
    }

    public void setHandshakeCompleted(boolean handshakeCompleted) {
        this.handshakeCompleted = handshakeCompleted;
    }

    public String getAuthMode() {
        return authMode;
    }

    public void setAuthMode(String authMode) {
        this.authMode = authMode;
    }

    public Map<String, Object> getServerSelectedCipherSuite() {
        return serverSelectedCipherSuite;
    }

    public void setServerSelectedCipherSuite(Map<String, Object> serverSelectedCipherSuite) {
        this.serverSelectedCipherSuite = serverSelectedCipherSuite;
    }

    public String getClientRandom() {
        return clientRandom;
    }

    public void setClientRandom(String clientRandom) {
        this.clientRandom = clientRandom;
    }

    public String getServerRandom() {
        return serverRandom;
    }

    public void setServerRandom(String serverRandom) {
        this.serverRandom = serverRandom;
    }

    public String getServerName() {
        return serverName;
    }

    public void setServerName(String serverName) {
        this.serverName = serverName;
    }

    public List<Map<String, Object>> getClientCipherSuites() {
        return clientCipherSuites;
    }

    public void setClientCipherSuites(List<Map<String, Object>> clientCipherSuites) {
        this.clientCipherSuites = clientCipherSuites;
    }

    public String getClientCompressionMethods() {
        return clientCompressionMethods;
    }

    public void setClientCompressionMethods(String clientCompressionMethods) {
        this.clientCompressionMethods = clientCompressionMethods;
    }

    public String getServerCompressionMethod() {
        return serverCompressionMethod;
    }

    public void setServerCompressionMethod(String serverCompressionMethod) {
        this.serverCompressionMethod = serverCompressionMethod;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }

    public void setClientSessionId(String clientSessionId) {
        this.clientSessionId = clientSessionId;
    }

    public String getServerSessionId() {
        return serverSessionId;
    }

    public void setServerSessionId(String serverSessionId) {
        this.serverSessionId = serverSessionId;
    }

    public List<Map<String, Object>> getClientExtensions() {
        return clientExtensions;
    }

    public void setClientExtensions(List<Map<String, Object>> clientExtensions) {
        this.clientExtensions = clientExtensions;
    }

    public List<Map<String, Object>> getServerExtensions() {
        return serverExtensions;
    }

    public void setServerExtensions(List<Map<String, Object>> serverExtensions) {
        this.serverExtensions = serverExtensions;
    }

    public Map<String, Object> getServerKeyExchange() {
        return serverKeyExchange;
    }

    public void setServerKeyExchange(Map<String, Object> serverKeyExchange) {
        this.serverKeyExchange = serverKeyExchange;
    }

    public List<TlsCertificateDto> getServerCertificateChain() {
        return serverCertificateChain;
    }

    public void setServerCertificateChain(List<TlsCertificateDto> serverCertificateChain) {
        this.serverCertificateChain = serverCertificateChain;
    }

    public List<TlsCertificateDto> getClientCertificateChain() {
        return clientCertificateChain;
    }

    public void setClientCertificateChain(List<TlsCertificateDto> clientCertificateChain) {
        this.clientCertificateChain = clientCertificateChain;
    }

    public List<String> getNotes() {
        return notes;
    }

    public void setNotes(List<String> notes) {
        this.notes = notes;
    }
}
