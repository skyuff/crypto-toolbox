package com.smtool.module.parse;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * TLS/TLCP 会话领域模型。
 */
public class TlsSession {

    private String sessionKey;
    private String clientIp;
    private int clientPort;
    private String serverIp;
    private int serverPort;

    private Integer clientHelloVersion;
    private Integer serverHelloVersion;
    private String clientRandom;
    private String serverRandom;
    private Integer serverCipherSuite;
    private String serverName;
    private List<Integer> clientCipherSuites = new ArrayList<>();
    private String clientCompressionMethods;
    private String serverCompressionMethod;
    private String clientSessionId;
    private String serverSessionId;
    private List<Map<String, Object>> clientExtensions = new ArrayList<>();
    private List<Map<String, Object>> serverExtensions = new ArrayList<>();

    private List<byte[]> serverCertChainDer = new ArrayList<>();
    private List<byte[]> clientCertChainDer = new ArrayList<>();

    private boolean sawClientHello;
    private boolean sawServerHello;
    private boolean sawCertificateRequest;
    private boolean sawClientCertificate;
    private boolean sawServerFinished;
    private boolean sawClientFinished;

    private List<String> notes = new ArrayList<>();

    public String getSessionKey() {
        return sessionKey;
    }

    public void setSessionKey(String sessionKey) {
        this.sessionKey = sessionKey;
    }

    public String getClientIp() {
        return clientIp;
    }

    public void setClientIp(String clientIp) {
        this.clientIp = clientIp;
    }

    public int getClientPort() {
        return clientPort;
    }

    public void setClientPort(int clientPort) {
        this.clientPort = clientPort;
    }

    public String getServerIp() {
        return serverIp;
    }

    public void setServerIp(String serverIp) {
        this.serverIp = serverIp;
    }

    public int getServerPort() {
        return serverPort;
    }

    public void setServerPort(int serverPort) {
        this.serverPort = serverPort;
    }

    public Integer getClientHelloVersion() {
        return clientHelloVersion;
    }

    public void setClientHelloVersion(Integer clientHelloVersion) {
        this.clientHelloVersion = clientHelloVersion;
    }

    public Integer getServerHelloVersion() {
        return serverHelloVersion;
    }

    public void setServerHelloVersion(Integer serverHelloVersion) {
        this.serverHelloVersion = serverHelloVersion;
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

    public Integer getServerCipherSuite() {
        return serverCipherSuite;
    }

    public void setServerCipherSuite(Integer serverCipherSuite) {
        this.serverCipherSuite = serverCipherSuite;
    }

    public String getServerName() {
        return serverName;
    }

    public void setServerName(String serverName) {
        this.serverName = serverName;
    }

    public List<Integer> getClientCipherSuites() {
        return clientCipherSuites;
    }

    public void setClientCipherSuites(List<Integer> clientCipherSuites) {
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

    public List<byte[]> getServerCertChainDer() {
        return serverCertChainDer;
    }

    public List<byte[]> getClientCertChainDer() {
        return clientCertChainDer;
    }

    public boolean isSawClientHello() {
        return sawClientHello;
    }

    public void setSawClientHello(boolean sawClientHello) {
        this.sawClientHello = sawClientHello;
    }

    public boolean isSawServerHello() {
        return sawServerHello;
    }

    public void setSawServerHello(boolean sawServerHello) {
        this.sawServerHello = sawServerHello;
    }

    public boolean isSawCertificateRequest() {
        return sawCertificateRequest;
    }

    public void setSawCertificateRequest(boolean sawCertificateRequest) {
        this.sawCertificateRequest = sawCertificateRequest;
    }

    public boolean isSawClientCertificate() {
        return sawClientCertificate;
    }

    public void setSawClientCertificate(boolean sawClientCertificate) {
        this.sawClientCertificate = sawClientCertificate;
    }

    public boolean isSawServerFinished() {
        return sawServerFinished;
    }

    public void setSawServerFinished(boolean sawServerFinished) {
        this.sawServerFinished = sawServerFinished;
    }

    public boolean isSawClientFinished() {
        return sawClientFinished;
    }

    public void setSawClientFinished(boolean sawClientFinished) {
        this.sawClientFinished = sawClientFinished;
    }

    public List<String> getNotes() {
        return notes;
    }
}
