package com.smtool.module.parse;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * SSH 会话模型：保存从流量包中解析出的 SSH 协商与密钥交换信息。
 */
public class SshSession {

    private String sessionKey;

    private String clientIp;
    private int clientPort;
    private String serverIp;
    private int serverPort;

    private String clientBanner;
    private String serverBanner;

    private List<String> clientKexAlgorithms = new ArrayList<>();
    private List<String> serverKexAlgorithms = new ArrayList<>();
    private List<String> clientHostKeyAlgorithms = new ArrayList<>();
    private List<String> serverHostKeyAlgorithms = new ArrayList<>();

    private List<String> clientEncryptionAlgorithms = new ArrayList<>();
    private List<String> clientEncryptionAlgorithmsServerToClient = new ArrayList<>();
    private List<String> serverEncryptionAlgorithmsClientToServer = new ArrayList<>();
    private List<String> serverEncryptionAlgorithms = new ArrayList<>();
    private List<String> clientMacAlgorithms = new ArrayList<>();
    private List<String> clientMacAlgorithmsServerToClient = new ArrayList<>();
    private List<String> serverMacAlgorithmsClientToServer = new ArrayList<>();
    private List<String> serverMacAlgorithms = new ArrayList<>();

    private List<String> clientCompressionAlgorithms = new ArrayList<>();
    private List<String> clientCompressionAlgorithmsServerToClient = new ArrayList<>();
    private List<String> serverCompressionAlgorithmsClientToServer = new ArrayList<>();
    private List<String> serverCompressionAlgorithms = new ArrayList<>();

    private String selectedKexAlgorithm;
    private String selectedHostKeyAlgorithm;
    private String selectedEncryptionAlgorithmClientToServer;
    private String selectedEncryptionAlgorithmServerToClient;
    private String selectedMacAlgorithmClientToServer;
    private String selectedMacAlgorithmServerToClient;
    private String selectedCompressionAlgorithmClientToServer;
    private String selectedCompressionAlgorithmServerToClient;

    private String clientDhInitParamHex;
    private String serverDhReplyParamHex;
    private String serverPublicKeyType;
    private String serverPublicKeyHex;
    private String serverSignatureType;
    private String serverSignatureValueHex;

    private boolean sawClientKexInit;
    private boolean sawServerKexInit;
    private boolean sawNewKeys;

    private final List<String> notes = new ArrayList<>();

    public String getSessionKey() { return sessionKey; }
    public void setSessionKey(String sessionKey) { this.sessionKey = sessionKey; }

    public String getClientIp() { return clientIp; }
    public void setClientIp(String clientIp) { this.clientIp = clientIp; }
    public int getClientPort() { return clientPort; }
    public void setClientPort(int clientPort) { this.clientPort = clientPort; }
    public String getServerIp() { return serverIp; }
    public void setServerIp(String serverIp) { this.serverIp = serverIp; }
    public int getServerPort() { return serverPort; }
    public void setServerPort(int serverPort) { this.serverPort = serverPort; }

    public String getClientBanner() { return clientBanner; }
    public void setClientBanner(String clientBanner) { this.clientBanner = clientBanner; }
    public String getServerBanner() { return serverBanner; }
    public void setServerBanner(String serverBanner) { this.serverBanner = serverBanner; }

    public List<String> getClientKexAlgorithms() { return clientKexAlgorithms; }
    public void setClientKexAlgorithms(List<String> clientKexAlgorithms) { this.clientKexAlgorithms = clientKexAlgorithms; }
    public List<String> getServerKexAlgorithms() { return serverKexAlgorithms; }
    public void setServerKexAlgorithms(List<String> serverKexAlgorithms) { this.serverKexAlgorithms = serverKexAlgorithms; }
    public List<String> getClientHostKeyAlgorithms() { return clientHostKeyAlgorithms; }
    public void setClientHostKeyAlgorithms(List<String> clientHostKeyAlgorithms) { this.clientHostKeyAlgorithms = clientHostKeyAlgorithms; }
    public List<String> getServerHostKeyAlgorithms() { return serverHostKeyAlgorithms; }
    public void setServerHostKeyAlgorithms(List<String> serverHostKeyAlgorithms) { this.serverHostKeyAlgorithms = serverHostKeyAlgorithms; }

    public List<String> getClientEncryptionAlgorithms() { return clientEncryptionAlgorithms; }
    public void setClientEncryptionAlgorithms(List<String> clientEncryptionAlgorithms) { this.clientEncryptionAlgorithms = clientEncryptionAlgorithms; }
    public List<String> getClientEncryptionAlgorithmsServerToClient() { return clientEncryptionAlgorithmsServerToClient; }
    public void setClientEncryptionAlgorithmsServerToClient(List<String> clientEncryptionAlgorithmsServerToClient) { this.clientEncryptionAlgorithmsServerToClient = clientEncryptionAlgorithmsServerToClient; }
    public List<String> getServerEncryptionAlgorithmsClientToServer() { return serverEncryptionAlgorithmsClientToServer; }
    public void setServerEncryptionAlgorithmsClientToServer(List<String> serverEncryptionAlgorithmsClientToServer) { this.serverEncryptionAlgorithmsClientToServer = serverEncryptionAlgorithmsClientToServer; }
    public List<String> getServerEncryptionAlgorithms() { return serverEncryptionAlgorithms; }
    public void setServerEncryptionAlgorithms(List<String> serverEncryptionAlgorithms) { this.serverEncryptionAlgorithms = serverEncryptionAlgorithms; }
    public List<String> getClientMacAlgorithms() { return clientMacAlgorithms; }
    public void setClientMacAlgorithms(List<String> clientMacAlgorithms) { this.clientMacAlgorithms = clientMacAlgorithms; }
    public List<String> getClientMacAlgorithmsServerToClient() { return clientMacAlgorithmsServerToClient; }
    public void setClientMacAlgorithmsServerToClient(List<String> clientMacAlgorithmsServerToClient) { this.clientMacAlgorithmsServerToClient = clientMacAlgorithmsServerToClient; }
    public List<String> getServerMacAlgorithmsClientToServer() { return serverMacAlgorithmsClientToServer; }
    public void setServerMacAlgorithmsClientToServer(List<String> serverMacAlgorithmsClientToServer) { this.serverMacAlgorithmsClientToServer = serverMacAlgorithmsClientToServer; }
    public List<String> getServerMacAlgorithms() { return serverMacAlgorithms; }
    public void setServerMacAlgorithms(List<String> serverMacAlgorithms) { this.serverMacAlgorithms = serverMacAlgorithms; }

    public List<String> getClientCompressionAlgorithms() { return clientCompressionAlgorithms; }
    public void setClientCompressionAlgorithms(List<String> clientCompressionAlgorithms) { this.clientCompressionAlgorithms = clientCompressionAlgorithms; }
    public List<String> getClientCompressionAlgorithmsServerToClient() { return clientCompressionAlgorithmsServerToClient; }
    public void setClientCompressionAlgorithmsServerToClient(List<String> clientCompressionAlgorithmsServerToClient) { this.clientCompressionAlgorithmsServerToClient = clientCompressionAlgorithmsServerToClient; }
    public List<String> getServerCompressionAlgorithmsClientToServer() { return serverCompressionAlgorithmsClientToServer; }
    public void setServerCompressionAlgorithmsClientToServer(List<String> serverCompressionAlgorithmsClientToServer) { this.serverCompressionAlgorithmsClientToServer = serverCompressionAlgorithmsClientToServer; }
    public List<String> getServerCompressionAlgorithms() { return serverCompressionAlgorithms; }
    public void setServerCompressionAlgorithms(List<String> serverCompressionAlgorithms) { this.serverCompressionAlgorithms = serverCompressionAlgorithms; }

    public String getSelectedKexAlgorithm() { return selectedKexAlgorithm; }
    public void setSelectedKexAlgorithm(String selectedKexAlgorithm) { this.selectedKexAlgorithm = selectedKexAlgorithm; }
    public String getSelectedHostKeyAlgorithm() { return selectedHostKeyAlgorithm; }
    public void setSelectedHostKeyAlgorithm(String selectedHostKeyAlgorithm) { this.selectedHostKeyAlgorithm = selectedHostKeyAlgorithm; }
    public String getSelectedEncryptionAlgorithmClientToServer() { return selectedEncryptionAlgorithmClientToServer; }
    public void setSelectedEncryptionAlgorithmClientToServer(String selectedEncryptionAlgorithmClientToServer) { this.selectedEncryptionAlgorithmClientToServer = selectedEncryptionAlgorithmClientToServer; }
    public String getSelectedEncryptionAlgorithmServerToClient() { return selectedEncryptionAlgorithmServerToClient; }
    public void setSelectedEncryptionAlgorithmServerToClient(String selectedEncryptionAlgorithmServerToClient) { this.selectedEncryptionAlgorithmServerToClient = selectedEncryptionAlgorithmServerToClient; }
    public String getSelectedMacAlgorithmClientToServer() { return selectedMacAlgorithmClientToServer; }
    public void setSelectedMacAlgorithmClientToServer(String selectedMacAlgorithmClientToServer) { this.selectedMacAlgorithmClientToServer = selectedMacAlgorithmClientToServer; }
    public String getSelectedMacAlgorithmServerToClient() { return selectedMacAlgorithmServerToClient; }
    public void setSelectedMacAlgorithmServerToClient(String selectedMacAlgorithmServerToClient) { this.selectedMacAlgorithmServerToClient = selectedMacAlgorithmServerToClient; }
    public String getSelectedCompressionAlgorithmClientToServer() { return selectedCompressionAlgorithmClientToServer; }
    public void setSelectedCompressionAlgorithmClientToServer(String selectedCompressionAlgorithmClientToServer) { this.selectedCompressionAlgorithmClientToServer = selectedCompressionAlgorithmClientToServer; }
    public String getSelectedCompressionAlgorithmServerToClient() { return selectedCompressionAlgorithmServerToClient; }
    public void setSelectedCompressionAlgorithmServerToClient(String selectedCompressionAlgorithmServerToClient) { this.selectedCompressionAlgorithmServerToClient = selectedCompressionAlgorithmServerToClient; }

    public String getClientDhInitParamHex() { return clientDhInitParamHex; }
    public void setClientDhInitParamHex(String clientDhInitParamHex) { this.clientDhInitParamHex = clientDhInitParamHex; }
    public String getServerDhReplyParamHex() { return serverDhReplyParamHex; }
    public void setServerDhReplyParamHex(String serverDhReplyParamHex) { this.serverDhReplyParamHex = serverDhReplyParamHex; }
    public String getServerPublicKeyHex() { return serverPublicKeyHex; }
    public void setServerPublicKeyHex(String serverPublicKeyHex) { this.serverPublicKeyHex = serverPublicKeyHex; }
    public String getServerPublicKeyType() { return serverPublicKeyType; }
    public void setServerPublicKeyType(String serverPublicKeyType) { this.serverPublicKeyType = serverPublicKeyType; }
    public String getServerSignatureType() { return serverSignatureType; }
    public void setServerSignatureType(String serverSignatureType) { this.serverSignatureType = serverSignatureType; }
    public String getServerSignatureValueHex() { return serverSignatureValueHex; }
    public void setServerSignatureValueHex(String serverSignatureValueHex) { this.serverSignatureValueHex = serverSignatureValueHex; }

    public boolean isSawClientKexInit() { return sawClientKexInit; }
    public void setSawClientKexInit(boolean sawClientKexInit) { this.sawClientKexInit = sawClientKexInit; }
    public boolean isSawServerKexInit() { return sawServerKexInit; }
    public void setSawServerKexInit(boolean sawServerKexInit) { this.sawServerKexInit = sawServerKexInit; }
    public boolean isSawNewKeys() { return sawNewKeys; }
    public void setSawNewKeys(boolean sawNewKeys) { this.sawNewKeys = sawNewKeys; }

    public List<String> getNotes() { return notes; }

    /**
     * 聚合所有服务端支持的算法（去重并按列表形式展示）。
     */
    public Map<String, List<String>> getServerAlgorithms() {
        Map<String, List<String>> map = new LinkedHashMap<>();
        map.put("kex", serverKexAlgorithms);
        map.put("hostKey", serverHostKeyAlgorithms);
        map.put("encryption", serverEncryptionAlgorithms);
        map.put("mac", serverMacAlgorithms);
        map.put("compression", serverCompressionAlgorithms);
        return map;
    }
}
