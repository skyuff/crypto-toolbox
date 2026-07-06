package com.smtool.module.parse;

import java.util.List;
import java.util.Map;

/**
 * SSH 会话 DTO：用于前端展示。
 */
public class SshSessionDto {

    private String id;
    private String protocolVersion;

    private String srcIp;
    private int srcPort;
    private String dstIp;
    private int dstPort;

    private String label;
    private boolean gm;
    private String softwareVersion;

    private String clientBanner;
    private String serverBanner;

    private List<String> clientKexAlgorithms;
    private List<String> clientHostKeyAlgorithms;
    private List<String> clientEncryptionAlgorithms;
    private List<String> clientMacAlgorithms;
    private List<String> clientCompressionAlgorithms;

    private List<String> serverKexAlgorithms;
    private List<String> serverHostKeyAlgorithms;
    private List<String> serverEncryptionAlgorithms;
    private List<String> serverMacAlgorithms;
    private List<String> serverCompressionAlgorithms;

    private String selectedKexAlgorithm;
    private String selectedHostKeyAlgorithm;
    private String selectedEncryptionAlgorithm;
    private String selectedMacAlgorithm;
    private String selectedCompressionAlgorithm;

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

    private Map<String, List<String>> clientAlgorithms;
    private Map<String, List<String>> serverAlgorithms;
    private List<String> notes;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getProtocolVersion() { return protocolVersion; }
    public void setProtocolVersion(String protocolVersion) { this.protocolVersion = protocolVersion; }
    public String getLabel() { return label; }
    public void setLabel(String label) { this.label = label; }
    public boolean isGm() { return gm; }
    public void setGm(boolean gm) { this.gm = gm; }
    public String getSoftwareVersion() { return softwareVersion; }
    public void setSoftwareVersion(String softwareVersion) { this.softwareVersion = softwareVersion; }

    public String getSrcIp() { return srcIp; }
    public void setSrcIp(String srcIp) { this.srcIp = srcIp; }
    public int getSrcPort() { return srcPort; }
    public void setSrcPort(int srcPort) { this.srcPort = srcPort; }
    public String getDstIp() { return dstIp; }
    public void setDstIp(String dstIp) { this.dstIp = dstIp; }
    public int getDstPort() { return dstPort; }
    public void setDstPort(int dstPort) { this.dstPort = dstPort; }

    public String getClientBanner() { return clientBanner; }
    public void setClientBanner(String clientBanner) { this.clientBanner = clientBanner; }
    public String getServerBanner() { return serverBanner; }
    public void setServerBanner(String serverBanner) { this.serverBanner = serverBanner; }

    public List<String> getClientKexAlgorithms() { return clientKexAlgorithms; }
    public void setClientKexAlgorithms(List<String> clientKexAlgorithms) { this.clientKexAlgorithms = clientKexAlgorithms; }
    public List<String> getClientHostKeyAlgorithms() { return clientHostKeyAlgorithms; }
    public void setClientHostKeyAlgorithms(List<String> clientHostKeyAlgorithms) { this.clientHostKeyAlgorithms = clientHostKeyAlgorithms; }
    public List<String> getClientEncryptionAlgorithms() { return clientEncryptionAlgorithms; }
    public void setClientEncryptionAlgorithms(List<String> clientEncryptionAlgorithms) { this.clientEncryptionAlgorithms = clientEncryptionAlgorithms; }
    public List<String> getClientMacAlgorithms() { return clientMacAlgorithms; }
    public void setClientMacAlgorithms(List<String> clientMacAlgorithms) { this.clientMacAlgorithms = clientMacAlgorithms; }
    public List<String> getClientCompressionAlgorithms() { return clientCompressionAlgorithms; }
    public void setClientCompressionAlgorithms(List<String> clientCompressionAlgorithms) { this.clientCompressionAlgorithms = clientCompressionAlgorithms; }

    public List<String> getServerKexAlgorithms() { return serverKexAlgorithms; }
    public void setServerKexAlgorithms(List<String> serverKexAlgorithms) { this.serverKexAlgorithms = serverKexAlgorithms; }
    public List<String> getServerHostKeyAlgorithms() { return serverHostKeyAlgorithms; }
    public void setServerHostKeyAlgorithms(List<String> serverHostKeyAlgorithms) { this.serverHostKeyAlgorithms = serverHostKeyAlgorithms; }
    public List<String> getServerEncryptionAlgorithms() { return serverEncryptionAlgorithms; }
    public void setServerEncryptionAlgorithms(List<String> serverEncryptionAlgorithms) { this.serverEncryptionAlgorithms = serverEncryptionAlgorithms; }
    public List<String> getServerMacAlgorithms() { return serverMacAlgorithms; }
    public void setServerMacAlgorithms(List<String> serverMacAlgorithms) { this.serverMacAlgorithms = serverMacAlgorithms; }
    public List<String> getServerCompressionAlgorithms() { return serverCompressionAlgorithms; }
    public void setServerCompressionAlgorithms(List<String> serverCompressionAlgorithms) { this.serverCompressionAlgorithms = serverCompressionAlgorithms; }

    public String getSelectedKexAlgorithm() { return selectedKexAlgorithm; }
    public void setSelectedKexAlgorithm(String selectedKexAlgorithm) { this.selectedKexAlgorithm = selectedKexAlgorithm; }
    public String getSelectedHostKeyAlgorithm() { return selectedHostKeyAlgorithm; }
    public void setSelectedHostKeyAlgorithm(String selectedHostKeyAlgorithm) { this.selectedHostKeyAlgorithm = selectedHostKeyAlgorithm; }
    public String getSelectedEncryptionAlgorithm() { return selectedEncryptionAlgorithm; }
    public void setSelectedEncryptionAlgorithm(String selectedEncryptionAlgorithm) { this.selectedEncryptionAlgorithm = selectedEncryptionAlgorithm; }
    public String getSelectedMacAlgorithm() { return selectedMacAlgorithm; }
    public void setSelectedMacAlgorithm(String selectedMacAlgorithm) { this.selectedMacAlgorithm = selectedMacAlgorithm; }
    public String getSelectedCompressionAlgorithm() { return selectedCompressionAlgorithm; }
    public void setSelectedCompressionAlgorithm(String selectedCompressionAlgorithm) { this.selectedCompressionAlgorithm = selectedCompressionAlgorithm; }

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

    public Map<String, List<String>> getClientAlgorithms() { return clientAlgorithms; }
    public void setClientAlgorithms(Map<String, List<String>> clientAlgorithms) { this.clientAlgorithms = clientAlgorithms; }
    public Map<String, List<String>> getServerAlgorithms() { return serverAlgorithms; }
    public void setServerAlgorithms(Map<String, List<String>> serverAlgorithms) { this.serverAlgorithms = serverAlgorithms; }
    public List<String> getNotes() { return notes; }
    public void setNotes(List<String> notes) { this.notes = notes; }
}
