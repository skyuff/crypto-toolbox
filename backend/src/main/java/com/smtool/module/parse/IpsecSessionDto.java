package com.smtool.module.parse;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * IPSEC / IKE 会话 DTO：用于前端展示。
 */
public class IpsecSessionDto {

    private String id;
    private String protocolVersion;
    private String label;
    private boolean gm;

    private String srcIp;
    private int srcPort;
    private String dstIp;
    private int dstPort;

    private String initiatorSpi;
    private String responderSpi;
    private List<String> exchangeTypes = new ArrayList<>();
    private List<String> messageIds = new ArrayList<>();

    private String selectedEncryption;
    private String selectedIntegrity;
    private String selectedPrf;
    private String selectedDhGroup;

    private String initiatorIdentity;
    private String responderIdentity;
    private String authMethod;

    private int certificateCount;
    private List<String> vendorIds = new ArrayList<>();
    private List<String> notifyTypes = new ArrayList<>();
    private List<String> deleteTypes = new ArrayList<>();

    private Map<String, List<String>> initiatorAlgorithms;
    private Map<String, List<String>> responderAlgorithms;

    private List<String> notes = new ArrayList<>();
    private List<Map<String, Object>> messages = new ArrayList<>();

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getProtocolVersion() { return protocolVersion; }
    public void setProtocolVersion(String protocolVersion) { this.protocolVersion = protocolVersion; }
    public String getLabel() { return label; }
    public void setLabel(String label) { this.label = label; }
    public boolean isGm() { return gm; }
    public void setGm(boolean gm) { this.gm = gm; }

    public String getSrcIp() { return srcIp; }
    public void setSrcIp(String srcIp) { this.srcIp = srcIp; }
    public int getSrcPort() { return srcPort; }
    public void setSrcPort(int srcPort) { this.srcPort = srcPort; }
    public String getDstIp() { return dstIp; }
    public void setDstIp(String dstIp) { this.dstIp = dstIp; }
    public int getDstPort() { return dstPort; }
    public void setDstPort(int dstPort) { this.dstPort = dstPort; }

    public String getInitiatorSpi() { return initiatorSpi; }
    public void setInitiatorSpi(String initiatorSpi) { this.initiatorSpi = initiatorSpi; }
    public String getResponderSpi() { return responderSpi; }
    public void setResponderSpi(String responderSpi) { this.responderSpi = responderSpi; }
    public List<String> getExchangeTypes() { return exchangeTypes; }
    public void setExchangeTypes(List<String> exchangeTypes) { this.exchangeTypes = exchangeTypes; }
    public List<String> getMessageIds() { return messageIds; }
    public void setMessageIds(List<String> messageIds) { this.messageIds = messageIds; }

    public String getSelectedEncryption() { return selectedEncryption; }
    public void setSelectedEncryption(String selectedEncryption) { this.selectedEncryption = selectedEncryption; }
    public String getSelectedIntegrity() { return selectedIntegrity; }
    public void setSelectedIntegrity(String selectedIntegrity) { this.selectedIntegrity = selectedIntegrity; }
    public String getSelectedPrf() { return selectedPrf; }
    public void setSelectedPrf(String selectedPrf) { this.selectedPrf = selectedPrf; }
    public String getSelectedDhGroup() { return selectedDhGroup; }
    public void setSelectedDhGroup(String selectedDhGroup) { this.selectedDhGroup = selectedDhGroup; }

    public String getInitiatorIdentity() { return initiatorIdentity; }
    public void setInitiatorIdentity(String initiatorIdentity) { this.initiatorIdentity = initiatorIdentity; }
    public String getResponderIdentity() { return responderIdentity; }
    public void setResponderIdentity(String responderIdentity) { this.responderIdentity = responderIdentity; }
    public String getAuthMethod() { return authMethod; }
    public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

    public int getCertificateCount() { return certificateCount; }
    public void setCertificateCount(int certificateCount) { this.certificateCount = certificateCount; }
    public List<String> getVendorIds() { return vendorIds; }
    public void setVendorIds(List<String> vendorIds) { this.vendorIds = vendorIds; }
    public List<String> getNotifyTypes() { return notifyTypes; }
    public void setNotifyTypes(List<String> notifyTypes) { this.notifyTypes = notifyTypes; }
    public List<String> getDeleteTypes() { return deleteTypes; }
    public void setDeleteTypes(List<String> deleteTypes) { this.deleteTypes = deleteTypes; }

    public Map<String, List<String>> getInitiatorAlgorithms() { return initiatorAlgorithms; }
    public void setInitiatorAlgorithms(Map<String, List<String>> initiatorAlgorithms) { this.initiatorAlgorithms = initiatorAlgorithms; }
    public Map<String, List<String>> getResponderAlgorithms() { return responderAlgorithms; }
    public void setResponderAlgorithms(Map<String, List<String>> responderAlgorithms) { this.responderAlgorithms = responderAlgorithms; }

    public List<String> getNotes() { return notes; }
    public void setNotes(List<String> notes) { this.notes = notes; }
    public List<Map<String, Object>> getMessages() { return messages; }
    public void setMessages(List<Map<String, Object>> messages) { this.messages = messages; }
}
