package com.smtool.module.parse;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * IPSEC / IKE 会话领域模型：保存从流量包中解析出的 IKE 协商信息。
 */
public class IpsecSession {

    private String sessionKey;

    private String initiatorIp;
    private int initiatorPort;
    private String responderIp;
    private int responderPort;

    private String initiatorSpi;
    private String responderSpi;
    private String ikeVersion;

    private List<String> exchangeTypes = new ArrayList<>();
    private List<String> messageIds = new ArrayList<>();

    private List<String> initiatorProposalsEncryption = new ArrayList<>();
    private List<String> initiatorProposalsIntegrity = new ArrayList<>();
    private List<String> initiatorProposalsPrf = new ArrayList<>();
    private List<String> initiatorProposalsDhGroup = new ArrayList<>();

    private List<String> responderProposalsEncryption = new ArrayList<>();
    private List<String> responderProposalsIntegrity = new ArrayList<>();
    private List<String> responderProposalsPrf = new ArrayList<>();
    private List<String> responderProposalsDhGroup = new ArrayList<>();

    private String selectedEncryption;
    private Integer selectedEncryptionKeyLength;
    private String selectedIntegrity;
    private String selectedPrf;
    private String selectedDhGroup;
    private String selectedAuthMethod;
    private Long keyLifetimeSeconds;

    private String initiatorIdentity;
    private String responderIdentity;
    private String authMethod;

    private List<IpsecCertificateInfo> initiatorCertificates = new ArrayList<>();
    private List<IpsecCertificateInfo> responderCertificates = new ArrayList<>();

    private String initiatorNonce;
    private String responderNonce;
    private String initiatorKeData;
    private String responderKeData;
    private String initiatorSignature;
    private String responderSignature;

    private List<String> certificateDerBase64 = new ArrayList<>();
    private List<String> vendorIds = new ArrayList<>();
    private List<String> notifyTypes = new ArrayList<>();
    private List<String> deleteTypes = new ArrayList<>();

    private boolean gm;
    private List<String> notes = new ArrayList<>();

    /** 是否存在 ESP/AH 数据面流量 */
    private boolean hasDataPlane;
    /** ESP/AH 数据面 SA 列表 */
    private List<IpsecDataPlaneSa> dataPlaneSas = new ArrayList<>();

    /** 每条 ISAKMP 消息的解析结果，包含 direction 字段 */
    private List<Map<String, Object>> messages = new ArrayList<>();

    public String getSessionKey() { return sessionKey; }
    public void setSessionKey(String sessionKey) { this.sessionKey = sessionKey; }

    public String getInitiatorIp() { return initiatorIp; }
    public void setInitiatorIp(String initiatorIp) { this.initiatorIp = initiatorIp; }
    public int getInitiatorPort() { return initiatorPort; }
    public void setInitiatorPort(int initiatorPort) { this.initiatorPort = initiatorPort; }
    public String getResponderIp() { return responderIp; }
    public void setResponderIp(String responderIp) { this.responderIp = responderIp; }
    public int getResponderPort() { return responderPort; }
    public void setResponderPort(int responderPort) { this.responderPort = responderPort; }

    public String getInitiatorSpi() { return initiatorSpi; }
    public void setInitiatorSpi(String initiatorSpi) { this.initiatorSpi = initiatorSpi; }
    public String getResponderSpi() { return responderSpi; }
    public void setResponderSpi(String responderSpi) { this.responderSpi = responderSpi; }
    public String getIkeVersion() { return ikeVersion; }
    public void setIkeVersion(String ikeVersion) { this.ikeVersion = ikeVersion; }

    public List<String> getExchangeTypes() { return exchangeTypes; }
    public void setExchangeTypes(List<String> exchangeTypes) { this.exchangeTypes = exchangeTypes; }
    public List<String> getMessageIds() { return messageIds; }
    public void setMessageIds(List<String> messageIds) { this.messageIds = messageIds; }

    public List<String> getInitiatorProposalsEncryption() { return initiatorProposalsEncryption; }
    public void setInitiatorProposalsEncryption(List<String> initiatorProposalsEncryption) { this.initiatorProposalsEncryption = initiatorProposalsEncryption; }
    public List<String> getInitiatorProposalsIntegrity() { return initiatorProposalsIntegrity; }
    public void setInitiatorProposalsIntegrity(List<String> initiatorProposalsIntegrity) { this.initiatorProposalsIntegrity = initiatorProposalsIntegrity; }
    public List<String> getInitiatorProposalsPrf() { return initiatorProposalsPrf; }
    public void setInitiatorProposalsPrf(List<String> initiatorProposalsPrf) { this.initiatorProposalsPrf = initiatorProposalsPrf; }
    public List<String> getInitiatorProposalsDhGroup() { return initiatorProposalsDhGroup; }
    public void setInitiatorProposalsDhGroup(List<String> initiatorProposalsDhGroup) { this.initiatorProposalsDhGroup = initiatorProposalsDhGroup; }

    public List<String> getResponderProposalsEncryption() { return responderProposalsEncryption; }
    public void setResponderProposalsEncryption(List<String> responderProposalsEncryption) { this.responderProposalsEncryption = responderProposalsEncryption; }
    public List<String> getResponderProposalsIntegrity() { return responderProposalsIntegrity; }
    public void setResponderProposalsIntegrity(List<String> responderProposalsIntegrity) { this.responderProposalsIntegrity = responderProposalsIntegrity; }
    public List<String> getResponderProposalsPrf() { return responderProposalsPrf; }
    public void setResponderProposalsPrf(List<String> responderProposalsPrf) { this.responderProposalsPrf = responderProposalsPrf; }
    public List<String> getResponderProposalsDhGroup() { return responderProposalsDhGroup; }
    public void setResponderProposalsDhGroup(List<String> responderProposalsDhGroup) { this.responderProposalsDhGroup = responderProposalsDhGroup; }

    public String getSelectedEncryption() { return selectedEncryption; }
    public void setSelectedEncryption(String selectedEncryption) { this.selectedEncryption = selectedEncryption; }
    public String getSelectedIntegrity() { return selectedIntegrity; }
    public void setSelectedIntegrity(String selectedIntegrity) { this.selectedIntegrity = selectedIntegrity; }
    public String getSelectedPrf() { return selectedPrf; }
    public void setSelectedPrf(String selectedPrf) { this.selectedPrf = selectedPrf; }
    public String getSelectedDhGroup() { return selectedDhGroup; }
    public void setSelectedDhGroup(String selectedDhGroup) { this.selectedDhGroup = selectedDhGroup; }
    public Integer getSelectedEncryptionKeyLength() { return selectedEncryptionKeyLength; }
    public void setSelectedEncryptionKeyLength(Integer selectedEncryptionKeyLength) { this.selectedEncryptionKeyLength = selectedEncryptionKeyLength; }
    public String getSelectedAuthMethod() { return selectedAuthMethod; }
    public void setSelectedAuthMethod(String selectedAuthMethod) { this.selectedAuthMethod = selectedAuthMethod; }
    public Long getKeyLifetimeSeconds() { return keyLifetimeSeconds; }
    public void setKeyLifetimeSeconds(Long keyLifetimeSeconds) { this.keyLifetimeSeconds = keyLifetimeSeconds; }

    public String getInitiatorIdentity() { return initiatorIdentity; }
    public void setInitiatorIdentity(String initiatorIdentity) { this.initiatorIdentity = initiatorIdentity; }
    public String getResponderIdentity() { return responderIdentity; }
    public void setResponderIdentity(String responderIdentity) { this.responderIdentity = responderIdentity; }
    public String getAuthMethod() { return authMethod; }
    public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

    public List<IpsecCertificateInfo> getInitiatorCertificates() { return initiatorCertificates; }
    public void setInitiatorCertificates(List<IpsecCertificateInfo> initiatorCertificates) { this.initiatorCertificates = initiatorCertificates; }
    public List<IpsecCertificateInfo> getResponderCertificates() { return responderCertificates; }
    public void setResponderCertificates(List<IpsecCertificateInfo> responderCertificates) { this.responderCertificates = responderCertificates; }

    public String getInitiatorNonce() { return initiatorNonce; }
    public void setInitiatorNonce(String initiatorNonce) { this.initiatorNonce = initiatorNonce; }
    public String getResponderNonce() { return responderNonce; }
    public void setResponderNonce(String responderNonce) { this.responderNonce = responderNonce; }
    public String getInitiatorKeData() { return initiatorKeData; }
    public void setInitiatorKeData(String initiatorKeData) { this.initiatorKeData = initiatorKeData; }
    public String getResponderKeData() { return responderKeData; }
    public void setResponderKeData(String responderKeData) { this.responderKeData = responderKeData; }
    public String getInitiatorSignature() { return initiatorSignature; }
    public void setInitiatorSignature(String initiatorSignature) { this.initiatorSignature = initiatorSignature; }
    public String getResponderSignature() { return responderSignature; }
    public void setResponderSignature(String responderSignature) { this.responderSignature = responderSignature; }

    public List<String> getCertificateDerBase64() { return certificateDerBase64; }
    public List<String> getVendorIds() { return vendorIds; }
    public List<String> getNotifyTypes() { return notifyTypes; }
    public List<String> getDeleteTypes() { return deleteTypes; }

    public boolean isGm() { return gm; }
    public void setGm(boolean gm) { this.gm = gm; }
    public List<String> getNotes() { return notes; }

    public List<Map<String, Object>> getMessages() { return messages; }
    public void setMessages(List<Map<String, Object>> messages) { this.messages = messages; }

    public boolean isHasDataPlane() { return hasDataPlane; }
    public void setHasDataPlane(boolean hasDataPlane) { this.hasDataPlane = hasDataPlane; }

    public List<IpsecDataPlaneSa> getDataPlaneSas() { return dataPlaneSas; }
    public void setDataPlaneSas(List<IpsecDataPlaneSa> dataPlaneSas) { this.dataPlaneSas = dataPlaneSas; }

    /**
     * 聚合发起方算法提案（用于前端展示）。
     */
    public Map<String, List<String>> getInitiatorAlgorithms() {
        Map<String, List<String>> map = new LinkedHashMap<>();
        map.put("encryption", initiatorProposalsEncryption);
        map.put("integrity", initiatorProposalsIntegrity);
        map.put("prf", initiatorProposalsPrf);
        map.put("dhGroup", initiatorProposalsDhGroup);
        return map;
    }

    /**
     * 聚合响应方算法提案（用于前端展示）。
     */
    public Map<String, List<String>> getResponderAlgorithms() {
        Map<String, List<String>> map = new LinkedHashMap<>();
        map.put("encryption", responderProposalsEncryption);
        map.put("integrity", responderProposalsIntegrity);
        map.put("prf", responderProposalsPrf);
        map.put("dhGroup", responderProposalsDhGroup);
        return map;
    }
}
