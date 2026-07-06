package com.smtool.module.parse;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * IpsecSession 领域对象 -> 前端展示 DTO 映射。
 */
@Component
public class IpsecSessionMapper {

    public IpsecSessionDto toDto(IpsecSession session) {
        IpsecSessionDto dto = new IpsecSessionDto();
        dto.setId(session.getSessionKey());
        dto.setSrcIp(session.getInitiatorIp());
        dto.setSrcPort(session.getInitiatorPort());
        dto.setDstIp(session.getResponderIp());
        dto.setDstPort(session.getResponderPort());

        String version = session.getIkeVersion();
        if (version == null || version.isBlank()) {
            version = "IPSEC";
        }
        dto.setProtocolVersion(version);
        dto.setLabel(version);

        dto.setInitiatorSpi(session.getInitiatorSpi());
        dto.setResponderSpi(session.getResponderSpi());
        dto.setExchangeTypes(new ArrayList<>(session.getExchangeTypes()));
        dto.setMessageIds(new ArrayList<>(session.getMessageIds()));

        dto.setSelectedEncryption(session.getSelectedEncryption());
        dto.setSelectedIntegrity(session.getSelectedIntegrity());
        dto.setSelectedPrf(session.getSelectedPrf());
        dto.setSelectedDhGroup(session.getSelectedDhGroup());

        dto.setInitiatorIdentity(session.getInitiatorIdentity());
        dto.setResponderIdentity(session.getResponderIdentity());
        dto.setAuthMethod(session.getAuthMethod());

        dto.setCertificateCount(session.getCertificateDerBase64().size());
        dto.setVendorIds(new ArrayList<>(session.getVendorIds()));
        dto.setNotifyTypes(new ArrayList<>(session.getNotifyTypes()));
        dto.setDeleteTypes(new ArrayList<>(session.getDeleteTypes()));

        dto.setInitiatorAlgorithms(session.getInitiatorAlgorithms());
        dto.setResponderAlgorithms(session.getResponderAlgorithms());

        dto.setGm(session.isGm());
        dto.setNotes(new ArrayList<>(session.getNotes()));
        dto.setMessages(new ArrayList<>(session.getMessages()));
        return dto;
    }
}
