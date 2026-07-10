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
        dto.setSelectedEncryptionKeyLength(session.getSelectedEncryptionKeyLength());
        dto.setSelectedIntegrity(session.getSelectedIntegrity());
        dto.setSelectedPrf(session.getSelectedPrf());
        dto.setSelectedDhGroup(session.getSelectedDhGroup());
        dto.setSelectedAuthMethod(session.getSelectedAuthMethod());
        dto.setKeyLifetimeSeconds(session.getKeyLifetimeSeconds());

        dto.setInitiatorIdentity(session.getInitiatorIdentity());
        dto.setResponderIdentity(session.getResponderIdentity());
        dto.setAuthMethod(session.getAuthMethod());

        List<IpsecCertificateInfoDto> initiatorCerts = new ArrayList<>();
        for (IpsecCertificateInfo cert : session.getInitiatorCertificates()) {
            initiatorCerts.add(toCertificateDto(cert));
        }
        dto.setInitiatorCertificates(initiatorCerts);
        List<IpsecCertificateInfoDto> responderCerts = new ArrayList<>();
        for (IpsecCertificateInfo cert : session.getResponderCertificates()) {
            responderCerts.add(toCertificateDto(cert));
        }
        dto.setResponderCertificates(responderCerts);

        dto.setInitiatorNonce(session.getInitiatorNonce());
        dto.setResponderNonce(session.getResponderNonce());
        dto.setInitiatorKeData(session.getInitiatorKeData());
        dto.setResponderKeData(session.getResponderKeData());
        dto.setInitiatorSignature(session.getInitiatorSignature());
        dto.setResponderSignature(session.getResponderSignature());

        int totalCertificates = session.getInitiatorCertificates().size() + session.getResponderCertificates().size();
        dto.setCertificateCount(totalCertificates);
        dto.setVendorIds(new ArrayList<>(session.getVendorIds()));
        dto.setNotifyTypes(new ArrayList<>(session.getNotifyTypes()));
        dto.setDeleteTypes(new ArrayList<>(session.getDeleteTypes()));

        dto.setInitiatorAlgorithms(session.getInitiatorAlgorithms());
        dto.setResponderAlgorithms(session.getResponderAlgorithms());

        dto.setGm(session.isGm());
        dto.setNotes(new ArrayList<>(session.getNotes()));
        dto.setMessages(new ArrayList<>(session.getMessages()));

        dto.setHasDataPlane(session.isHasDataPlane());
        List<IpsecDataPlaneSaDto> dataPlaneDtos = new ArrayList<>();
        for (IpsecDataPlaneSa sa : session.getDataPlaneSas()) {
            dataPlaneDtos.add(toDataPlaneSaDto(sa));
        }
        dto.setDataPlaneSas(dataPlaneDtos);
        return dto;
    }

    private IpsecDataPlaneSaDto toDataPlaneSaDto(IpsecDataPlaneSa sa) {
        IpsecDataPlaneSaDto dto = new IpsecDataPlaneSaDto();
        dto.setProtocol(sa.getProtocol());
        dto.setSpi(sa.getSpi());
        dto.setSpiHex(sa.getSpiHex());
        dto.setSrcIp(sa.getSrcIp());
        dto.setDstIp(sa.getDstIp());
        dto.setPacketCount(sa.getPacketCount());
        dto.setByteCount(sa.getByteCount());
        dto.setFirstSeq(sa.getFirstSeq());
        dto.setLastSeq(sa.getLastSeq());
        dto.setFirstSeenMicros(sa.getFirstSeenMicros());
        dto.setLastSeenMicros(sa.getLastSeenMicros());
        dto.setSampleSequenceNumbers(new ArrayList<>(sa.getSampleSequenceNumbers()));
        return dto;
    }

    private IpsecCertificateInfoDto toCertificateDto(IpsecCertificateInfo cert) {
        IpsecCertificateInfoDto dto = new IpsecCertificateInfoDto();
        dto.setIndex(cert.getIndex());
        dto.setVersion(cert.getVersion());
        dto.setSerialNumber(cert.getSerialNumber());
        dto.setSubject(cert.getSubject());
        dto.setIssuer(cert.getIssuer());
        dto.setNotBefore(cert.getNotBefore());
        dto.setNotAfter(cert.getNotAfter());
        dto.setSignatureAlgorithm(cert.getSignatureAlgorithm());
        dto.setPublicKeyAlgorithm(cert.getPublicKeyAlgorithm());
        dto.setKeyUsage(cert.getKeyUsage());
        dto.setDerBase64(cert.getDerBase64());
        return dto;
    }
}
