package com.smtool.module.parse;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

public class SshTrafficParseDebug {

    public static void main(String[] args) throws Exception {
        byte[] data = Files.readAllBytes(new File("../test/ssh_session_demo.pcap").toPath());

        PcapReader reader = new PcapReader(data);
        List<PcapPacket> packets = reader.readAll();
        System.out.println("packets=" + packets.size());
        for (PcapPacket p : packets) {
            System.out.println("pkt " + p.getSrcIp() + ":" + p.getSrcPort() + " -> " + p.getDstIp() + ":" + p.getDstPort()
                    + " proto=" + p.getProtocol() + " payload=" + (p.getPayload() == null ? 0 : p.getPayload().length));
        }

        TcpReassemblyService reassembly = new TcpReassemblyService();
        Map<TcpReassemblyService.SessionKey, TcpReassemblyService.BidirectionalStream> streams = reassembly.reassemble(packets);
        System.out.println("streams=" + streams.size());
        for (Map.Entry<TcpReassemblyService.SessionKey, TcpReassemblyService.BidirectionalStream> e : streams.entrySet()) {
            System.out.println("stream " + e.getKey() + " aToB=" + e.getValue().aToB.getReassembledData().length
                    + " bToA=" + e.getValue().bToA.getReassembledData().length);
        }

        SshStreamParser parser = new SshStreamParser();
        SshSessionAnalyzer analyzer = new SshSessionAnalyzer(parser);
        SshSessionMapper mapper = new SshSessionMapper();
        for (TcpReassemblyService.BidirectionalStream s : streams.values()) {
            System.out.println("--- parse aToB ---");
            List<SshStreamParser.SshMessage> msgs = parser.parseStream(s.aToB.getReassembledData());
            for (SshStreamParser.SshMessage m : msgs) {
                System.out.println("msg type=" + m.type + " name=" + m.typeName + " payload=" + (m.payload == null ? 0 : m.payload.length));
            }
            System.out.println("--- parse bToA ---");
            msgs = parser.parseStream(s.bToA.getReassembledData());
            for (SshStreamParser.SshMessage m : msgs) {
                System.out.println("msg type=" + m.type + " name=" + m.typeName + " payload=" + (m.payload == null ? 0 : m.payload.length));
            }

            SshSession session = analyzer.analyze(s);
            if (session != null) {
                SshSessionDto dto = mapper.toDto(session);
                System.out.println("--- DTO ---");
                System.out.println("protocolVersion=" + dto.getProtocolVersion());
                System.out.println("softwareVersion=" + dto.getSoftwareVersion());
                System.out.println("label=" + dto.getLabel());
                System.out.println("gm=" + dto.isGm());
                System.out.println("selectedKex=" + dto.getSelectedKexAlgorithm());
                System.out.println("selectedHostKey=" + dto.getSelectedHostKeyAlgorithm());
                System.out.println("selectedEncryptionCs=" + dto.getSelectedEncryptionAlgorithmClientToServer());
                System.out.println("selectedEncryptionSc=" + dto.getSelectedEncryptionAlgorithmServerToClient());
                System.out.println("selectedMacCs=" + dto.getSelectedMacAlgorithmClientToServer());
                System.out.println("selectedMacSc=" + dto.getSelectedMacAlgorithmServerToClient());
                System.out.println("serverPublicKeyType=" + dto.getServerPublicKeyType());
                System.out.println("serverDhReplyParamHex=" + dto.getServerDhReplyParamHex());
                System.out.println("serverSignatureType=" + dto.getServerSignatureType());
                System.out.println("serverKex=" + dto.getServerKexAlgorithms());
                System.out.println("serverEncryption=" + dto.getServerEncryptionAlgorithms());
                System.out.println("clientEncryption=" + dto.getClientEncryptionAlgorithms());
            }
        }
    }
}
