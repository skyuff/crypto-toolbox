package com.smtool.module.parse;

/**
 * IKE 解密密钥日志条目：用于解密加密后的 IKE 载荷。
 */
public class IpsecKeyLogEntry {

    private final String initiatorSpi;
    private final String responderSpi;
    private final byte[] skeyidE;
    private final byte[] skeyidA;
    private final byte[] iv;

    public IpsecKeyLogEntry(String initiatorSpi, String responderSpi,
                            byte[] skeyidE, byte[] skeyidA, byte[] iv) {
        this.initiatorSpi = initiatorSpi;
        this.responderSpi = responderSpi;
        this.skeyidE = skeyidE;
        this.skeyidA = skeyidA;
        this.iv = iv;
    }

    public String getInitiatorSpi() {
        return initiatorSpi;
    }

    public String getResponderSpi() {
        return responderSpi;
    }

    public byte[] getSkeyidE() {
        return skeyidE;
    }

    public byte[] getSkeyidA() {
        return skeyidA;
    }

    public byte[] getIv() {
        return iv;
    }

    public boolean matches(String initSpi, String respSpi) {
        return (initiatorSpi.equalsIgnoreCase(initSpi) && responderSpi.equalsIgnoreCase(respSpi))
                || (initiatorSpi.equalsIgnoreCase(respSpi) && responderSpi.equalsIgnoreCase(initSpi));
    }
}
