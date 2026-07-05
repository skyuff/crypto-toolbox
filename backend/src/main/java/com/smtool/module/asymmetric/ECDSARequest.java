package com.smtool.module.asymmetric;

import lombok.Data;

@Data
public class ECDSARequest {

    private String curve;
    private String publicKey;
    private String privateKey;
    private String publicKeyFormat;
    private String privateKeyFormat;
    private String hash;
    private String input;
    private String inputFormat;
    private String outputFormat;
    private String signature;
    private String signatureFormat;
}
