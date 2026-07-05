package com.smtool.module.asymmetric;

import lombok.Data;

@Data
public class RSARequest {

    private Integer keySize;
    private String publicKey;
    private String privateKey;
    private String publicKeyFormat;
    private String privateKeyFormat;
    private String padding;
    private String algorithm;
    private String input;
    private String inputFormat;
    private String outputFormat;
    private String signature;
    private String signatureFormat;
}
