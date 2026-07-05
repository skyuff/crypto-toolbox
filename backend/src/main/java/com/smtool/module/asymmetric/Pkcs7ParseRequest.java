package com.smtool.module.asymmetric;

import lombok.Data;

@Data
public class Pkcs7ParseRequest {
    private String input;
    private String format;

    private String cert;
    private String certFormat;
    private String privateKey;
    private String privateKeyFormat;
    private String mode;
    private String message;
    private String messageFormat;
    private String signature;
    private String signatureFormat;
    private String outputFormat;
}
