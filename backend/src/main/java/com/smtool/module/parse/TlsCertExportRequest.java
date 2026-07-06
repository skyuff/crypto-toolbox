package com.smtool.module.parse;

/**
 * 证书导出请求。
 */
public class TlsCertExportRequest {

    private String derBase64;
    private String filename;

    public String getDerBase64() {
        return derBase64;
    }

    public void setDerBase64(String derBase64) {
        this.derBase64 = derBase64;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }
}
