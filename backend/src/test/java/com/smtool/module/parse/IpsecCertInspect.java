package com.smtool.module.parse;

import com.smtool.util.CodecUtil;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import java.io.StringReader;

public class IpsecCertInspect {

    public static void main(String[] args) throws Exception {
        String hex = "3078022061468100fb91997e895eec7d0648144dceb19ac837ea40017270d61d3faec2a00220685cba993d5b58bc429093b9f6dabdb31ad1f4d0503c4ea807c12fe0d3a2c01f042068fbed2391050991586818160d2985824c736881e4121e86b90a92d834443a8504109499b3f6cef39cd20e2fa8daea21b521";
        byte[] data = CodecUtil.fromHex(hex);
        System.out.println("len=" + data.length);

        System.out.println("\n-- ASN.1 dump --");
        try (ASN1InputStream ais = new ASN1InputStream(data)) {
            ASN1Primitive obj;
            while ((obj = ais.readObject()) != null) {
                System.out.println(obj);
            }
        }

        System.out.println("\n-- Try X509CertificateHolder --");
        try {
            X509CertificateHolder holder = new X509CertificateHolder(data);
            System.out.println("subject=" + holder.getSubject());
            System.out.println("issuer=" + holder.getIssuer());
            System.out.println("sigAlg=" + holder.getSignatureAlgorithm());
        } catch (Exception e) {
            System.out.println("X509CertificateHolder failed: " + e.getMessage());
        }

        System.out.println("\n-- Try SubjectPublicKeyInfo --");
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(data);
            System.out.println("spki algorithm=" + spki.getAlgorithm());
        } catch (Exception e) {
            System.out.println("SPKI failed: " + e.getMessage());
        }

        System.out.println("\n-- Try PEMParser --");
        try (PEMParser parser = new PEMParser(new StringReader(new String(data)))) {
            Object o = parser.readObject();
            System.out.println("PEM object=" + o);
        } catch (Exception e) {
            System.out.println("PEM failed: " + e.getMessage());
        }
    }
}
