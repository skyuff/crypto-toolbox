package com.smtool.module.signature;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;

/**
 * PDF 签名测试用的 SignatureInterface 实现。
 */
public class PdfTestSignatureInterface implements SignatureInterface {

    private final PrivateKey privateKey;
    private final X509Certificate certificate;

    public PdfTestSignatureInterface(PrivateKey privateKey, X509Certificate certificate) {
        this.privateKey = privateKey;
        this.certificate = certificate;
    }

    @Override
    public byte[] sign(InputStream content) {
        try {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(privateKey);
            JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
            gen.addSignerInfoGenerator(builder.build(contentSigner, certificate));
            gen.addCertificates(new JcaCertStore(Collections.singletonList(certificate)));

            CMSSignedData cms = gen.generate(new CMSProcessableByteArray(content.readAllBytes()), false);
            return cms.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("PDF 签名失败: " + e.getMessage(), e);
        }
    }
}
