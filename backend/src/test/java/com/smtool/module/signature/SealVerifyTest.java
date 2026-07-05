package com.smtool.module.signature;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

/**
 * 生成带真实数字签名的测试 PDF，用于验证电子签章校验功能。
 */
public class SealVerifyTest {

    public static void main(String[] args) throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // 1. 生成 RSA 密钥对与自签证书
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        X500Name dn = new X500Name("CN=Test Signer, O=TestOrg, C=CN");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn, serial, notBefore, notAfter, dn, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));

        // 2. 创建基础 PDF 文档并保存为字节
        ByteArrayOutputStream basePdf = new ByteArrayOutputStream();
        PDDocument baseDoc = new PDDocument();
        PDPage page = new PDPage();
        baseDoc.addPage(page);
        try (PDPageContentStream cs = new PDPageContentStream(baseDoc, page)) {
            cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
            cs.beginText();
            cs.newLineAtOffset(100, 700);
            cs.showText("Test signed document");
            cs.endText();
        }
        baseDoc.save(basePdf);
        baseDoc.close();

        // 3. 从字节重新加载文档并添加数字签名（ExternalSigning 方式）
        PDDocument doc = Loader.loadPDF(basePdf.toByteArray());
        PDSignature pdSignature = new PDSignature();
        pdSignature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        pdSignature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        pdSignature.setName("Test Signer");
        pdSignature.setLocation("Beijing");
        pdSignature.setReason("Testing");
        pdSignature.setSignDate(Calendar.getInstance());
        doc.addSignature(pdSignature);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ExternalSigningSupport ess = doc.saveIncrementalForExternalSigning(baos);
        byte[] content = ess.getContent().readAllBytes();
        byte[] cms = new PdfTestSignatureInterface(kp.getPrivate(), cert).sign(new ByteArrayInputStream(content));
        ess.setSignature(cms);
        doc.close();

        byte[] pdfBytes = baos.toByteArray();
        try (FileOutputStream fos = new FileOutputStream("c:/Users/ifany/Desktop/test-signed.pdf")) {
            fos.write(pdfBytes);
        }
        System.out.println("测试 PDF 已生成: c:/Users/ifany/Desktop/test-signed.pdf");

        // 4. 用服务验证
        SealParseService service = new SealParseService();
        SealVerifyResult result = service.verifyFile(pdfBytes);
        System.out.println("验证结果: " + result);
    }
}
