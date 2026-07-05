package com.smtool.module.signature;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * PDF 电子签章真实校验器：
 * 提取 PDSignature，用 BouncyCastle CMS 验证签名有效性，并输出签章人证书信息。
 */
public class PdfSealVerifier {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static List<Map<String, Object>> verify(byte[] fileBytes) throws Exception {
        List<Map<String, Object>> list = new ArrayList<>();
        try (PDDocument doc = Loader.loadPDF(fileBytes)) {
            List<PDSignature> signs = doc.getSignatureDictionaries();
            if (signs == null || signs.isEmpty()) {
                return list;
            }
            int idx = 1;
            for (PDSignature sig : signs) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("index", idx++);
                item.put("name", sig.getName());
                item.put("location", sig.getLocation());
                item.put("reason", sig.getReason());
                item.put("subFilter", sig.getSubFilter());
                item.put("signTime", formatDate(sig.getSignDate() == null ? null : sig.getSignDate().getTime()));

                byte[] content = sig.getContents(fileBytes);
                byte[] signedBytes = sig.getSignedContent(fileBytes);

                item.put("signatureValueLength", content == null ? 0 : content.length);

                boolean valid = false;
                String verifyMsg = "无法验证";
                Map<String, Object> certInfo = new LinkedHashMap<>();

                try {
                    CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(signedBytes), content);
                    Store<X509CertificateHolder> certs = cms.getCertificates();
                    SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();

                    if (certs.getMatches(signer.getSID()).isEmpty()) {
                        verifyMsg = "未找到签名者证书";
                    } else {
                        X509CertificateHolder holder = (X509CertificateHolder) certs.getMatches(signer.getSID()).iterator().next();
                        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
                        valid = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
                        verifyMsg = valid ? "签名验证通过" : "签名验证失败";

                        certInfo.put("subject", cert.getSubjectX500Principal().toString());
                        certInfo.put("issuer", cert.getIssuerX500Principal().toString());
                        certInfo.put("serialNumber", cert.getSerialNumber().toString(16));
                        certInfo.put("notBefore", formatDate(cert.getNotBefore()));
                        certInfo.put("notAfter", formatDate(cert.getNotAfter()));
                        certInfo.put("algorithm", cert.getSigAlgName());
                    }
                } catch (Exception e) {
                    verifyMsg = "验证异常: " + e.getMessage();
                }

                item.put("verified", valid);
                item.put("verifyMessage", verifyMsg);
                item.put("certificate", certInfo);
                list.add(item);
            }
        }
        return list;
    }

    private static String formatDate(Date date) {
        if (date == null) {
            return "";
        }
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(date);
    }
}
