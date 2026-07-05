package com.smtool.module.signature;

import com.smtool.util.CodecUtil;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * OFD 电子签章解析器（GB/T 33190 / GM/T 0099）：
 * OFD 本质为 ZIP 包，签章数据位于 Signatures/Sign_N 目录下。
 * 本实现提取 SignedValue.dat 并用 CMS 验证签名（如为 CMS 格式）。
 */
public class OfdSealVerifier {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static List<Map<String, Object>> verify(byte[] fileBytes) throws Exception {
        List<Map<String, Object>> list = new ArrayList<>();
        Map<String, byte[]> entries = readZip(fileBytes);

        // 收集签章目录
        Set<String> signDirs = new LinkedHashSet<>();
        for (String name : entries.keySet()) {
            if (name.startsWith("Signatures/Sign_") && name.contains("/")) {
                signDirs.add(name.substring(0, name.indexOf('/', "Signatures/Sign_".length())));
            }
        }

        if (signDirs.isEmpty()) {
            return list;
        }

        int idx = 1;
        for (String dir : signDirs) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("index", idx++);
            item.put("directory", dir);

            byte[] signedValue = entries.get(dir + "/SignedValue.dat");
            byte[] seal = entries.get(dir + "/Seal.esl");

            boolean valid = false;
            String verifyMsg = "无法验证";
            Map<String, Object> certInfo = new LinkedHashMap<>();

            if (signedValue == null) {
                verifyMsg = "未找到 SignedValue.dat";
            } else {
                item.put("signedValueLength", signedValue.length);
                try {
                    CMSSignedData cms = new CMSSignedData(signedValue);
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
                        certInfo.put("notBefore", cert.getNotBefore().toInstant().toString());
                        certInfo.put("notAfter", cert.getNotAfter().toInstant().toString());
                        certInfo.put("algorithm", cert.getSigAlgName());
                    }
                } catch (Exception e) {
                    verifyMsg = "OFD 签章验证异常: " + e.getMessage();
                }
            }

            item.put("verified", valid);
            item.put("verifyMessage", verifyMsg);
            item.put("certificate", certInfo);
            if (seal != null) {
                item.put("sealLength", seal.length);
                item.put("sealHexPrefix", CodecUtil.toHex(Arrays.copyOf(seal, Math.min(32, seal.length))));
            }
            list.add(item);
        }

        return list;
    }

    private static Map<String, byte[]> readZip(byte[] data) throws Exception {
        Map<String, byte[]> map = new LinkedHashMap<>();
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(data))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (!entry.isDirectory()) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = zis.read(buf)) > 0) {
                        baos.write(buf, 0, n);
                    }
                    map.put(entry.getName(), baos.toByteArray());
                }
            }
        }
        return map;
    }
}
