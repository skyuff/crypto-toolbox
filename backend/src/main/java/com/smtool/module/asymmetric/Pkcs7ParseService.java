package com.smtool.module.asymmetric;

import com.smtool.module.cert.DerInputUtil;
import com.smtool.module.cert.OidNames;
import com.smtool.util.CodecUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

@Service
public class Pkcs7ParseService {

    public Map<String, Object> sign(Pkcs7ParseRequest req) throws Exception {
        byte[] certDer = DerInputUtil.toDer(req.getCert(), req.getCertFormat());
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(certDer));

        PrivateKey privKey = parsePrivateKey(req.getPrivateKey(), req.getPrivateKeyFormat());

        byte[] data = CodecUtil.decode(req.getMessage(), req.getMessageFormat());
        boolean attached = "attach".equalsIgnoreCase(req.getMode());

        List<X509Certificate> certList = Collections.singletonList(cert);
        JcaCertStore certStore = new JcaCertStore(certList);

        CMSTypedData msg;
        if (attached) {
            msg = new CMSProcessableByteArray(data);
        } else {
            CMSProcessableByteArray cmsData = new CMSProcessableByteArray(data);
            msg = cmsData;
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(privKey);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                        .build(signer, cert));
        gen.addCertificates(certStore);

        CMSSignedData signedData = gen.generate(msg, attached);
        byte[] encoded = signedData.getEncoded();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("mode", attached ? "attach" : "detach");
        result.put("signature", CodecUtil.encode(encoded, req.getOutputFormat() != null ? req.getOutputFormat() : "hex"));
        return result;
    }

    public Map<String, Object> verify(Pkcs7ParseRequest req) throws Exception {
        byte[] p7Der = DerInputUtil.toDer(req.getSignature(), req.getSignatureFormat());
        CMSSignedData signedData;

        if (req.getMessage() != null && !req.getMessage().isBlank()) {
            byte[] data = CodecUtil.decode(req.getMessage(), req.getMessageFormat());
            CMSProcessableByteArray msg = new CMSProcessableByteArray(data);
            signedData = new CMSSignedData(msg, p7Der);
        } else {
            signedData = new CMSSignedData(p7Der);
        }

        Store<X509CertificateHolder> certStore = signedData.getCertificates();
        SignerInformationStore signers = signedData.getSignerInfos();
        Collection<SignerInformation> signerInfos = signers.getSigners();

        boolean allVerified = true;
        List<Map<String, Object>> results = new ArrayList<>();

        for (SignerInformation signer : signerInfos) {
            Map<String, Object> sr = new LinkedHashMap<>();
            Collection<X509CertificateHolder> matches = certStore.getMatches(signer.getSID());

            if (matches.isEmpty()) {
                sr.put("verified", false);
                sr.put("reason", "未找到对应证书");
                allVerified = false;
            } else {
                X509CertificateHolder certHolder = matches.iterator().next();
                X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
                        .generateCertificate(new java.io.ByteArrayInputStream(certHolder.getEncoded()));
                boolean ok = signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider("BC")
                        .build(cert.getPublicKey()));
                sr.put("verified", ok);
                sr.put("signerId", signerIdString(signer.getSID()));
                sr.put("digestAlgorithm", OidNames.describe(signer.getDigestAlgOID()));
                sr.put("signatureAlgorithm", OidNames.describe(signer.getEncryptionAlgOID()));
                if (!ok) allVerified = false;
            }
            results.add(sr);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("verified", allVerified);
        result.put("signerCount", signerInfos.size());
        result.put("signers", results);
        return result;
    }

    public Map<String, Object> parse(Pkcs7ParseRequest req) throws Exception {
        byte[] der = DerInputUtil.toDer(req.getInput(), req.getFormat() == null ? "base64" : req.getFormat());
        CMSSignedData signedData = new CMSSignedData(der);

        Map<String, Object> result = new LinkedHashMap<>();

        String contentTypeOid = signedData.getSignedContentTypeOID();
        result.put("contentTypeOid", contentTypeOid == null ? null : OidNames.describe(contentTypeOid));

        boolean hasContent = signedData.getSignedContent() != null;
        result.put("hasContent", hasContent);
        result.put("type", hasContent ? "attached" : "detached");

        List<Map<String, Object>> signers = new ArrayList<>();
        SignerInformationStore signerStore = signedData.getSignerInfos();
        for (SignerInformation signer : signerStore.getSigners()) {
            Map<String, Object> s = new LinkedHashMap<>();
            s.put("digestAlgorithm", OidNames.describe(signer.getDigestAlgOID()));
            s.put("signatureAlgorithm", OidNames.describe(signer.getEncryptionAlgOID()));
            s.put("signature", CodecUtil.toHex(signer.getSignature()));
            s.put("version", signer.getVersion());

            SignerId sid = signer.getSID();
            Map<String, Object> sidMap = new LinkedHashMap<>();
            if (sid.getIssuer() != null) sidMap.put("issuer", sid.getIssuer().toString());
            if (sid.getSerialNumber() != null) sidMap.put("serialNumber", sid.getSerialNumber().toString(16));
            if (sid.getSubjectKeyIdentifier() != null) sidMap.put("subjectKeyIdentifier", CodecUtil.toHex(sid.getSubjectKeyIdentifier()));
            s.put("signerId", sidMap);
            signers.add(s);
        }
        result.put("signers", signers);

        List<Map<String, Object>> certs = new ArrayList<>();
        Store<X509CertificateHolder> certStore = signedData.getCertificates();
        Collection<X509CertificateHolder> matches = certStore.getMatches(null);
        for (X509CertificateHolder holder : matches) {
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("subject", nameToString(holder.getSubject()));
            c.put("issuer", nameToString(holder.getIssuer()));
            c.put("serialNumber", holder.getSerialNumber().toString(16));
            c.put("notBefore", holder.getNotBefore().toInstant().toString());
            c.put("notAfter", holder.getNotAfter().toInstant().toString());
            certs.add(c);
        }
        result.put("certificates", certs);
        result.put("certificateCount", certs.size());

        return result;
    }

    private String signerIdString(SignerId sid) {
        if (sid.getIssuer() != null && sid.getSerialNumber() != null) {
            return sid.getIssuer() + "/" + sid.getSerialNumber().toString(16);
        }
        if (sid.getSubjectKeyIdentifier() != null) {
            return "SKI:" + CodecUtil.toHex(sid.getSubjectKeyIdentifier());
        }
        return "unknown";
    }

    private String nameToString(X500Name name) {
        return name == null ? null : name.toString();
    }

    private PrivateKey parsePrivateKey(String key, String format) throws Exception {
        if (key == null || key.isBlank()) throw new IllegalArgumentException("私钥不能为空");
        String f = (format == null) ? "auto" : format.trim().toLowerCase();
        byte[] der;
        if ("hex".equals(f)) {
            der = CodecUtil.fromHex(key);
        } else if ("base64".equals(f)) {
            der = CodecUtil.decode(key, "base64");
        } else if ("utf8".equals(f) || "string".equals(f)) {
            if (key.contains("-----BEGIN")) {
                der = DerInputUtil.readPem(key);
            } else {
                der = CodecUtil.decode(key, "base64");
            }
        } else {
            der = DerInputUtil.toDer(key);
        }
        java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(der);
        try {
            return java.security.KeyFactory.getInstance("RSA", "BC").generatePrivate(keySpec);
        } catch (Exception e) {
            try {
                return java.security.KeyFactory.getInstance("EC", "BC").generatePrivate(keySpec);
            } catch (Exception e2) {
                throw new IllegalArgumentException("不支持的私钥类型");
            }
        }
    }
}
