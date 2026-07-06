package com.smtool.module.cert;

import com.smtool.util.CodecUtil;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 数字证书格式检查服务：
 * 解析 X.509 证书（支持 PEM / base64 DER / hex DER），提取版本、序列号、签名算法、
 * 颁发者/使用者、有效期、公钥信息、扩展项，并给出格式规范检查结果与是否为国密 SM2 证书判断。
 */
@Service
public class CertCheckService {

    /**
     * 检查证书并返回结构化信息。
     */
    public Map<String, Object> check(CertCheckRequest req) throws Exception {
        return check(DerInputUtil.toDer(req.getCertPem()));
    }

    /**
     * 直接从 DER 字节解析证书。
     */
    public Map<String, Object> check(byte[] der) throws Exception {
        // 用标准 CertificateFactory(BC) 解析为 X509Certificate，便于取过期等信息
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate cert;
        try (java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(der)) {
            cert = (X509Certificate) cf.generateCertificate(in);
        }
        // 同时用 BC 的 Holder 便于取扩展项原始内容
        X509CertificateHolder holder = new X509CertificateHolder(der);

        Map<String, Object> result = new LinkedHashMap<>();

        int version = cert.getVersion();
        result.put("version", "v" + version);
        result.put("serialNumber", cert.getSerialNumber().toString(16));

        // 签名算法：OID + 名称
        String sigOid = cert.getSigAlgOID();
        String sigName = OidNames.get(sigOid);
        if (sigName == null) {
            sigName = cert.getSigAlgName();
        }
        Map<String, Object> sigInfo = new LinkedHashMap<>();
        sigInfo.put("oid", sigOid);
        sigInfo.put("name", sigName);
        result.put("signatureAlgorithm", sigInfo);

        result.put("issuer", cert.getIssuerX500Principal().getName());
        result.put("subject", cert.getSubjectX500Principal().getName());

        Date notBefore = cert.getNotBefore();
        Date notAfter = cert.getNotAfter();
        result.put("notBefore", notBefore.toInstant().toString());
        result.put("notAfter", notAfter.toInstant().toString());

        Date now = new Date();
        boolean expired = now.after(notAfter) || now.before(notBefore);
        result.put("expired", expired);

        // 公钥算法与公钥字节
        String pkAlg = cert.getPublicKey().getAlgorithm();
        byte[] pkEncoded = cert.getPublicKey().getEncoded();
        boolean isSm2 = false;
        // 判断是否 SM2：EC 公钥且曲线 OID 为 sm2p256v1，或签名算法为 SM3withSM2
        String pkCurveOid = holder.getSubjectPublicKeyInfo().getAlgorithm().getParameters() == null
                ? null : holder.getSubjectPublicKeyInfo().getAlgorithm().getParameters().toString();
        if ("1.2.156.10197.1.301".equals(pkCurveOid) || "1.2.156.10197.1.501".equals(sigOid)) {
            isSm2 = true;
            pkAlg = "SM2";
        }
        result.put("publicKeyAlgorithm", pkAlg);
        result.put("publicKeyHex", CodecUtil.toHex(pkEncoded));
        result.put("isSm2", isSm2);

        // 扩展项解析
        List<Map<String, Object>> extensions = parseExtensions(holder);
        result.put("extensions", extensions);

        // 格式规范检查
        List<Map<String, Object>> checks = new ArrayList<>();
        checks.add(check("版本为 v3", version == 3,
                version == 3 ? "证书为 X.509 v3" : "证书版本为 v" + version + "，现代证书建议使用 v3"));
        boolean hasBasicConstraints = holder.getExtension(Extension.basicConstraints) != null;
        checks.add(check("包含 basicConstraints 扩展", hasBasicConstraints,
                hasBasicConstraints ? "已包含基本约束扩展" : "缺少 basicConstraints 扩展"));
        boolean hasKeyUsage = holder.getExtension(Extension.keyUsage) != null;
        checks.add(check("包含 keyUsage 扩展", hasKeyUsage,
                hasKeyUsage ? "已包含密钥用法扩展" : "缺少 keyUsage 扩展"));
        boolean hasSki = holder.getExtension(Extension.subjectKeyIdentifier) != null;
        checks.add(check("包含 subjectKeyIdentifier 扩展", hasSki,
                hasSki ? "已包含使用者密钥标识扩展" : "缺少 subjectKeyIdentifier 扩展"));
        checks.add(check("编码合法", true, "证书 DER 编码解析成功"));
        checks.add(check("在有效期内", !expired,
                expired ? "证书当前不在有效期内" : "证书在有效期内"));
        result.put("checks", checks);

        return result;
    }

    /** 解析证书扩展项列表 */
    private List<Map<String, Object>> parseExtensions(X509CertificateHolder holder) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (holder.getExtensions() == null) {
            return list;
        }
        for (ASN1ObjectIdentifier oid : holder.getExtensions().getExtensionOIDs()) {
            Extension ext = holder.getExtension(oid);
            Map<String, Object> item = new LinkedHashMap<>();
            String oidStr = oid.getId();
            item.put("oid", oidStr);
            item.put("name", OidNames.get(oidStr));
            item.put("critical", ext.isCritical());
            item.put("description", describeExtension(oid, ext));
            list.add(item);
        }
        return list;
    }

    /** 对常见扩展项给出简要可读说明 */
    private String describeExtension(ASN1ObjectIdentifier oid, Extension ext) {
        try {
            if (Extension.keyUsage.equals(oid)) {
                KeyUsage ku = KeyUsage.getInstance(ext.getParsedValue());
                return "密钥用法: " + keyUsageToString(ku);
            }
            if (Extension.basicConstraints.equals(oid)) {
                BasicConstraints bc = BasicConstraints.getInstance(ext.getParsedValue());
                String s = "CA=" + bc.isCA();
                if (bc.getPathLenConstraint() != null) {
                    s += ", pathLen=" + bc.getPathLenConstraint();
                }
                return "基本约束: " + s;
            }
            if (Extension.subjectAlternativeName.equals(oid)) {
                GeneralNames gns = GeneralNames.getInstance(ext.getParsedValue());
                List<String> names = new ArrayList<>();
                for (GeneralName gn : gns.getNames()) {
                    names.add(gn.toString());
                }
                return "使用者备用名称: " + String.join(", ", names);
            }
            if (Extension.authorityKeyIdentifier.equals(oid)) {
                AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(ext.getParsedValue());
                return "颁发机构密钥标识: " + (aki.getKeyIdentifier() == null
                        ? "(无)" : CodecUtil.toHex(aki.getKeyIdentifier()));
            }
            if (Extension.subjectKeyIdentifier.equals(oid)) {
                SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(ext.getParsedValue());
                return "使用者密钥标识: " + CodecUtil.toHex(ski.getKeyIdentifier());
            }
        } catch (Exception e) {
            return "解析失败: " + e.getMessage();
        }
        String name = OidNames.get(oid.getId());
        return name != null ? name : "未识别扩展";
    }

    /** 将 KeyUsage 位标志转为可读字符串 */
    private String keyUsageToString(KeyUsage ku) {
        List<String> usages = new ArrayList<>();
        if (ku.hasUsages(KeyUsage.digitalSignature)) usages.add("digitalSignature");
        if (ku.hasUsages(KeyUsage.nonRepudiation)) usages.add("nonRepudiation");
        if (ku.hasUsages(KeyUsage.keyEncipherment)) usages.add("keyEncipherment");
        if (ku.hasUsages(KeyUsage.dataEncipherment)) usages.add("dataEncipherment");
        if (ku.hasUsages(KeyUsage.keyAgreement)) usages.add("keyAgreement");
        if (ku.hasUsages(KeyUsage.keyCertSign)) usages.add("keyCertSign");
        if (ku.hasUsages(KeyUsage.cRLSign)) usages.add("cRLSign");
        if (ku.hasUsages(KeyUsage.encipherOnly)) usages.add("encipherOnly");
        if (ku.hasUsages(KeyUsage.decipherOnly)) usages.add("decipherOnly");
        return String.join(", ", usages);
    }

    /** 验证证书链：每个节点由父节点签名，父节点主题为子节点颁发者，且父节点在有效期内。 */
    public Map<String, Object> validateChain(List<String> certs) throws Exception {
        if (certs == null || certs.isEmpty()) {
            throw new IllegalArgumentException("证书链不能为空");
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        List<X509Certificate> chain = new ArrayList<>();
        List<String> errors = new ArrayList<>();

        for (int i = 0; i < certs.size(); i++) {
            String input = certs.get(i);
            if (input == null || input.isBlank()) {
                errors.add("节点 " + (i + 1) + " 证书内容为空");
                continue;
            }
            try {
                byte[] der = DerInputUtil.toDer(input);
                X509Certificate cert;
                try (java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(der)) {
                    cert = (X509Certificate) cf.generateCertificate(in);
                }
                chain.add(cert);
            } catch (Exception e) {
                errors.add("节点 " + (i + 1) + " 证书解析失败: " + e.getMessage());
            }
        }

        List<Map<String, Object>> nodeResults = new ArrayList<>();
        boolean chainValid = true;
        Date now = new Date();

        for (int i = 0; i < chain.size(); i++) {
            X509Certificate cert = chain.get(i);
            Map<String, Object> node = new LinkedHashMap<>();
            node.put("index", i);
            node.put("subject", cert.getSubjectX500Principal().getName());
            node.put("issuer", cert.getIssuerX500Principal().getName());

            boolean selfSigned = cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
            node.put("selfSigned", selfSigned);

            boolean inValidityPeriod = now.after(cert.getNotBefore()) && now.before(cert.getNotAfter());
            node.put("expired", !inValidityPeriod);

            boolean signatureValid = false;
            String signatureError = null;
            if (i == 0) {
                // 根证书：自签名验证
                try {
                    cert.verify(cert.getPublicKey());
                    signatureValid = true;
                } catch (Exception e) {
                    signatureError = "根证书自签名验证失败: " + e.getMessage();
                }
            } else {
                // 非根证书：由上一级父证书验证签名
                X509Certificate parent = chain.get(i - 1);
                boolean issuerMatch = parent.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
                node.put("issuerMatch", issuerMatch);
                if (!issuerMatch) {
                    signatureError = "父证书主题与当前证书颁发者不匹配";
                }
                try {
                    cert.verify(parent.getPublicKey());
                    signatureValid = true;
                } catch (Exception e) {
                    signatureError = signatureError == null
                            ? "父证书签名验证失败: " + e.getMessage()
                            : signatureError + "; 父证书签名验证失败: " + e.getMessage();
                }
            }
            node.put("signatureValid", signatureValid);
            node.put("signatureError", signatureError);
            node.put("valid", inValidityPeriod && signatureValid);
            if (!inValidityPeriod || !signatureValid) {
                chainValid = false;
            }
            nodeResults.add(node);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("chainLength", chain.size());
        result.put("chainValid", chainValid && errors.isEmpty());
        result.put("errors", errors);
        result.put("nodes", nodeResults);
        return result;
    }

    /** 构造单条检查结果 */
    private Map<String, Object> check(String item, boolean pass, String message) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("item", item);
        m.put("pass", pass);
        m.put("message", message);
        return m;
    }
}
