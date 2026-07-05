package com.smtool.module.signature;

import com.smtool.module.cert.DerInputUtil;
import com.smtool.module.cert.OidNames;
import com.smtool.util.CodecUtil;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 电子签章（GM/T 0031）解析服务。
 *
 * <p>说明：BouncyCastle 未提供 GM/T 0031 专用高层解析 API，因此本服务采用
 * 「通用 ASN.1 结构解析 + 常见字段启发式提取」策略：
 * 用 {@link ASN1InputStream} 递归解析签章数据的 ASN.1 树，并尽力提取版本、签章者证书、
 * 签名值、时间戳等可读字段。不进行也不伪造验签结果，验签相关限制在 note 中诚实说明。</p>
 */
@Service
public class SealParseService {

    /**
     * 解析入口（原始签章数据）。
     */
    public Map<String, Object> parse(SealParseRequest req) throws Exception {
        byte[] der = DerInputUtil.toDer(req.getInput(), req.getFormat() == null ? "base64" : req.getFormat());
        return parseRaw(der);
    }

    /**
     * 校验入口（OFD/PDF 文件）。
     */
    public SealVerifyResult verifyFile(byte[] fileBytes) {
        String type = detectFileType(fileBytes);
        SealVerifyResult result = new SealVerifyResult();
        result.setFileType(type);
        result.setParsed(true);

        try {
            List<Map<String, Object>> signs;
            if ("PDF".equals(type)) {
                signs = PdfSealVerifier.verify(fileBytes);
            } else if ("OFD".equals(type)) {
                signs = OfdSealVerifier.verify(fileBytes);
            } else {
                return SealVerifyResult.error("仅支持 OFD / PDF 格式文件");
            }
            result.setSignatures(signs);
            result.getExtra().put("signatureCount", signs.size());
            if (signs.isEmpty()) {
                result.getExtra().put("tip", "未检测到电子签章");
            }
        } catch (Exception e) {
            return SealVerifyResult.error("解析失败: " + e.getMessage());
        }
        return result;
    }

    private String detectFileType(byte[] data) {
        if (data == null || data.length < 4) {
            return "UNKNOWN";
        }
        // PDF: %PDF
        if (data[0] == '%' && data[1] == 'P' && data[2] == 'D' && data[3] == 'F') {
            return "PDF";
        }
        // OFD: ZIP 文件头
        if (data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04) {
            return "OFD";
        }
        return "UNKNOWN";
    }

    private Map<String, Object> parseRaw(byte[] der) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();

        // 1) ASN.1 结构树摘要
        Map<String, Object> asn1Summary;
        // 启发式提取的字段容器
        Map<String, Object> extracted = new LinkedHashMap<>();
        List<Map<String, Object>> certificates = new ArrayList<>();
        List<String> oids = new ArrayList<>();
        List<Map<String, Object>> texts = new ArrayList<>();
        List<Map<String, Object>> times = new ArrayList<>();
        List<Map<String, Object>> integers = new ArrayList<>();
        List<Map<String, Object>> binaries = new ArrayList<>();

        try (ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(der))) {
            ASN1Primitive root = ais.readObject();
            if (root == null) {
                throw new IllegalArgumentException("未能解析出任何 ASN.1 对象，请检查输入内容与格式");
            }
            asn1Summary = buildNode(root, 0);
            // 递归提取启发式字段
            collect(root, oids, texts, times, integers, binaries, certificates);
        }

        result.put("asn1Summary", asn1Summary);

        // 2) 启发式字段
        // 版本：取第一个较小的 INTEGER 作为可能的版本号
        if (!integers.isEmpty()) {
            extracted.put("possibleVersion", integers.get(0).get("value"));
        }
        extracted.put("objectIdentifiers", distinct(oids));
        extracted.put("textFields", texts);
        extracted.put("timeFields", times);
        extracted.put("certificates", certificates);
        // 最长的二进制串很可能是签名值
        if (!binaries.isEmpty()) {
            Map<String, Object> longest = binaries.get(0);
            for (Map<String, Object> b : binaries) {
                if ((int) b.get("byteLength") > (int) longest.get("byteLength")) {
                    longest = b;
                }
            }
            extracted.put("possibleSignatureValue", longest.get("hex"));
            extracted.put("possibleSignatureLength", longest.get("byteLength"));
        }
        result.put("extractedFields", extracted);

        // 3) 诚实说明验签限制
        result.put("note", "本结果仅为 ASN.1 结构解析与常见字段的启发式提取，未进行签名验证。"
                + "GM/T 0031 无 BouncyCastle 专用高层 API，字段定位基于结构推断，可能与具体厂商实现存在差异。"
                + "如需验签，需要：1) 依据 GM/T 0031 规范准确定位待签数据（TBS）与签名值；"
                + "2) 提供签章者证书公钥（SM2）与原文/摘要；3) 使用 SM3withSM2 按规范校验，并核验证书链与时间戳有效性。");

        return result;
    }

    // ==================== ASN.1 结构树（限制深度，避免过大） ====================

    /** 递归构造 ASN.1 结构摘要节点（最大深度 6） */
    private Map<String, Object> buildNode(ASN1Primitive obj, int depth) {
        Map<String, Object> node = new LinkedHashMap<>();
        if (obj instanceof ASN1Sequence seq) {
            node.put("type", "SEQUENCE");
            if (depth < 6) {
                node.put("children", childrenOf(seq.getObjects(), depth));
            } else {
                node.put("value", "(深度截断)");
            }
        } else if (obj instanceof ASN1Set set) {
            node.put("type", "SET");
            if (depth < 6) {
                node.put("children", childrenOf(set.getObjects(), depth));
            } else {
                node.put("value", "(深度截断)");
            }
        } else if (obj instanceof ASN1TaggedObject tagged) {
            node.put("type", "context[" + tagged.getTagNo() + "]");
            if (depth < 6) {
                List<Map<String, Object>> children = new ArrayList<>();
                children.add(buildNode(tagged.getBaseObject().toASN1Primitive(), depth + 1));
                node.put("children", children);
            }
        } else if (obj instanceof ASN1ObjectIdentifier oid) {
            node.put("type", "OBJECT IDENTIFIER");
            node.put("value", OidNames.describe(oid.getId()));
        } else if (obj instanceof ASN1Integer integer) {
            node.put("type", "INTEGER");
            java.math.BigInteger v = integer.getValue();
            node.put("value", v.bitLength() > 64 ? "0x" + v.toString(16) : v.toString());
        } else if (obj instanceof ASN1OctetString octet) {
            node.put("type", "OCTET STRING");
            node.put("value", brief(octet.getOctets()));
        } else if (obj instanceof ASN1BitString bits) {
            node.put("type", "BIT STRING");
            node.put("value", brief(bits.getBytes()));
        } else if (obj instanceof ASN1UTCTime t) {
            node.put("type", "UTCTime");
            node.put("value", t.getTime());
        } else if (obj instanceof ASN1GeneralizedTime t) {
            node.put("type", "GeneralizedTime");
            node.put("value", t.getTime());
        } else if (obj instanceof ASN1String str) {
            node.put("type", obj.getClass().getSimpleName().replaceFirst("^(DER|DL|BER)", ""));
            node.put("value", str.getString());
        } else {
            node.put("type", obj.getClass().getSimpleName());
            try {
                node.put("value", brief(obj.getEncoded()));
            } catch (Exception e) {
                node.put("value", obj.toString());
            }
        }
        return node;
    }

    /** 构造子节点列表 */
    private List<Map<String, Object>> childrenOf(Enumeration<?> e, int depth) {
        List<Map<String, Object>> children = new ArrayList<>();
        while (e.hasMoreElements()) {
            children.add(buildNode(((ASN1Encodable) e.nextElement()).toASN1Primitive(), depth + 1));
        }
        return children;
    }

    // ==================== 启发式字段提取 ====================

    /** 递归遍历 ASN.1 树，收集 OID / 文本 / 时间 / 整数 / 二进制串 / 内嵌证书 */
    private void collect(ASN1Primitive obj, List<String> oids, List<Map<String, Object>> texts,
                         List<Map<String, Object>> times, List<Map<String, Object>> integers,
                         List<Map<String, Object>> binaries, List<Map<String, Object>> certificates) {
        if (obj instanceof ASN1Sequence seq) {
            // 尝试将该 SEQUENCE 识别为 X.509 证书
            tryExtractCertificate(seq, certificates);
            for (Enumeration<?> e = seq.getObjects(); e.hasMoreElements(); ) {
                collect(((ASN1Encodable) e.nextElement()).toASN1Primitive(), oids, texts, times, integers, binaries, certificates);
            }
        } else if (obj instanceof ASN1Set set) {
            for (Enumeration<?> e = set.getObjects(); e.hasMoreElements(); ) {
                collect(((ASN1Encodable) e.nextElement()).toASN1Primitive(), oids, texts, times, integers, binaries, certificates);
            }
        } else if (obj instanceof ASN1TaggedObject tagged) {
            collect(tagged.getBaseObject().toASN1Primitive(), oids, texts, times, integers, binaries, certificates);
        } else if (obj instanceof ASN1ObjectIdentifier oid) {
            oids.add(OidNames.describe(oid.getId()));
        } else if (obj instanceof ASN1Integer integer) {
            Map<String, Object> m = new LinkedHashMap<>();
            java.math.BigInteger v = integer.getValue();
            m.put("value", v.bitLength() > 64 ? "0x" + v.toString(16) : v.toString());
            integers.add(m);
        } else if (obj instanceof ASN1String str) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("type", obj.getClass().getSimpleName().replaceFirst("^(DER|DL|BER)", ""));
            m.put("value", str.getString());
            texts.add(m);
        } else if (obj instanceof ASN1UTCTime t) {
            times.add(timeField("UTCTime", t.getTime()));
        } else if (obj instanceof ASN1GeneralizedTime t) {
            times.add(timeField("GeneralizedTime", t.getTime()));
        } else if (obj instanceof ASN1OctetString octet) {
            addBinary(binaries, octet.getOctets());
            // OCTET STRING 内部可能内嵌 DER（如签章内容），尝试继续解析
            tryParseInner(octet.getOctets(), oids, texts, times, integers, binaries, certificates);
        } else if (obj instanceof ASN1BitString bits) {
            addBinary(binaries, bits.getBytes());
        }
    }

    /** 尝试把 SEQUENCE 当作 X.509 证书解析，成功则记录关键字段 */
    private void tryExtractCertificate(ASN1Sequence seq, List<Map<String, Object>> certificates) {
        try {
            X509CertificateHolder holder = new X509CertificateHolder(seq.getEncoded());
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("subject", holder.getSubject().toString());
            c.put("issuer", holder.getIssuer().toString());
            c.put("serialNumber", holder.getSerialNumber().toString(16));
            c.put("notBefore", holder.getNotBefore().toInstant().toString());
            c.put("notAfter", holder.getNotAfter().toInstant().toString());
            certificates.add(c);
        } catch (Exception ignore) {
            // 非证书结构，忽略
        }
    }

    /** 尝试把字节内容当作 DER 再次解析并继续收集 */
    private void tryParseInner(byte[] data, List<String> oids, List<Map<String, Object>> texts,
                               List<Map<String, Object>> times, List<Map<String, Object>> integers,
                               List<Map<String, Object>> binaries, List<Map<String, Object>> certificates) {
        if (data == null || data.length < 2) {
            return;
        }
        try (ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(data))) {
            ASN1Primitive inner = ais.readObject();
            if (inner != null && ais.readObject() == null
                    && (inner instanceof ASN1Sequence || inner instanceof ASN1Set || inner instanceof ASN1TaggedObject)) {
                collect(inner, oids, texts, times, integers, binaries, certificates);
            }
        } catch (Exception ignore) {
            // 非合法 DER，忽略
        }
    }

    /** 记录二进制串（超过 4 字节才认为有意义） */
    private void addBinary(List<Map<String, Object>> binaries, byte[] data) {
        if (data == null || data.length < 4) {
            return;
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("byteLength", data.length);
        m.put("hex", CodecUtil.toHex(data));
        binaries.add(m);
    }

    /** 构造时间字段 */
    private Map<String, Object> timeField(String type, String value) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", type);
        m.put("value", value);
        return m;
    }

    /** 二进制内容摘要展示（过长仅展示前 64 字节） */
    private String brief(byte[] data) {
        if (data == null) {
            return "";
        }
        if (data.length <= 64) {
            return CodecUtil.toHex(data);
        }
        byte[] head = new byte[64];
        System.arraycopy(data, 0, head, 0, 64);
        return CodecUtil.toHex(head) + "...(共 " + data.length + " 字节)";
    }

    /** 去重并保持顺序 */
    private List<String> distinct(List<String> list) {
        List<String> out = new ArrayList<>();
        for (String s : list) {
            if (!out.contains(s)) {
                out.add(s);
            }
        }
        return out;
    }
}
