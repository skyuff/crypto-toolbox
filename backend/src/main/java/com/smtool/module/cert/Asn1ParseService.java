package com.smtool.module.cert;

import com.smtool.util.CodecUtil;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * ASN.1 解析服务：
 * 将 PEM / base64 / hex 编码的 DER 数据读取为 ASN1Primitive，递归构造成一棵树，
 * 每个节点包含 type、value、length、children。
 */
@Service
public class Asn1ParseService {

    /**
     * 解析入口：返回根节点（若含多个顶层对象则返回列表包装）。
     */
    public Map<String, Object> parse(Asn1ParseRequest req) throws Exception {
        byte[] der = DerInputUtil.toDer(req.getInput(), req.getFormat());

        List<Map<String, Object>> roots = new ArrayList<>();
        try (ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(der))) {
            ASN1Primitive obj;
            while ((obj = ais.readObject()) != null) {
                roots.add(buildNode(obj));
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("totalBytes", der.length);
        // 通常只有一个根对象，直接返回它；兼容多个顶层对象的情况
        if (roots.size() == 1) {
            result.put("root", roots.get(0));
        } else {
            result.put("root", roots);
        }
        return result;
    }

    /** 递归构造单个 ASN.1 节点 */
    private Map<String, Object> buildNode(ASN1Primitive obj) {
        Map<String, Object> node = new LinkedHashMap<>();
        try {
            node.put("length", obj.getEncoded().length);
        } catch (Exception e) {
            node.put("length", -1);
        }

        if (obj instanceof ASN1Sequence seq) {
            node.put("type", "SEQUENCE");
            List<Map<String, Object>> children = new ArrayList<>();
            for (Enumeration<?> e = seq.getObjects(); e.hasMoreElements(); ) {
                children.add(buildNode(((org.bouncycastle.asn1.ASN1Encodable) e.nextElement()).toASN1Primitive()));
            }
            node.put("children", children);
        } else if (obj instanceof ASN1Set set) {
            node.put("type", "SET");
            List<Map<String, Object>> children = new ArrayList<>();
            for (Enumeration<?> e = set.getObjects(); e.hasMoreElements(); ) {
                children.add(buildNode(((org.bouncycastle.asn1.ASN1Encodable) e.nextElement()).toASN1Primitive()));
            }
            node.put("children", children);
        } else if (obj instanceof ASN1TaggedObject tagged) {
            node.put("type", "context[" + tagged.getTagNo() + "]");
            List<Map<String, Object>> children = new ArrayList<>();
            children.add(buildNode(tagged.getBaseObject().toASN1Primitive()));
            node.put("children", children);
        } else if (obj instanceof ASN1ObjectIdentifier oid) {
            node.put("type", "OBJECT IDENTIFIER");
            node.put("value", OidNames.describe(oid.getId()));
        } else if (obj instanceof ASN1Integer integer) {
            node.put("type", "INTEGER");
            java.math.BigInteger v = integer.getValue();
            // 大整数用 hex 展示，小整数用十进制
            if (v.bitLength() > 64) {
                node.put("value", "0x" + v.toString(16));
            } else {
                node.put("value", v.toString());
            }
        } else if (obj instanceof ASN1Enumerated en) {
            node.put("type", "ENUMERATED");
            node.put("value", en.getValue().toString());
        } else if (obj instanceof ASN1OctetString octet) {
            node.put("type", "OCTET STRING");
            byte[] octets = octet.getOctets();
            // 尝试将内部内容再解析为 DER，失败则展示 hex
            Map<String, Object> inner = tryParseInner(octets);
            if (inner != null) {
                node.put("value", "(内含可解析的 DER 结构)");
                List<Map<String, Object>> children = new ArrayList<>();
                children.add(inner);
                node.put("children", children);
            } else {
                node.put("value", CodecUtil.toHex(octets));
            }
        } else if (obj instanceof ASN1BitString bits) {
            node.put("type", "BIT STRING");
            node.put("value", CodecUtil.toHex(bits.getBytes()));
            // 尝试解析 BIT STRING 内部（如公钥中的 subjectPublicKey）
            Map<String, Object> inner = tryParseInner(bits.getBytes());
            if (inner != null) {
                List<Map<String, Object>> children = new ArrayList<>();
                children.add(inner);
                node.put("children", children);
            }
        } else if (obj instanceof ASN1Boolean bool) {
            node.put("type", "BOOLEAN");
            node.put("value", bool.isTrue());
        } else if (obj instanceof ASN1Null) {
            node.put("type", "NULL");
            node.put("value", null);
        } else if (obj instanceof ASN1UTCTime t) {
            node.put("type", "UTCTime");
            node.put("value", t.getTime());
        } else if (obj instanceof ASN1GeneralizedTime t) {
            node.put("type", "GeneralizedTime");
            node.put("value", t.getTime());
        } else if (obj instanceof ASN1String str) {
            // 涵盖 UTF8String / PrintableString / IA5String / T61String 等
            node.put("type", asn1StringType(obj));
            node.put("value", str.getString());
        } else {
            node.put("type", obj.getClass().getSimpleName());
            try {
                node.put("value", CodecUtil.toHex(obj.getEncoded()));
            } catch (Exception e) {
                node.put("value", obj.toString());
            }
        }
        return node;
    }

    /** 尝试将字节内容当作 DER 再次解析，成功返回节点，失败返回 null */
    private Map<String, Object> tryParseInner(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }
        try (ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(data))) {
            ASN1Primitive inner = ais.readObject();
            // 要求恰好消费完全部字节，并接受常见 ASN.1 类型作为合法内嵌 DER
            if (inner != null && ais.readObject() == null) {
                return buildNode(inner);
            }
        } catch (Exception ignore) {
            // 非合法 DER，忽略
        }
        return null;
    }

    /** 根据具体字符串类型返回 ASN.1 类型名 */
    private String asn1StringType(ASN1Primitive obj) {
        String simple = obj.getClass().getSimpleName();
        // 例如 DERUTF8String -> UTF8String、DERPrintableString -> PrintableString
        return simple.replaceFirst("^(DER|DL|BER)", "");
    }
}
