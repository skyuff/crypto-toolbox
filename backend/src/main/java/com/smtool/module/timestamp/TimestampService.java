package com.smtool.module.timestamp;

import com.smtool.module.cert.DerInputUtil;
import com.smtool.util.CodecUtil;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 时间戳（RFC 3161）解析服务。
 *
 * <p>用 BouncyCastle 的 {@link TimeStampResponse} / {@link TimeStampToken} 解析输入。
 * 优先按 TimeStampResponse 解析；若输入是裸 TimeStampToken(ContentInfo)，则回退直接构造
 * {@link TimeStampToken} 解析。解析失败给出中文异常提示。</p>
 */
@Service
public class TimestampService {

    /** 解析时间戳并返回结构化信息。 */
    public Map<String, Object> parse(TimestampRequest req) throws Exception {
        byte[] der = DerInputUtil.toDer(req.getInput(), req.getFormat());

        Integer status = null;
        String statusString = null;
        TimeStampToken token;
        try {
            TimeStampResponse response = new TimeStampResponse(der);
            status = response.getStatus();
            statusString = response.getStatusString();
            token = response.getTimeStampToken();
        } catch (Exception respEx) {
            token = new TimeStampToken(
                    org.bouncycastle.asn1.cms.ContentInfo.getInstance(der));
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", status);
        result.put("statusString", statusString);
        result.put("statusText", statusText(status));

        if (token == null) {
            result.put("message", "响应中不包含 TimeStampToken（可能被 TSA 拒绝或仅为状态响应）");
            return result;
        }

        result.putAll(parseTokenInfo(token));
        return result;
    }

    /**
     * 验证时间戳：解析时间戳令牌后，用其中声明的摘要算法对原始数据重新计算摘要，
     * 并与 messageImprint 比较，判断时间戳是否对应指定原始数据。
     */
    public Map<String, Object> verify(TimestampRequest req) throws Exception {
        byte[] der = DerInputUtil.toDer(req.getInput(), req.getFormat());
        TimeStampToken token = extractToken(der);
        if (token == null) {
            throw new IllegalArgumentException("时间戳令牌为空，无法验证");
        }

        TimeStampTokenInfo info = token.getTimeStampInfo();
        String digestAlgOid = info.getMessageImprintAlgOID().getId();
        byte[] expectedImprint = info.getMessageImprintDigest();

        byte[] original = CodecUtil.decode(req.getOriginalInput(), req.getOriginalFormat());
        MessageDigest md = MessageDigest.getInstance(digestAlgOid, "BC");
        byte[] actualImprint = md.digest(original);

        boolean match = java.util.Arrays.equals(expectedImprint, actualImprint);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("verified", match);
        result.put("verifyMessage", match ? "摘要一致，时间戳与原始数据匹配" : "摘要不一致，时间戳与原始数据不匹配");
        result.put("digestAlgorithm", digestAlgOid);
        result.put("expectedMessageImprint", CodecUtil.toHex(expectedImprint));
        result.put("actualMessageImprint", CodecUtil.toHex(actualImprint));
        result.put("originalBytes", original.length);
        result.putAll(parseTokenInfo(token));
        return result;
    }

    /** 提取 TimeStampToken：先尝试 TimeStampResponse，再尝试裸 ContentInfo。 */
    private TimeStampToken extractToken(byte[] der) throws Exception {
        try {
            TimeStampResponse response = new TimeStampResponse(der);
            return response.getTimeStampToken();
        } catch (Exception respEx) {
            try {
                return new TimeStampToken(
                        org.bouncycastle.asn1.cms.ContentInfo.getInstance(der));
            } catch (Exception tokEx) {
                throw new IllegalArgumentException(
                        "时间戳解析失败：既不是有效的 TimeStampResponse，也不是有效的 TimeStampToken。"
                                + " Response 错误: " + respEx.getMessage()
                                + "；Token 错误: " + tokEx.getMessage());
            }
        }
    }

    /** 把 TimeStampTokenInfo 中的关键字段提取为 Map（供解析和验证复用）。 */
    private Map<String, Object> parseTokenInfo(TimeStampToken token) {
        Map<String, Object> result = new LinkedHashMap<>();
        TimeStampTokenInfo info = token.getTimeStampInfo();
        result.put("genTime", info.getGenTime() == null ? null : info.getGenTime().toInstant().toString());
        result.put("serialNumber", info.getSerialNumber() == null
                ? null : info.getSerialNumber().toString(16));
        result.put("tsaPolicyId", info.getPolicy() == null ? null : info.getPolicy().getId());
        result.put("hashAlgorithm", info.getMessageImprintAlgOID() == null
                ? null : info.getMessageImprintAlgOID().getId());
        byte[] imprint = info.getMessageImprintDigest();
        result.put("messageImprint", imprint == null ? null : CodecUtil.toHex(imprint));
        result.put("tsaName", info.getTsa() == null ? null : info.getTsa().getName().toString());
        result.put("accuracy", info.getGenTimeAccuracy() == null ? null : info.getGenTimeAccuracy().toString());
        result.put("nonce", info.getNonce() == null ? null : info.getNonce().toString());
        result.put("ordering", info.isOrdered());

        Store<X509CertificateHolder> certStore = token.getCertificates();
        Collection<X509CertificateHolder> certs = certStore.getMatches(null);
        result.put("signerCertCount", certs.size());
        List<Map<String, Object>> certList = new ArrayList<>();
        for (X509CertificateHolder holder : certs) {
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("subject", holder.getSubject().toString());
            c.put("issuer", holder.getIssuer().toString());
            c.put("serialNumber", holder.getSerialNumber().toString(16));
            certList.add(c);
        }
        result.put("certificates", certList);
        return result;
    }

    /** 将 PKIStatus 数值转为可读中文说明。 */
    private String statusText(Integer status) {
        if (status == null) {
            return "无状态字段（裸 TimeStampToken）";
        }
        if (status == PKIStatus.GRANTED) {
            return "已签发（granted）";
        }
        if (status == PKIStatus.GRANTED_WITH_MODS) {
            return "已签发但有修改（grantedWithMods）";
        }
        if (status == PKIStatus.REJECTION) {
            return "被拒绝（rejection）";
        }
        if (status == PKIStatus.WAITING) {
            return "等待中（waiting）";
        }
        if (status == PKIStatus.REVOCATION_WARNING) {
            return "撤销警告（revocationWarning）";
        }
        if (status == PKIStatus.REVOCATION_NOTIFICATION) {
            return "撤销通知（revocationNotification）";
        }
        return "未知状态: " + status;
    }
}
