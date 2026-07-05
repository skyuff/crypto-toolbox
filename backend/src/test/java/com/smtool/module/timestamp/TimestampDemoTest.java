package com.smtool.module.timestamp;

import com.smtool.util.CodecUtil;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.tsp.*;

import java.io.File;
import java.io.FileWriter;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * 生成演示用 RFC 3161 时间戳令牌，用于前端时间戳解析/验证功能演示。
 */
public class TimestampDemoTest {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** 基于 JCA MessageDigest 的简单 DigestCalculator 实现。 */
    static class SimpleDigestCalculator implements DigestCalculator {
        private final AlgorithmIdentifier algId;
        private final MessageDigest digest;

        SimpleDigestCalculator(AlgorithmIdentifier algId, MessageDigest digest) {
            this.algId = algId;
            this.digest = digest;
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return algId;
        }

        @Override
        public OutputStream getOutputStream() {
            return new OutputStream() {
                @Override
                public void write(int b) {
                    digest.update((byte) b);
                }

                @Override
                public void write(byte[] b, int off, int len) {
                    digest.update(b, off, len);
                }
            };
        }

        @Override
        public byte[] getDigest() {
            return digest.digest();
        }
    }

    public static void main(String[] args) throws Exception {
        // 1. 生成 RSA 密钥对和自签名 TSA 证书
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        X500Name issuer = new X500Name("CN=Demo TSA, O=SM Toolbox, C=CN");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);

        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(
                keyPair.getPublic().getEncoded());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, issuer, keyPair.getPublic());
        certBuilder.addExtension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certBuilder.build(signer));

        // 2. 原始数据
        String originalText = "这是商用密码检测工具箱的时间戳演示数据。";
        byte[] originalBytes = originalText.getBytes(StandardCharsets.UTF_8);

        // 3. 构造时间戳请求（TimeStampRequest）
        MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
        byte[] digest = md.digest(originalBytes);
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        reqGen.setCertReq(true);
        TimeStampRequest request = reqGen.generate(
                new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"), digest);

        // 4. 构造时间戳响应（TimeStampResponse / TimeStampToken）
        SignerInfoGenerator sigGen = new JcaSimpleSignerInfoGeneratorBuilder()
                .setProvider("BC")
                .build("SHA256withRSA", keyPair.getPrivate(), cert);

        AlgorithmIdentifier sha256Id = new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"));
        DigestCalculator digestCalculator = new SimpleDigestCalculator(sha256Id,
                MessageDigest.getInstance("SHA-256", "BC"));

        TimeStampTokenGenerator tokenGen = new TimeStampTokenGenerator(
                sigGen,
                digestCalculator,
                new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.4")
        );
        tokenGen.addCertificates(new org.bouncycastle.util.CollectionStore<>(Collections.singletonList(
                new org.bouncycastle.cert.X509CertificateHolder(cert.getEncoded()))));

        Set<ASN1ObjectIdentifier> acceptedAlgorithms = new HashSet<>();
        acceptedAlgorithms.add(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"));
        TimeStampResponseGenerator respGen = new TimeStampResponseGenerator(
                tokenGen,
                acceptedAlgorithms
        );

        TimeStampResponse response = respGen.generate(request, new BigInteger("1234567890"), new Date());
        response.validate(request);

        byte[] responseBytes = response.getEncoded();
        String hex = CodecUtil.toHex(responseBytes);
        String base64 = CodecUtil.encode(responseBytes, "base64");

        // 5. 保存演示文件
        String baseDir = System.getProperty("user.dir");
        File hexFile = new File(baseDir, "timestamp_demo_token.hex");
        File b64File = new File(baseDir, "timestamp_demo_token.b64");
        File originalFile = new File(baseDir, "timestamp_demo_original.txt");
        try (FileWriter w1 = new FileWriter(hexFile);
             FileWriter w2 = new FileWriter(b64File);
             FileWriter w3 = new FileWriter(originalFile)) {
            w1.write(hex);
            w2.write(base64);
            w3.write(originalText);
        }

        System.out.println("原始数据: " + originalText);
        System.out.println("原始数据文件: " + originalFile.getAbsolutePath());
        System.out.println("时间戳令牌(hex): " + hexFile.getAbsolutePath());
        System.out.println("时间戳令牌(b64): " + b64File.getAbsolutePath());
        System.out.println("时间戳令牌大小: " + responseBytes.length + " 字节");
    }
}
