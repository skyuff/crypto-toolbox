package com.smtool.module.parse;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * TLS / TLCP 密码套件统一映射表。
 * <p>
 * 本类用于集中维护所有密码套件名称，避免在 TlsParseService、TlsSessionAnalyzer、TlsSessionMapper
 * 中重复硬编码不一致的映射表。
 */
public final class TlsCipherSuites {

    private TlsCipherSuites() {
    }

    private static final Map<Integer, String> CIPHER_SUITES;

    static {
        Map<Integer, String> map = new LinkedHashMap<>();

        // ========== TLS 1.3 国密套件（RFC 8998 / GM/T 0091-2020）==========
        map.put(0x00c6, "TLS_SM4_GCM_SM3（国密，TLS 1.3）");
        map.put(0x00c7, "TLS_SM4_CCM_SM3（国密，TLS 1.3）");
        map.put(0x00c8, "TLS_SM4_CBC_SM3（国密，TLS 1.3）");

        // ========== GM/T 0024-2023 TLCP 1.1 国密套件（SM4 + SM3）==========
        map.put(0xe011, "ECC_SM4_SM3（国密 TLCP）");
        map.put(0xe013, "ECDHE_SM4_SM3（国密 TLCP）");
        map.put(0xe015, "ECC_SM4_GCM_SM3（国密 TLCP）");
        map.put(0xe019, "IBSDH_SM4_SM3（国密 TLCP）");
        map.put(0xe01c, "RSA_SM4_SM3（国密 TLCP）");
        map.put(0xe01d, "RSA_SM4_GCM_SM3（国密 TLCP）");

        // GM/T 0024-2023 新增 CBC/GCM 套件
        map.put(0xe093, "ECDHE_SM4_CBC_SM3（国密 TLCP）");
        map.put(0xe095, "ECDHE_SM4_GCM_SM3（国密 TLCP）");
        map.put(0xe097, "RSA_SM4_CBC_SM3（国密 TLCP）");
        map.put(0xe099, "RSA_SM4_GCM_SM3（国密 TLCP）");
        map.put(0xe09b, "IBSDH_SM4_CBC_SM3（国密 TLCP）");
        map.put(0xe09d, "IBSDH_SM4_GCM_SM3（国密 TLCP）");

        // GM/T 0024-2014 / 历史 SM4 套件
        map.put(0xe017, "ECC_SM4_CBC_SM3（国密 TLCP 历史）");
        map.put(0xe01e, "RSA_SM4_CBC_SM3（国密 TLCP 历史）");
        map.put(0xe01f, "RSA_SM4_SHA1（国密 TLCP 历史）");
        map.put(0xe020, "RSA_SM4_SHA256（国密 TLCP 历史）");
        map.put(0xe021, "RSA_SM4_SHA384（国密 TLCP 历史）");
        map.put(0xe022, "RSA_SM4_SHA512（国密 TLCP 历史）");
        map.put(0xe023, "ECDHE_SM4_SHA1（国密 TLCP 历史）");
        map.put(0xe024, "ECDHE_SM4_SHA256（国密 TLCP 历史）");
        map.put(0xe025, "ECDHE_SM4_SHA384（国密 TLCP 历史）");
        map.put(0xe026, "ECDHE_SM4_SHA512（国密 TLCP 历史）");

        // SM1 套件（历史/较少使用，GM/T 0024-2014 定义）
        map.put(0xe001, "ECDHE_SM1_SM3（国密 TLCP 历史）");
        map.put(0xe003, "ECC_SM1_SM3（国密 TLCP 历史）");
        map.put(0xe005, "IBSDH_SM1_SM3（国密 TLCP 历史）");
        map.put(0xe007, "RSA_SM1_SM3（国密 TLCP 历史）");
        map.put(0xe009, "RSA_SM1_SHA1（国密 TLCP 历史）");
        map.put(0xe00a, "RSA_SM1_SHA256（国密 TLCP 历史）");
        map.put(0xe00b, "RSA_SM1_SHA384（国密 TLCP 历史）");
        map.put(0xe00c, "RSA_SM1_SHA512（国密 TLCP 历史）");
        map.put(0xe00d, "ECDHE_SM1_SHA1（国密 TLCP 历史）");
        map.put(0xe00e, "ECDHE_SM1_SHA256（国密 TLCP 历史）");
        map.put(0xe00f, "ECDHE_SM1_SHA384（国密 TLCP 历史）");
        map.put(0xe010, "ECDHE_SM1_SHA512（国密 TLCP 历史）");

        // 早期草案/其他国密套件
        map.put(0xe053, "SM2_WITH_SM4_SM3（国密草案）");
        map.put(0xe0a3, "ECDHE_SM4_CCM_SM3（国密）");
        map.put(0xe0a5, "RSA_SM4_CCM_SM3（国密）");

        // ========== 标准 TLS 1.3 套件 ==========
        map.put(0x1301, "TLS_AES_128_GCM_SHA256（TLS 1.3）");
        map.put(0x1302, "TLS_AES_256_GCM_SHA384（TLS 1.3）");
        map.put(0x1303, "TLS_CHACHA20_POLY1305_SHA256（TLS 1.3）");
        map.put(0x1304, "TLS_AES_128_CCM_SHA256（TLS 1.3）");
        map.put(0x1305, "TLS_AES_128_CCM_8_SHA256（TLS 1.3）");

        // ========== RSA 密钥交换 ==========
        map.put(0x0000, "TLS_NULL_WITH_NULL_NULL");
        map.put(0x0001, "TLS_RSA_WITH_NULL_MD5");
        map.put(0x0002, "TLS_RSA_WITH_NULL_SHA");
        map.put(0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA");
        map.put(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA");
        map.put(0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256");
        map.put(0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256");
        map.put(0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256");
        map.put(0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384");
        map.put(0x002c, "TLS_PSK_WITH_AES_128_CBC_SHA");
        map.put(0x008d, "TLS_PSK_WITH_AES_128_CBC_SHA256");
        map.put(0x008b, "TLS_PSK_WITH_AES_256_CBC_SHA384");

        // ========== ECDHE / ECDH ==========
        map.put(0xc007, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
        map.put(0xc008, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
        map.put(0xc009, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
        map.put(0xc00a, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA");
        map.put(0xc011, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        map.put(0xc012, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        map.put(0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        map.put(0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        map.put(0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
        map.put(0xc024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        map.put(0xc025, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256");
        map.put(0xc026, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384");
        map.put(0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
        map.put(0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
        map.put(0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        map.put(0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
        map.put(0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        map.put(0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        map.put(0xc037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256");
        map.put(0xc038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384");

        // ========== DHE / DH ==========
        map.put(0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
        map.put(0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA");
        map.put(0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
        map.put(0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA");
        map.put(0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256");
        map.put(0x006b, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256");
        map.put(0x009e, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");
        map.put(0x009f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");
        map.put(0x00a3, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256");
        map.put(0x00a4, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384");

        // ========== ChaCha20-Poly1305 ==========
        map.put(0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
        map.put(0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
        map.put(0xccaa, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
        map.put(0xccab, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256");
        map.put(0xccac, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256");
        map.put(0xccad, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256");

        // ========== 特殊 / 安全信号 ==========
        map.put(0x00ff, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
        map.put(0x5600, "TLS_FALLBACK_SCSV");

        CIPHER_SUITES = Collections.unmodifiableMap(map);
    }

    /**
     * 获取密码套件名称；未知套件直接返回十六进制值 0x%04x，避免显示为空或“未知套件”。
     */
    public static String getName(int cipherSuite) {
        return CIPHER_SUITES.getOrDefault(cipherSuite, String.format("0x%04x", cipherSuite));
    }

    /**
     * 判断是否为已知的国密 / TLCP 套件。
     */
    public static boolean isGmSuite(int cipherSuite) {
        if (cipherSuite < 0) {
            return false;
        }
        if ((cipherSuite & 0xff00) == 0xe000) {
            return true;
        }
        return cipherSuite == 0x00c6 || cipherSuite == 0x00c7 || cipherSuite == 0x00c8;
    }

    /**
     * 判断是否为已知的 TLS 1.3 套件。
     */
    public static boolean isTls13Suite(int cipherSuite) {
        return (cipherSuite & 0xff00) == 0x1300 || cipherSuite == 0x00c6 || cipherSuite == 0x00c7 || cipherSuite == 0x00c8;
    }

    /**
     * 根据套件名称推断密钥交换算法。
     */
    public static String inferKeyExchangeAlgorithm(int cipherSuite) {
        String name = getName(cipherSuite).toLowerCase();
        if (isGmSuite(cipherSuite)) {
            if (name.contains("rsa")) {
                return "RSA";
            }
            if (name.contains("ibsdh")) {
                return "IBS";
            }
            if (name.contains("ecdhe") || name.contains("ecc")) {
                return "SM2/ECDHE";
            }
            return "SM2";
        }
        if (name.contains("ecdhe")) {
            return "ECDHE";
        }
        if (name.contains("ecdh")) {
            return "ECDH";
        }
        if (name.contains("dhe") || name.contains("dh_") || name.contains("_dh_")) {
            return "DHE";
        }
        if (name.contains("rsa")) {
            return "RSA";
        }
        if (name.contains("psk")) {
            return "PSK";
        }
        return "未知";
    }

    /**
     * 获取只读的密码套件映射表副本。
     */
    public static Map<Integer, String> getAll() {
        return CIPHER_SUITES;
    }
}
