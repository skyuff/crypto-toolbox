package com.smtool.config;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Configuration;
import jakarta.annotation.PostConstruct;

import java.security.Security;

/**
 * 注册 BouncyCastle Provider，供全部国密/密码运算使用。
 */
@Configuration
public class BouncyCastleConfig {

    @PostConstruct
    public void init() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
