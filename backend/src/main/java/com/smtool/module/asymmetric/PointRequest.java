package com.smtool.module.asymmetric;

import lombok.Data;

/**
 * 椭圆曲线点压缩/解压缩请求体。
 */
@Data
public class PointRequest {

    /** 椭圆曲线公钥点：未压缩（04 开头 hex）或压缩（02/03 开头 hex） */
    private String point;

    /** 曲线名称：sm2p256v1（默认）/ secp256r1 / secp256k1 */
    private String curve;
}
