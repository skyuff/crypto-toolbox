package com.smtool.module.sm9.core;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * G1 群中的点：椭圆曲线 E(Fp)：y^2 = x^3 + b（b = 5）上的仿射点。
 *
 * <p>支持点加、点倍、标量乘、曲线判定，以及标准 SM9 点编码：
 * 非压缩 0x04||x||y、64 字节 x||y、压缩 0x02/0x03||x。</p>
 */
public final class PointG1 {

    private static final BigInteger P = SM9Params.P;
    private static final BigInteger B = SM9Params.B;

    /** 无穷远点（单位元）。 */
    public static final PointG1 INFINITY = new PointG1(null, null, true);

    /** G1 生成元 P1。 */
    public static final PointG1 G = new PointG1(SM9Params.P1_X, SM9Params.P1_Y);

    public final BigInteger x;
    public final BigInteger y;
    public final boolean infinity;

    private PointG1(BigInteger x, BigInteger y, boolean infinity) {
        this.x = x;
        this.y = y;
        this.infinity = infinity;
    }

    public PointG1(BigInteger x, BigInteger y) {
        this(mod(x), mod(y), false);
    }

    private static BigInteger mod(BigInteger v) {
        BigInteger r = v.mod(P);
        return r.signum() < 0 ? r.add(P) : r;
    }

    public boolean isInfinity() {
        return infinity;
    }

    /** 判断是否在曲线上。 */
    public boolean isOnCurve() {
        if (infinity) {
            return true;
        }
        BigInteger lhs = y.multiply(y).mod(P);
        BigInteger rhs = x.multiply(x).mod(P).multiply(x).add(B).mod(P);
        return lhs.equals(rhs);
    }

    public PointG1 negate() {
        if (infinity) {
            return this;
        }
        return new PointG1(x, P.subtract(y), false);
    }

    /** 点加。 */
    public PointG1 add(PointG1 o) {
        if (infinity) {
            return o;
        }
        if (o.infinity) {
            return this;
        }
        if (x.equals(o.x)) {
            if (y.add(o.y).mod(P).signum() == 0) {
                return INFINITY;
            }
            return doublePoint();
        }
        BigInteger lambda = o.y.subtract(y).multiply(o.x.subtract(x).modInverse(P)).mod(P);
        BigInteger x3 = lambda.multiply(lambda).subtract(x).subtract(o.x).mod(P);
        BigInteger y3 = lambda.multiply(x.subtract(x3)).subtract(y).mod(P);
        return new PointG1(x3, y3, false);
    }

    /** 点倍。 */
    public PointG1 doublePoint() {
        if (infinity || y.signum() == 0) {
            return INFINITY;
        }
        BigInteger three = BigInteger.valueOf(3);
        BigInteger lambda = three.multiply(x).multiply(x)
                .multiply(y.shiftLeft(1).modInverse(P)).mod(P);
        BigInteger x3 = lambda.multiply(lambda).subtract(x.shiftLeft(1)).mod(P);
        BigInteger y3 = lambda.multiply(x.subtract(x3)).subtract(y).mod(P);
        return new PointG1(x3, y3, false);
    }

    /** 标量乘 kP。 */
    public PointG1 multiply(BigInteger k) {
        k = k.mod(SM9Params.N);
        if (k.signum() == 0 || infinity) {
            return INFINITY;
        }
        PointG1 result = INFINITY;
        PointG1 base = this;
        int bits = k.bitLength();
        for (int i = 0; i < bits; i++) {
            if (k.testBit(i)) {
                result = result.add(base);
            }
            base = base.doublePoint();
        }
        return result;
    }

    // ---------------- 编码 ----------------

    private static byte[] fixed32(BigInteger v) {
        byte[] raw = v.mod(P).toByteArray();
        byte[] out = new byte[32];
        if (raw.length > 32) {
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        } else {
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        }
        return out;
    }

    /** 64 字节 x||y 编码。 */
    public byte[] toBytes() {
        if (infinity) {
            return new byte[64];
        }
        byte[] out = new byte[64];
        System.arraycopy(fixed32(x), 0, out, 0, 32);
        System.arraycopy(fixed32(y), 0, out, 32, 32);
        return out;
    }

    /** 非压缩编码 0x04||x||y（65 字节）。 */
    public byte[] toUncompressed() {
        if (infinity) {
            return new byte[]{0x00};
        }
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(fixed32(x), 0, out, 1, 32);
        System.arraycopy(fixed32(y), 0, out, 33, 32);
        return out;
    }

    /** 压缩编码 0x02/0x03||x（33 字节）。 */
    public byte[] toCompressed() {
        if (infinity) {
            return new byte[]{0x00};
        }
        byte[] out = new byte[33];
        out[0] = (byte) (y.testBit(0) ? 0x03 : 0x02);
        System.arraycopy(fixed32(x), 0, out, 1, 32);
        return out;
    }

    /** 从字节解析：支持 0x04||x||y、64 字节 x||y、0x02/0x03||x。 */
    public static PointG1 fromBytes(byte[] data) {
        if (data == null || data.length == 0 || (data.length == 1 && data[0] == 0x00)) {
            return INFINITY;
        }
        if (data.length == 64) {
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(data, 0, 32));
            BigInteger y = new BigInteger(1, Arrays.copyOfRange(data, 32, 64));
            return new PointG1(x, y);
        }
        int type = data[0] & 0xff;
        if (type == 0x04 && data.length == 65) {
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(data, 1, 33));
            BigInteger y = new BigInteger(1, Arrays.copyOfRange(data, 33, 65));
            return new PointG1(x, y);
        }
        if ((type == 0x02 || type == 0x03) && data.length == 33) {
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(data, 1, 33));
            return decompress(x, type == 0x03);
        }
        throw new IllegalArgumentException("无法识别的 G1 点编码，长度=" + data.length);
    }

    private static PointG1 decompress(BigInteger x, boolean odd) {
        BigInteger rhs = x.multiply(x).mod(P).multiply(x).add(B).mod(P);
        BigInteger y = sqrtModP(rhs);
        if (y == null) {
            throw new IllegalArgumentException("点解压失败：无平方根");
        }
        if (y.testBit(0) != odd) {
            y = P.subtract(y);
        }
        return new PointG1(x, y);
    }

    /** p ≡ 3 (mod 4)，可用 y = a^((p+1)/4) mod p。 */
    static BigInteger sqrtModP(BigInteger a) {
        BigInteger exp = P.add(BigInteger.ONE).shiftRight(2);
        BigInteger y = a.modPow(exp, P);
        if (y.multiply(y).mod(P).equals(a.mod(P))) {
            return y;
        }
        return null;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PointG1 o)) {
            return false;
        }
        if (infinity || o.infinity) {
            return infinity == o.infinity;
        }
        return x.equals(o.x) && y.equals(o.y);
    }

    @Override
    public int hashCode() {
        if (infinity) {
            return 0;
        }
        return x.hashCode() * 31 + y.hashCode();
    }

    @Override
    public String toString() {
        return infinity ? "G1(inf)" : "G1(" + x.toString(16) + ", " + y.toString(16) + ")";
    }
}
