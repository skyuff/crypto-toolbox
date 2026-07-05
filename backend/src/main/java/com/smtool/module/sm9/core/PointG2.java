package com.smtool.module.sm9.core;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * G2 群中的点：六次扭曲线 E'(Fp2)：y^2 = x^3 + b' 上的仿射点。
 *
 * <p>坐标为 Fp2 元素。b' 由标准 G2 生成元 P2 反算得到，保证与国标参数一致。
 * 支持点加、点倍、标量乘、曲线判定，以及坐标编码。</p>
 */
public final class PointG2 {

    private static final BigInteger P = SM9Params.P;

    /** 扭曲线常数 b'（由生成元反算：b' = yP2^2 - xP2^3）。 */
    public static final Fp2 BPRIME;

    /** 无穷远点。 */
    public static final PointG2 INFINITY = new PointG2(null, null, true);

    /** G2 生成元 P2（Fp2 坐标用 (实部 a0, 虚部 a1) 表示，国标以 (虚部,实部) 给出）。 */
    public static final PointG2 G;

    public final Fp2 x;
    public final Fp2 y;
    public final boolean infinity;

    static {
        // 国标以 (a1=虚部, a0=实部) 顺序给出 P2 坐标
        Fp2 xP2 = new Fp2(SM9Params.P2_X_0, SM9Params.P2_X_1);
        Fp2 yP2 = new Fp2(SM9Params.P2_Y_0, SM9Params.P2_Y_1);
        G = new PointG2(xP2, yP2, false);
        BPRIME = yP2.square().sub(xP2.square().mul(xP2));
    }

    private PointG2(Fp2 x, Fp2 y, boolean infinity) {
        this.x = x;
        this.y = y;
        this.infinity = infinity;
    }

    public PointG2(Fp2 x, Fp2 y) {
        this(x, y, false);
    }

    public boolean isInfinity() {
        return infinity;
    }

    public boolean isOnCurve() {
        if (infinity) {
            return true;
        }
        Fp2 lhs = y.square();
        Fp2 rhs = x.square().mul(x).add(BPRIME);
        return lhs.equals(rhs);
    }

    public PointG2 negate() {
        if (infinity) {
            return this;
        }
        return new PointG2(x, y.negate(), false);
    }

    public PointG2 add(PointG2 o) {
        if (infinity) {
            return o;
        }
        if (o.infinity) {
            return this;
        }
        if (x.equals(o.x)) {
            if (y.add(o.y).isZero()) {
                return INFINITY;
            }
            return doublePoint();
        }
        Fp2 lambda = o.y.sub(y).mul(o.x.sub(x).inverse());
        Fp2 x3 = lambda.square().sub(x).sub(o.x);
        Fp2 y3 = lambda.mul(x.sub(x3)).sub(y);
        return new PointG2(x3, y3, false);
    }

    public PointG2 doublePoint() {
        if (infinity || y.isZero()) {
            return INFINITY;
        }
        Fp2 three = Fp2.fromFp(BigInteger.valueOf(3));
        Fp2 lambda = three.mul(x.square()).mul(y.add(y).inverse());
        Fp2 x3 = lambda.square().sub(x.add(x));
        Fp2 y3 = lambda.mul(x.sub(x3)).sub(y);
        return new PointG2(x3, y3, false);
    }

    public PointG2 multiply(BigInteger k) {
        k = k.mod(SM9Params.N);
        if (k.signum() == 0 || infinity) {
            return INFINITY;
        }
        PointG2 result = INFINITY;
        PointG2 base = this;
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

    /**
     * 128 字节编码：x1 || x0 || y1 || y0（每个 Fp2 以 虚部||实部 排列，符合国标点序）。
     */
    public byte[] toBytes() {
        if (infinity) {
            return new byte[128];
        }
        byte[] out = new byte[128];
        System.arraycopy(fixed32(x.a1), 0, out, 0, 32);
        System.arraycopy(fixed32(x.a0), 0, out, 32, 32);
        System.arraycopy(fixed32(y.a1), 0, out, 64, 32);
        System.arraycopy(fixed32(y.a0), 0, out, 96, 32);
        return out;
    }

    /** 非压缩编码 0x04 || (128 字节)。 */
    public byte[] toUncompressed() {
        if (infinity) {
            return new byte[]{0x00};
        }
        byte[] body = toBytes();
        byte[] out = new byte[129];
        out[0] = 0x04;
        System.arraycopy(body, 0, out, 1, 128);
        return out;
    }

    /** 从 128 字节 x1||x0||y1||y0 解析。 */
    public static PointG2 fromBytes(byte[] data) {
        if (data == null || data.length == 0 || (data.length == 1 && data[0] == 0x00)) {
            return INFINITY;
        }
        byte[] body = data;
        if (data.length == 129 && (data[0] & 0xff) == 0x04) {
            body = Arrays.copyOfRange(data, 1, 129);
        }
        if (body.length != 128) {
            throw new IllegalArgumentException("无法识别的 G2 点编码，长度=" + data.length);
        }
        BigInteger x1 = new BigInteger(1, Arrays.copyOfRange(body, 0, 32));
        BigInteger x0 = new BigInteger(1, Arrays.copyOfRange(body, 32, 64));
        BigInteger y1 = new BigInteger(1, Arrays.copyOfRange(body, 64, 96));
        BigInteger y0 = new BigInteger(1, Arrays.copyOfRange(body, 96, 128));
        return new PointG2(new Fp2(x0, x1), new Fp2(y0, y1));
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PointG2 o)) {
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
        return infinity ? "G2(inf)" : "G2(x=" + x + ", y=" + y + ")";
    }
}
