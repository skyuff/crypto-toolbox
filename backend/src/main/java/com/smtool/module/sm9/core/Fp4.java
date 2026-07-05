package com.smtool.module.sm9.core;

import java.math.BigInteger;

/**
 * 四次扩域 Fp4 = Fp2[v]/(v^2 - u)，即 v^2 = u（GM/T 0044.1-2016 塔式扩张）。
 *
 * <p>元素表示为 b0 + b1*v，其中 b0、b1 ∈ Fp2。</p>
 */
public final class Fp4 {

    /** 常数项 b0。 */
    public final Fp2 b0;
    /** v 的系数 b1。 */
    public final Fp2 b1;

    public static final Fp4 ZERO = new Fp4(Fp2.ZERO, Fp2.ZERO);
    public static final Fp4 ONE = new Fp4(Fp2.ONE, Fp2.ZERO);

    public Fp4(Fp2 b0, Fp2 b1) {
        this.b0 = b0;
        this.b1 = b1;
    }

    public static Fp4 fromFp2(Fp2 x) {
        return new Fp4(x, Fp2.ZERO);
    }

    public boolean isZero() {
        return b0.isZero() && b1.isZero();
    }

    public Fp4 add(Fp4 o) {
        return new Fp4(b0.add(o.b0), b1.add(o.b1));
    }

    public Fp4 sub(Fp4 o) {
        return new Fp4(b0.sub(o.b0), b1.sub(o.b1));
    }

    public Fp4 negate() {
        return new Fp4(b0.negate(), b1.negate());
    }

    /**
     * Fp4 乘法。v^2 = u。
     * (b0+b1 v)(c0+c1 v) = (b0 c0 + b1 c1 * u) + (b0 c1 + b1 c0) v
     */
    public Fp4 mul(Fp4 o) {
        Fp2 t0 = b0.mul(o.b0);
        Fp2 t1 = b1.mul(o.b1);
        Fp2 c0 = t0.add(t1.mulU()); // + b1 c1 * u
        // Karatsuba for the v-part
        Fp2 c1 = b0.add(b1).mul(o.b0.add(o.b1)).sub(t0).sub(t1);
        return new Fp4(c0, c1);
    }

    public Fp4 mulFp2(Fp2 k) {
        return new Fp4(b0.mul(k), b1.mul(k));
    }

    /** 平方。 */
    public Fp4 square() {
        // (b0+b1 v)^2 = (b0^2 + b1^2 u) + (2 b0 b1) v
        Fp2 b0sq = b0.square();
        Fp2 b1sq = b1.square();
        Fp2 c0 = b0sq.add(b1sq.mulU());
        Fp2 c1 = b0.mul(b1);
        c1 = c1.add(c1);
        return new Fp4(c0, c1);
    }

    /**
     * 求逆。共轭 (b0 - b1 v)，范数 = b0^2 - b1^2 * u ∈ Fp2。
     * inverse = (b0 - b1 v) / (b0^2 - b1^2 u)
     */
    public Fp4 inverse() {
        Fp2 norm = b0.square().sub(b1.square().mulU());
        Fp2 ninv = norm.inverse();
        return new Fp4(b0.mul(ninv), b1.negate().mul(ninv));
    }

    /** 乘以 v：(b0 + b1 v) * v = b1 u + b0 v。 */
    public Fp4 mulV() {
        return new Fp4(b1.mulU(), b0);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Fp4 o)) {
            return false;
        }
        return b0.equals(o.b0) && b1.equals(o.b1);
    }

    @Override
    public int hashCode() {
        return b0.hashCode() * 31 + b1.hashCode();
    }

    @Override
    public String toString() {
        return "[" + b0 + " + " + b1 + " v]";
    }
}
