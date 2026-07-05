package com.smtool.module.sm9.core;

import java.math.BigInteger;

/**
 * 二次扩域 Fp2 = Fp[u]/(u^2 + 2)，即 u^2 = -2（GM/T 0044.1-2016 塔式扩张 β=√-2）。
 *
 * <p>元素表示为 a0 + a1*u，其中 a0、a1 ∈ Fp。</p>
 */
public final class Fp2 {

    /** 基域素数 p。 */
    static final BigInteger P = SM9Params.P;

    /** 实部 a0。 */
    public final BigInteger a0;
    /** 虚部 a1（u 的系数）。 */
    public final BigInteger a1;

    public static final Fp2 ZERO = new Fp2(BigInteger.ZERO, BigInteger.ZERO);
    public static final Fp2 ONE = new Fp2(BigInteger.ONE, BigInteger.ZERO);

    public Fp2(BigInteger a0, BigInteger a1) {
        this.a0 = mod(a0);
        this.a1 = mod(a1);
    }

    public static Fp2 of(BigInteger a0, BigInteger a1) {
        return new Fp2(a0, a1);
    }

    public static Fp2 fromFp(BigInteger a) {
        return new Fp2(a, BigInteger.ZERO);
    }

    static BigInteger mod(BigInteger x) {
        BigInteger r = x.mod(P);
        return r.signum() < 0 ? r.add(P) : r;
    }

    public boolean isZero() {
        return a0.signum() == 0 && a1.signum() == 0;
    }

    public Fp2 add(Fp2 o) {
        return new Fp2(a0.add(o.a0), a1.add(o.a1));
    }

    public Fp2 sub(Fp2 o) {
        return new Fp2(a0.subtract(o.a0), a1.subtract(o.a1));
    }

    public Fp2 negate() {
        return new Fp2(a0.negate(), a1.negate());
    }

    /**
     * Fp2 乘法。u^2 = -2。
     * (a0+a1 u)(b0+b1 u) = a0 b0 + (a0 b1 + a1 b0) u + a1 b1 u^2
     *                    = (a0 b0 - 2 a1 b1) + (a0 b1 + a1 b0) u
     */
    public Fp2 mul(Fp2 o) {
        BigInteger t0 = a0.multiply(o.a0);
        BigInteger t1 = a1.multiply(o.a1);
        BigInteger c0 = t0.subtract(t1.shiftLeft(1)); // a0b0 - 2 a1b1
        // Karatsuba: (a0+a1)(b0+b1) - a0b0 - a1b1 = a0b1 + a1b0
        BigInteger c1 = a0.add(a1).multiply(o.a0.add(o.a1)).subtract(t0).subtract(t1);
        return new Fp2(c0, c1);
    }

    /** 乘以 Fp 标量。 */
    public Fp2 mulFp(BigInteger k) {
        return new Fp2(a0.multiply(k), a1.multiply(k));
    }

    /** 平方。 */
    public Fp2 square() {
        // (a0+a1 u)^2 = (a0^2 - 2 a1^2) + (2 a0 a1) u
        BigInteger a0sq = a0.multiply(a0);
        BigInteger a1sq = a1.multiply(a1);
        BigInteger c0 = a0sq.subtract(a1sq.shiftLeft(1));
        BigInteger c1 = a0.multiply(a1).shiftLeft(1);
        return new Fp2(c0, c1);
    }

    /**
     * 求逆。范数 N = a0^2 + 2 a1^2（因 u^2=-2，共轭为 a0 - a1 u，
     * (a0+a1u)(a0-a1u)=a0^2 - a1^2 u^2 = a0^2 + 2 a1^2）。
     * inverse = (a0 - a1 u) / N。
     */
    public Fp2 inverse() {
        BigInteger norm = a0.multiply(a0).add(a1.multiply(a1).shiftLeft(1)).mod(P);
        BigInteger ninv = norm.modInverse(P);
        return new Fp2(a0.multiply(ninv), a1.negate().multiply(ninv));
    }

    public Fp2 div(Fp2 o) {
        return mul(o.inverse());
    }

    /** 共轭：a0 - a1 u（即 Frobenius p 次幂在 Fp2 上）。 */
    public Fp2 conjugate() {
        return new Fp2(a0, a1.negate());
    }

    /** 乘以 u：(a0 + a1 u) * u = a1 u^2 + a0 u = -2 a1 + a0 u。 */
    public Fp2 mulU() {
        return new Fp2(a1.negate().shiftLeft(1), a0);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Fp2 o)) {
            return false;
        }
        return a0.equals(o.a0) && a1.equals(o.a1);
    }

    @Override
    public int hashCode() {
        return a0.hashCode() * 31 + a1.hashCode();
    }

    @Override
    public String toString() {
        return "(" + a0.toString(16) + ", " + a1.toString(16) + ")";
    }
}
