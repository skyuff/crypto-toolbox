package com.smtool.module.sm9.core;

import java.math.BigInteger;

/**
 * 十二次扩域 Fp12 = Fp4[w]/(w^3 - v)，即 w^3 = v（GM/T 0044.1-2016 塔式扩张）。
 *
 * <p>元素表示为 c0 + c1*w + c2*w^2，其中 c0、c1、c2 ∈ Fp4。
 * 这是 SM9 R-ate 对的目标群 GT 所在的域。</p>
 */
public final class Fp12 {

    public final Fp4 c0;
    public final Fp4 c1;
    public final Fp4 c2;

    public static final Fp12 ZERO = new Fp12(Fp4.ZERO, Fp4.ZERO, Fp4.ZERO);
    public static final Fp12 ONE = new Fp12(Fp4.ONE, Fp4.ZERO, Fp4.ZERO);

    public Fp12(Fp4 c0, Fp4 c1, Fp4 c2) {
        this.c0 = c0;
        this.c1 = c1;
        this.c2 = c2;
    }

    public boolean isZero() {
        return c0.isZero() && c1.isZero() && c2.isZero();
    }

    public boolean isOne() {
        return this.equals(ONE);
    }

    public Fp12 add(Fp12 o) {
        return new Fp12(c0.add(o.c0), c1.add(o.c1), c2.add(o.c2));
    }

    public Fp12 sub(Fp12 o) {
        return new Fp12(c0.sub(o.c0), c1.sub(o.c1), c2.sub(o.c2));
    }

    public Fp12 negate() {
        return new Fp12(c0.negate(), c1.negate(), c2.negate());
    }

    /**
     * Fp12 乘法（w^3 = v）。
     * 设 a = a0 + a1 w + a2 w^2，b = b0 + b1 w + b2 w^2。
     * 用 Karatsuba/Toom 展开并将 w^3、w^4 项以 v 归约到 Fp4。
     */
    public Fp12 mul(Fp12 o) {
        Fp4 a0 = c0, a1 = c1, a2 = c2;
        Fp4 b0 = o.c0, b1 = o.c1, b2 = o.c2;

        Fp4 t0 = a0.mul(b0);
        Fp4 t1 = a1.mul(b1);
        Fp4 t2 = a2.mul(b2);

        // r0 = t0 + ((a1+a2)(b1+b2) - t1 - t2) * v
        Fp4 r0 = t0.add(a1.add(a2).mul(b1.add(b2)).sub(t1).sub(t2).mulV());
        // r1 = (a0+a1)(b0+b1) - t0 - t1 + t2 * v
        Fp4 r1 = a0.add(a1).mul(b0.add(b1)).sub(t0).sub(t1).add(t2.mulV());
        // r2 = (a0+a2)(b0+b2) - t0 - t2 + t1
        Fp4 r2 = a0.add(a2).mul(b0.add(b2)).sub(t0).sub(t2).add(t1);

        return new Fp12(r0, r1, r2);
    }

    /** 平方。 */
    public Fp12 square() {
        return mul(this);
    }

    /** 乘以 Fp4 标量。 */
    public Fp12 mulFp4(Fp4 k) {
        return new Fp12(c0.mul(k), c1.mul(k), c2.mul(k));
    }

    /** 乘以 w：结果 (c2*v) + c0 w + c1 w^2。 */
    public Fp12 mulW() {
        return new Fp12(c2.mulV(), c0, c1);
    }

    /**
     * 求逆（Fp12 作为 Fp4 上三次扩张）。
     * 采用标准三次域求逆公式。
     */
    public Fp12 inverse() {
        // v 为 Fp4 的 mulV 映射对应的常数（v）
        Fp4 A = c0.square().sub(c1.mul(c2).mulV());
        Fp4 B = c2.square().mulV().sub(c0.mul(c1));
        Fp4 C = c1.square().sub(c0.mul(c2));
        Fp4 F = c0.mul(A).add(c2.mul(B).mulV()).add(c1.mul(C).mulV());
        Fp4 Finv = F.inverse();
        return new Fp12(A.mul(Finv), B.mul(Finv), C.mul(Finv));
    }

    public Fp12 div(Fp12 o) {
        return mul(o.inverse());
    }

    /** 幂运算 this^e（e >= 0）。 */
    public Fp12 pow(BigInteger e) {
        if (e.signum() < 0) {
            return inverse().pow(e.negate());
        }
        Fp12 result = ONE;
        Fp12 base = this;
        int bits = e.bitLength();
        for (int i = 0; i < bits; i++) {
            if (e.testBit(i)) {
                result = result.mul(base);
            }
            base = base.square();
        }
        return result;
    }

    /**
     * Frobenius 映射 x -> x^p。作用于 Fp12 元素。
     * 通过对各 Fp2 分量取共轭再乘以预计算的 Frobenius 常数实现。
     */
    public Fp12 frobenius() {
        return SM9Frobenius.frobenius(this, 1);
    }

    public Fp12 frobenius(int power) {
        return SM9Frobenius.frobenius(this, power);
    }

    /** 共轭：作用于 Fp12/Fp6 二次子扩张，即 conjugate over Fp6（用于最终幂 easy 部分）。 */
    public Fp12 conjugateFp6() {
        // Fp12 = Fp6[?]... 这里用 w^6 层次的共轭：把 w -> -w 等价的映射
        // 采用 x^(p^6) = 对 (c0 + c1 w + c2 w^2) 中奇数次 w 项取负 —— 见 SM9Frobenius.
        return SM9Frobenius.conjugateP6(this);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Fp12 o)) {
            return false;
        }
        return c0.equals(o.c0) && c1.equals(o.c1) && c2.equals(o.c2);
    }

    @Override
    public int hashCode() {
        return (c0.hashCode() * 31 + c1.hashCode()) * 31 + c2.hashCode();
    }

    @Override
    public String toString() {
        return "{c0=" + c0 + ", c1=" + c1 + ", c2=" + c2 + "}";
    }
}
