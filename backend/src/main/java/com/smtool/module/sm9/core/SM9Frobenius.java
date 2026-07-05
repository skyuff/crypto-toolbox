package com.smtool.module.sm9.core;

import java.math.BigInteger;

/**
 * Fp12 上的 Frobenius 映射（x -> x^(p^i)）实现。
 *
 * <p>为避免手工推导塔式扩域 Frobenius 常数出错，本类在首次使用时通过对基元素
 * u、v、w 直接做 p 次幂（仅依赖 mul/square，不依赖 Frobenius 自身）来标定常数，
 * 从而保证与实际域运算完全自洽。</p>
 *
 * <p>Frobenius 是 Fp-线性且是环同态，满足 (xy)^p = x^p y^p、(x+y)^p = x^p+y^p。
 * 对 x = c0 + c1 w + c2 w^2（c_i ∈ Fp4），有
 * x^(p^i) = c0^(p^i) + c1^(p^i)·W1[i] + c2^(p^i)·W2[i]，
 * 其中 c^(p^i) 为 Fp4 上的 Frobenius，W1[i]=w^(p^i)、W2[i]=(w^2)^(p^i) 为预标定的 Fp12 常数。
 * 而 Fp4 上 (b0+b1 v)^(p^i) = conj^i(b0) + conj^i(b1)·V[i]，V[i]=v^(p^i) 为预标定的 Fp4 常数。</p>
 */
final class SM9Frobenius {

    private static final BigInteger P = SM9Params.P;

    private static final Fp12 W = new Fp12(Fp4.ZERO, Fp4.ONE, Fp4.ZERO);       // w
    private static final Fp12 W2 = new Fp12(Fp4.ZERO, Fp4.ZERO, Fp4.ONE);      // w^2

    private static final Fp12[] W1_FROB = new Fp12[12]; // w^(p^i)
    private static final Fp12[] W2_FROB = new Fp12[12]; // (w^2)^(p^i)
    private static final Fp4[] V_FROB = new Fp4[12];     // v^(p^i) as Fp4

    private static volatile boolean init = false;

    private SM9Frobenius() {
    }

    private static synchronized void ensureInit() {
        if (init) {
            return;
        }
        Fp12 wi = W;
        Fp12 w2i = W2;
        // v = w^3，作为 Fp12 元素
        Fp12 vAsFp12 = W.mul(W).mul(W);
        Fp12 vi = vAsFp12;
        W1_FROB[0] = W;
        W2_FROB[0] = W2;
        V_FROB[0] = new Fp4(Fp2.ZERO, Fp2.ONE); // v
        for (int i = 1; i < 12; i++) {
            wi = wi.pow(P);
            w2i = w2i.pow(P);
            vi = vi.pow(P);
            W1_FROB[i] = wi;
            W2_FROB[i] = w2i;
            // vi 必为纯 Fp4（c1=c2=0），取 c0
            V_FROB[i] = vi.c0;
        }
        init = true;
    }

    /** Fp2 的 p^i 次 Frobenius：i 偶为恒等，i 奇为共轭。 */
    private static Fp2 fp2Frob(Fp2 x, int power) {
        return (power % 2 == 0) ? x : x.conjugate();
    }

    /** Fp4 元素的 p^i 次 Frobenius。 */
    private static Fp4 fp4Frob(Fp4 x, int power) {
        Fp2 nb0 = fp2Frob(x.b0, power);
        Fp2 nb1 = fp2Frob(x.b1, power);
        Fp4 base = new Fp4(nb0, Fp2.ZERO);
        Fp4 vpart = new Fp4(nb1, Fp2.ZERO).mul(V_FROB[power]);
        return base.add(vpart);
    }

    /** 计算 x^(p^power)。 */
    static Fp12 frobenius(Fp12 x, int power) {
        ensureInit();
        int pw = ((power % 12) + 12) % 12;
        if (pw == 0) {
            return x;
        }
        Fp12 term0 = new Fp12(fp4Frob(x.c0, pw), Fp4.ZERO, Fp4.ZERO);
        Fp12 term1 = new Fp12(fp4Frob(x.c1, pw), Fp4.ZERO, Fp4.ZERO).mul(W1_FROB[pw]);
        Fp12 term2 = new Fp12(fp4Frob(x.c2, pw), Fp4.ZERO, Fp4.ZERO).mul(W2_FROB[pw]);
        return term0.add(term1).add(term2);
    }

    /** x^(p^6)。 */
    static Fp12 conjugateP6(Fp12 x) {
        return frobenius(x, 6);
    }
}
