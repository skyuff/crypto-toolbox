package com.smtool.module.sm9.core;

import java.math.BigInteger;

/**
 * SM9 R-ate 双线性对 e: G1 × G2 -> GT(Fp12)。
 *
 * <p>基于 GM/T 0044.1-2016 的 256 位 BN 曲线，嵌入度 k = 12，六次扭曲线。
 * 采用标准“扭优化” Miller 循环：累加点 T 始终留在扭曲线 E'(Fp2) 上（廉价的 Fp2 运算），
 * 线函数在 P ∈ G1（Fp 坐标）处求值后按扭映射打包为 Fp12 元素。垂直线（分母）落在
 * Fp6 子域，会被最终幂 (p^6-1) 部分消去，因此循环中只累加分子线（denominator elimination）。</p>
 *
 * <p>Miller 循环参数 a = 6t + 2；随后做两步 Frobenius 调整（R-ate 附加线）。由于
 * Q ∈ G2 是 p-幂 Frobenius 的特征子空间（π_p 在其上等于 [p]），
 * 故 π_p(Q) = [p mod N]·Q、π_{p^2}(Q) = [p^2 mod N]·Q，可直接用 PointG2 标量乘计算。
 * 最终幂 (p^12 - 1)/N 分 easy 部分 (p^6-1)(p^2+1) 与 hard 部分 (p^4 - p^2 + 1)/N。</p>
 */
public final class SM9Pairing {

    private static final BigInteger P = SM9Params.P;
    private static final BigInteger N = SM9Params.N;
    private static final BigInteger T = SM9Params.T;

    /** Miller 循环参数 a = 6t + 2。 */
    private static final BigInteger LOOP_A = T.multiply(BigInteger.valueOf(6)).add(BigInteger.valueOf(2));

    /** [p mod N] 与 [p^2 mod N]，用于 R-ate Frobenius 附加线。 */
    private static final BigInteger P_MOD_N = P.mod(N);
    private static final BigInteger P2_MOD_N = P.multiply(P).mod(N);

    /** 调试开关：跳过 R-ate 的两个 Frobenius 附加线（隔离测试用）。 */
    static boolean SKIP_FINAL_ADDITIONS = false;

    private SM9Pairing() {
    }

    /**
     * R-ate 对主函数 e(P, Q)，P ∈ G1、Q ∈ G2。
     */
    public static Fp12 rate(PointG1 pPoint, PointG2 qPoint) {
        if (pPoint.isInfinity() || qPoint.isInfinity()) {
            return Fp12.ONE;
        }
        BigInteger xP = pPoint.x;
        BigInteger yP = pPoint.y;

        Fp12 f = Fp12.ONE;
        PointG2 t = qPoint;

        int bits = LOOP_A.bitLength();
        for (int i = bits - 2; i >= 0; i--) {
            f = f.square().mul(doubleLine(t, xP, yP));
            t = t.doublePoint();
            if (LOOP_A.testBit(i)) {
                f = f.mul(addLine(t, qPoint, xP, yP));
                t = t.add(qPoint);
            }
        }

        // R-ate Frobenius 附加线：Q1 = π_p(Q) = [p]Q，Q2 = π_{p^2}(Q) = [p^2]Q
        if (!SKIP_FINAL_ADDITIONS) {
            PointG2 q1 = qPoint.multiply(P_MOD_N);
            PointG2 q2 = qPoint.multiply(P2_MOD_N);

            f = f.mul(addLine(t, q1, xP, yP));
            t = t.add(q1);
            PointG2 negQ2 = q2.negate();
            f = f.mul(addLine(t, negQ2, xP, yP));
            t = t.add(negQ2);
        }

        return finalExponentiation(f);
    }

    /**
     * 切线线函数在 P 处取值（扭映射打包，仅分子）。
     *
     * <p>扭映射 Ψ(x',y') = (x'·w^2, y'·w^3)。过 Ψ(T) 的切线斜率 Λ = λ'·w，λ' = 3xT^2/(2yT) ∈ Fp2。
     * 直线 L(X,Y) = Y - yT·w^3 - λ'w(X - xT·w^2)，在 P=(xP,yP) ∈ Fp 处：
     * L = yP - λ'·xP·w + (λ'·xT - yT)·w^3。其中 w^3 = v 落在 c0 的 v 分量，w 落在 c1。</p>
     */
    private static Fp12 doubleLine(PointG2 t, BigInteger xP, BigInteger yP) {
        Fp2 xT = t.x;
        Fp2 yT = t.y;
        Fp2 three = Fp2.fromFp(BigInteger.valueOf(3));
        Fp2 two = Fp2.fromFp(BigInteger.valueOf(2));
        Fp2 lambda = three.mul(xT.square()).mul(two.mul(yT).inverse());
        return packLine(lambda, xT, yT, xP, yP);
    }

    /**
     * 连线线函数在 P 处取值（扭映射打包，仅分子）。斜率 λ' = (yQ - yT)/(xQ - xT) ∈ Fp2。
     */
    private static Fp12 addLine(PointG2 t, PointG2 q, BigInteger xP, BigInteger yP) {
        if (t.isInfinity() || q.isInfinity()) {
            return Fp12.ONE;
        }
        if (t.x.equals(q.x)) {
            if (t.y.add(q.y).isZero()) {
                // T + Q = O：垂直线 X - xT·w^2 ∈ Fp6，被最终幂消去，返回 1
                return Fp12.ONE;
            }
            return doubleLine(t, xP, yP);
        }
        Fp2 lambda = q.y.sub(t.y).mul(q.x.sub(t.x).inverse());
        return packLine(lambda, t.x, t.y, xP, yP);
    }

    /**
     * 将线函数 L = yP - λ'·xP·w + (λ'·xT - yT)·w^3 打包为 Fp12。
     */
    private static Fp12 packLine(Fp2 lambda, Fp2 xT, Fp2 yT, BigInteger xP, BigInteger yP) {
        Fp2 c0b0 = Fp2.fromFp(yP);                 // yP
        Fp2 c0b1 = lambda.mul(xT).sub(yT);         // λ'·xT - yT   (w^3 = v 分量)
        Fp2 c1b0 = lambda.mulFp(xP).negate();      // -λ'·xP       (w 分量)
        Fp4 c0 = new Fp4(c0b0, c0b1);
        Fp4 c1 = new Fp4(c1b0, Fp2.ZERO);
        return new Fp12(c0, c1, Fp4.ZERO);
    }

    // ---------------- 最终幂 ----------------

    /**
     * 最终幂 f^((p^12 - 1)/N)。easy 部分 (p^6-1)(p^2+1)，hard 部分 (p^4 - p^2 + 1)/N。
     */
    public static Fp12 finalExponentiation(Fp12 f) {
        if (f.isZero()) {
            return Fp12.ONE;
        }
        Fp12 f1 = SM9Frobenius.frobenius(f, 6).mul(f.inverse());   // f^(p^6 - 1)
        Fp12 f2 = SM9Frobenius.frobenius(f1, 2).mul(f1);           // f^(p^2 + 1)
        BigInteger p2 = P.multiply(P);
        BigInteger p4 = p2.multiply(p2);
        BigInteger hard = p4.subtract(p2).add(BigInteger.ONE).divide(N);
        return f2.pow(hard);
    }
}
