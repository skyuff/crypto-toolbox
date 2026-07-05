package com.smtool.module.sm9;

import com.smtool.module.sm9.core.Fp2;
import com.smtool.module.sm9.core.SM9Params;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

/**
 * 权威诊断：用项目真实 Fp2 类，b' = 5/u = 5*u^{-1}，检验标准 P2 是否 onCurve 且阶为 N。
 * 独立实现 raw 标量乘（不 mod N），P2 坐标严格按 (a0=实部=X0, a1=虚部=X1)。
 */
public class TwistProbeTest {

    static final BigInteger P = SM9Params.P;
    static final BigInteger N = SM9Params.N;

    static class Pt {
        Fp2 x, y;
        Pt(Fp2 x, Fp2 y) { this.x = x; this.y = y; }
    }

    static Pt add(Pt A, Pt B) {
        if (A == null) return B;
        if (B == null) return A;
        if (A.x.equals(B.x)) {
            if (A.y.add(B.y).isZero()) return null;
            Fp2 three = Fp2.fromFp(BigInteger.valueOf(3));
            Fp2 lam = three.mul(A.x.square()).mul(A.y.add(A.y).inverse());
            Fp2 x3 = lam.square().sub(A.x).sub(A.x);
            Fp2 y3 = lam.mul(A.x.sub(x3)).sub(A.y);
            return new Pt(x3, y3);
        }
        Fp2 lam = B.y.sub(A.y).mul(B.x.sub(A.x).inverse());
        Fp2 x3 = lam.square().sub(A.x).sub(B.x);
        Fp2 y3 = lam.mul(A.x.sub(x3)).sub(A.y);
        return new Pt(x3, y3);
    }

    static Pt scalar(BigInteger k, Pt base) {
        Pt R = null;
        for (int i = 0; i < k.bitLength(); i++) {
            if (k.testBit(i)) R = add(R, base);
            base = add(base, base);
        }
        return R;
    }

    @Test
    public void probe() {
        StringBuilder sb = new StringBuilder();

        // b' candidates
        Fp2 u = new Fp2(BigInteger.ZERO, BigInteger.ONE);         // u
        Fp2 bp_5overU = Fp2.fromFp(BigInteger.valueOf(5)).mul(u.inverse()); // 5/u
        Fp2 bp_5u = Fp2.fromFp(BigInteger.valueOf(5)).mul(u);              // 5u

        // standard P2 : (a0=X0, a1=X1)
        Fp2 x = new Fp2(SM9Params.P2_X_0, SM9Params.P2_X_1);
        Fp2 y = new Fp2(SM9Params.P2_Y_0, SM9Params.P2_Y_1);

        Fp2 lhs = y.square();
        Fp2 rhs3 = x.square().mul(x);
        Fp2 recovered = lhs.sub(rhs3); // b' = y^2 - x^3

        sb.append("b'=5/u   = ").append(bp_5overU).append("\n");
        sb.append("b'=5u    = ").append(bp_5u).append("\n");
        sb.append("recovered= ").append(recovered).append("\n");
        sb.append("recovered==5/u? ").append(recovered.equals(bp_5overU)).append("\n");
        sb.append("recovered==5u?  ").append(recovered.equals(bp_5u)).append("\n");

        Pt p2 = new Pt(x, y);
        Pt r = scalar(N, p2);
        sb.append("N*P2=O (raw)? ").append(r == null).append("\n");

        // Also try P2 with swapped coord interpretation (a0=X1,a1=X0)
        Fp2 xs = new Fp2(SM9Params.P2_X_1, SM9Params.P2_X_0);
        Fp2 ys = new Fp2(SM9Params.P2_Y_1, SM9Params.P2_Y_0);
        Pt r2 = scalar(N, new Pt(xs, ys));
        sb.append("N*P2=O swapped? ").append(r2 == null).append("\n");

        throw new AssertionError("\n" + sb);
    }
}
