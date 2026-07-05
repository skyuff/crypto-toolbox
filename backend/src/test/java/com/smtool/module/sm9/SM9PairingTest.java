package com.smtool.module.sm9;

import com.smtool.module.sm9.core.Fp2;
import com.smtool.module.sm9.core.Fp4;
import com.smtool.module.sm9.core.Fp12;
import com.smtool.module.sm9.core.PointG1;
import com.smtool.module.sm9.core.PointG2;
import com.smtool.module.sm9.core.SM9Pairing;
import com.smtool.module.sm9.core.SM9Params;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 塔式扩域与 R-ate 对的基础自洽性测试（域公理、群公理、双线性、阶）。
 */
public class SM9PairingTest {

    private static final BigInteger P = SM9Params.P;
    private static final BigInteger N = SM9Params.N;

    private static BigInteger rnd(long seed) {
        return BigInteger.valueOf(seed).multiply(BigInteger.valueOf(2654435761L)).mod(P).add(BigInteger.ONE);
    }

    @Test
    void fp2FieldAxioms() {
        Fp2 a = new Fp2(rnd(1), rnd(2));
        Fp2 b = new Fp2(rnd(3), rnd(4));
        // a * a^{-1} = 1
        assertEquals(Fp2.ONE, a.mul(a.inverse()));
        // (a*b) 分配律 a*(b+1)=a*b+a
        assertEquals(a.mul(b.add(Fp2.ONE)), a.mul(b).add(a));
        // square == mul self
        assertEquals(a.square(), a.mul(a));
    }

    @Test
    void fp4FieldAxioms() {
        Fp4 a = new Fp4(new Fp2(rnd(5), rnd(6)), new Fp2(rnd(7), rnd(8)));
        Fp4 b = new Fp4(new Fp2(rnd(9), rnd(10)), new Fp2(rnd(11), rnd(12)));
        assertEquals(Fp4.ONE, a.mul(a.inverse()));
        assertEquals(a.mul(b.add(Fp4.ONE)), a.mul(b).add(a));
        assertEquals(a.square(), a.mul(a));
    }

    @Test
    void fp12FieldAxioms() {
        Fp12 a = randFp12(20);
        Fp12 b = randFp12(40);
        assertEquals(Fp12.ONE, a.mul(a.inverse()));
        assertEquals(a.mul(b.add(Fp12.ONE)), a.mul(b).add(a));
        assertEquals(a.square(), a.mul(a));
        // Frobenius 同态： (a*b)^p == a^p * b^p
        assertEquals(a.mul(b).frobenius(), a.frobenius().mul(b.frobenius()));
        // a^(p^12) == a
        assertEquals(a, a.frobenius(12));
    }

    private Fp12 randFp12(int s) {
        Fp4 c0 = new Fp4(new Fp2(rnd(s), rnd(s + 1)), new Fp2(rnd(s + 2), rnd(s + 3)));
        Fp4 c1 = new Fp4(new Fp2(rnd(s + 4), rnd(s + 5)), new Fp2(rnd(s + 6), rnd(s + 7)));
        Fp4 c2 = new Fp4(new Fp2(rnd(s + 8), rnd(s + 9)), new Fp2(rnd(s + 10), rnd(s + 11)));
        return new Fp12(c0, c1, c2);
    }

    @Test
    void generatorsOnCurve() {
        assertTrue(PointG1.G.isOnCurve(), "P1 应在 E(Fp) 上");
        assertTrue(PointG2.G.isOnCurve(), "P2 应在 E'(Fp2) 上");
        // 阶： N*P1 = O
        assertTrue(PointG1.G.multiply(N).isInfinity(), "N*P1 应为无穷远点");
        assertTrue(PointG2.G.multiply(N).isInfinity(), "N*P2 应为无穷远点");
    }

    @Test
    void pairingNonDegenerateAndOrderN() {
        Fp12 g = SM9Pairing.rate(PointG1.G, PointG2.G);
        assertTrue(!g.isOne(), "e(P1,P2) 不应为 1（非退化）");
        // g^N == 1
        assertEquals(Fp12.ONE, g.pow(N), "e(P1,P2)^N 应为 1");
    }

    @Test
    void pairingBilinearity() {
        Fp12 g = SM9Pairing.rate(PointG1.G, PointG2.G);
        BigInteger two = BigInteger.TWO;
        Fp12 e2P = SM9Pairing.rate(PointG1.G.multiply(two), PointG2.G);
        Fp12 eP2 = SM9Pairing.rate(PointG1.G, PointG2.G.multiply(two));
        assertEquals(g.pow(two), e2P, "G1 侧: e([2]P1,P2) == e(P1,P2)^2");
        assertEquals(g.pow(two), eP2, "G2 侧: e(P1,[2]P2) == e(P1,P2)^2");
        assertEquals(e2P, eP2, "e([2]P1,P2) == e(P1,[2]P2)");

        BigInteger a = rnd(100).mod(N);
        BigInteger b = rnd(200).mod(N);
        Fp12 lhs = SM9Pairing.rate(PointG1.G.multiply(a), PointG2.G.multiply(b));
        Fp12 rhs = g.pow(a.multiply(b).mod(N));
        assertEquals(rhs, lhs, "e(aP1,bP2) == e(P1,P2)^(ab)");
    }
}
