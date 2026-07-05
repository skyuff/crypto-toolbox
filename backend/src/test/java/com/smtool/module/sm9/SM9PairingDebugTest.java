package com.smtool.module.sm9;

import com.smtool.module.sm9.core.SM9Params;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class SM9PairingDebugTest {

    private static final BigInteger P = SM9Params.P;
    private static final BigInteger N = SM9Params.N;
    private final List<String> log = new ArrayList<>();
    private BigInteger BETA; // u^2

    private void out(String s) { log.add(s); }

    @Test
    void diagnoseOrder() throws IOException {
        BigInteger X0 = SM9Params.P2_X_0.mod(P), X1 = SM9Params.P2_X_1.mod(P);
        BigInteger Y0 = SM9Params.P2_Y_0.mod(P), Y1 = SM9Params.P2_Y_1.mod(P);

        BigInteger[][] combos = {
            {X0, X1, Y0, Y1}, {X0, X1, Y1, Y0}, {X1, X0, Y0, Y1}, {X1, X0, Y1, Y0},
        };
        String[] names = {"AA", "AB", "BA", "BB"};

        for (BigInteger beta : new BigInteger[]{BigInteger.valueOf(-2), BigInteger.valueOf(2)}) {
            BETA = beta.mod(P);
            for (int i = 0; i < combos.length; i++) {
                BigInteger[] x = {combos[i][0], combos[i][1]};
                BigInteger[] y = {combos[i][2], combos[i][3]};
                // b' = y^2 - x^3
                BigInteger[] bp = sub(mul(y, y), cube(x));
                // is order N on curve y^2=x^3+bp? check N*P == O and also (N)*P via double-add
                boolean nInf = scalarInf(x, y, N);
                out("beta=" + beta + " " + names[i] + " b'=(" + hx(bp[0]) + "," + hx(bp[1]) + ") N*P=O?" + nInf);
            }
        }
        Files.write(Path.of(System.getProperty("user.dir"), "debug-out.txt"), log);
        throw new AssertionError(String.join(" | ", log));
    }

    private String hx(BigInteger b) { String s = b.toString(16); return s.length() > 10 ? s.substring(0, 10) : s; }

    private BigInteger[] mul(BigInteger[] a, BigInteger[] b) {
        BigInteger c0 = a[0].multiply(b[0]).add(a[1].multiply(b[1]).multiply(BETA)).mod(P);
        BigInteger c1 = a[0].multiply(b[1]).add(a[1].multiply(b[0])).mod(P);
        return new BigInteger[]{c0, c1};
    }
    private BigInteger[] cube(BigInteger[] a) { return mul(mul(a, a), a); }
    private BigInteger[] sub(BigInteger[] a, BigInteger[] b) {
        return new BigInteger[]{a[0].subtract(b[0]).mod(P), a[1].subtract(b[1]).mod(P)};
    }
    private BigInteger[] inv(BigInteger[] a) {
        BigInteger norm = a[0].multiply(a[0]).subtract(a[1].multiply(a[1]).multiply(BETA)).mod(P);
        BigInteger ni = norm.modInverse(P);
        return new BigInteger[]{a[0].multiply(ni).mod(P), a[1].negate().multiply(ni).mod(P)};
    }
    private boolean eq(BigInteger[] a, BigInteger[] b) { return a[0].equals(b[0]) && a[1].equals(b[1]); }

    private boolean scalarInf(BigInteger[] x, BigInteger[] y, BigInteger k) {
        BigInteger[][] acc = null;
        BigInteger[][] base = {x, y};
        for (int i = 0; i < k.bitLength(); i++) {
            if (k.testBit(i)) acc = add(acc, base);
            base = add(base, base);
        }
        return acc == null;
    }
    private BigInteger[][] add(BigInteger[][] a, BigInteger[][] b) {
        if (a == null) return b == null ? null : new BigInteger[][]{b[0].clone(), b[1].clone()};
        if (b == null) return a;
        BigInteger[] lambda;
        if (eq(a[0], b[0])) {
            if (a[1][0].add(b[1][0]).mod(P).signum() == 0 && a[1][1].add(b[1][1]).mod(P).signum() == 0) return null;
            BigInteger[] num = mul(new BigInteger[]{BigInteger.valueOf(3), BigInteger.ZERO}, mul(a[0], a[0]));
            BigInteger[] den = new BigInteger[]{a[1][0].shiftLeft(1).mod(P), a[1][1].shiftLeft(1).mod(P)};
            lambda = mul(num, inv(den));
        } else {
            lambda = mul(sub(b[1], a[1]), inv(sub(b[0], a[0])));
        }
        BigInteger[] x3 = sub(sub(mul(lambda, lambda), a[0]), b[0]);
        BigInteger[] y3 = sub(mul(lambda, sub(a[0], x3)), a[1]);
        return new BigInteger[][]{x3, y3};
    }
}
