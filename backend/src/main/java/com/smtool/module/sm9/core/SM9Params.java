package com.smtool.module.sm9.core;

import java.math.BigInteger;

/**
 * SM9 系统参数（GM/T 0044-2016 第 5 部分：参数定义）。
 *
 * <p>采用 256 位 BN 曲线，曲线方程 y^2 = x^3 + b，嵌入度 k = 12。
 * 所有参数取自国标附录，可用于逐步运算正确性验证。</p>
 */
public final class SM9Params {

    private SM9Params() {
    }

    private static BigInteger h(String hex) {
        return new BigInteger(hex.replaceAll("\\s", ""), 16);
    }

    /** 嵌入度 t 参数。 */
    public static final BigInteger T = h("60000000 0058F98A");

    /** 基域特征 q（素数 p）。 */
    public static final BigInteger P = h(
            "B6400000 02A3A6F1 D603AB4F F58EC745 21F2934B 1A7AEEDB E56F9B27 E351457D");

    /** 群的阶 N（记为 n）。 */
    public static final BigInteger N = h(
            "B6400000 02A3A6F1 D603AB4F F58EC744 49F2934B 18EA8BEE E56EE19C D69ECF25");

    /** 曲线方程参数 b。 */
    public static final BigInteger B = BigInteger.valueOf(5);

    /** 余因子 cf。 */
    public static final BigInteger COFACTOR = BigInteger.ONE;

    /** G1 生成元 P1 = (xP1, yP1)。 */
    public static final BigInteger P1_X = h(
            "93DE051D 62BF718F F5ED0704 487D01D6 E1E40869 09DC3280 E8C4E481 7C66DDDD");
    public static final BigInteger P1_Y = h(
            "21FE8DDA 4F21E607 63106512 5C395BBC 1C1C00CB FA602435 0C464CD7 0A3EA616");

    /** G2 生成元 P2 = ((xP2_1, xP2_0), (yP2_1, yP2_0))，Fp2 元素用 (虚部, 实部) 表示。 */
    public static final BigInteger P2_X_1 = h(
            "85AEF3D0 78640C98 597B6027 B441A01F F1DD2C19 0F5E93C4 54806C11 D8806141");
    public static final BigInteger P2_X_0 = h(
            "37227552 92130B08 D2AAB97F D34EC120 EE265948 D19C17AB F9B7213B AF82D65B");
    public static final BigInteger P2_Y_1 = h(
            "17509B09 2E845C12 66BA0D26 2CBEE6ED 0736A96F A347C8BD 856DC768 84EBEB96");
    public static final BigInteger P2_Y_0 = h(
            "A7CF28D5 19BE3DA6 5F317015 3D278FF2 47EFBA98 A71A0811 6215BBA5 C999A7C7");

    /** 曲线标识 cid = 0x12（BN 曲线）。 */
    public static final int CID = 0x12;

    /** 曲线方程文字描述（用于前端“曲线参数”标签页展示）。 */
    public static final String CURVE_EQUATION = "y^2 = x^3 + b，256 位 BN 椭圆曲线";
}
