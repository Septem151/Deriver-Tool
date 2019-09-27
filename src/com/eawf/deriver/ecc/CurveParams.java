package com.eawf.deriver.ecc;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/**
 * Non-instantiable class containing Curve parameters for the SECP-256K1
 * Elliptic Curve. More information may be found on Pg. 9 of
 * <a href="https://www.secg.org/sec2-v2.pdf">SEC2 Vol. 2</a>
 *
 * @author Carson Mullins
 */
public class CurveParams {

    private CurveParams() {
    } // Non-instantiable

    public static final ECPoint G = new ECPoint(
            new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
            new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    );
    public static final BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    public static final BigInteger a = BigInteger.ZERO;
    public static final BigInteger b = BigInteger.valueOf(7);
    public static final BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    public static final int h = 1;

    public static final ECFieldFp field = new ECFieldFp(p);
    public static final EllipticCurve curve = new EllipticCurve(field, a, b);
    public static final ECParameterSpec ecSpec = new ECParameterSpec(curve, G, n, h);
}
