// Ported from rustls src/crypto/kx.rs and src/webpki/verify.rs (which curve a key is on) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/** The NIST curves the handshake uses, from the JDK's own parameters. */
final class EcCurves {

    static final ECParameterSpec P256 = load("secp256r1");
    static final ECParameterSpec P384 = load("secp384r1");
    static final ECParameterSpec P521 = load("secp521r1");

    private EcCurves() {}

    private static ECParameterSpec load(String name) {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(name));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("JDK lacks curve " + name, e);
        }
    }

    static ECParameterSpec forName(String name) {
        return switch (name) {
            case "secp256r1" -> P256;
            case "secp384r1" -> P384;
            case "secp521r1" -> P521;
            default -> throw new IllegalArgumentException(name);
        };
    }

    /** The name of the curve {@code spec} describes, or null if it is not P-256, P-384 or P-521. */
    static String nameOf(ECParameterSpec spec) {
        if (spec == null) return null;
        if (same(spec, P256)) return "secp256r1";
        if (same(spec, P384)) return "secp384r1";
        if (same(spec, P521)) return "secp521r1";
        return null;
    }

    private static boolean same(ECParameterSpec a, ECParameterSpec b) {
        return a.getCurve().equals(b.getCurve())
                && a.getGenerator().equals(b.getGenerator())
                && a.getOrder().equals(b.getOrder());
    }

    /** Whether {@code point} is an affine point on {@code spec}'s curve: y^2 = x^3 + ax + b (mod p). */
    static boolean onCurve(ECParameterSpec spec, ECPoint point) {
        if (point == null || point.equals(ECPoint.POINT_INFINITY)) return false;
        EllipticCurve curve = spec.getCurve();
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        BigInteger x = point.getAffineX();
        BigInteger y = point.getAffineY();
        if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0) return false;
        BigInteger left = y.multiply(y).mod(p);
        BigInteger right = x.pow(3).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
        return left.equals(right);
    }

    /** The length in bytes of a field element. */
    static int fieldLength(ECParameterSpec spec) {
        return (spec.getCurve().getField().getFieldSize() + 7) / 8;
    }
}
