// Ported from rustls src/crypto/kx.rs and the provider key exchanges of src/crypto (ActiveKeyExchange,
// SupportedKxGroup: generate a key share, then complete it with the peer's) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.QuicException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;

/**
 * One ephemeral (EC)DHE key pair and its key share (RFC 8446 section 4.2.8.2): X25519's 32-byte
 * little-endian u-coordinate, or an uncompressed P-256 or P-384 point. Peer shares are validated
 * (length, point on the curve, a non-zero X25519 result) and fail with {@code illegal_parameter}.
 */
final class KeyExchange {

    private final NamedGroup group;
    private final PrivateKey privateKey;
    private final byte[] publicKey;

    private KeyExchange(NamedGroup group, PrivateKey privateKey, byte[] publicKey) {
        this.group = group;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    static KeyExchange generate(NamedGroup group, SecureRandom random) {
        try {
            KeyPair pair;
            if (group == NamedGroup.X25519) {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("XDH");
                gen.initialize(NamedParameterSpec.X25519, random);
                pair = gen.generateKeyPair();
                return new KeyExchange(group, pair.getPrivate(), encodeX25519(((XECPublicKey) pair.getPublic()).getU()));
            }
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec(group.curve()), random);
            pair = gen.generateKeyPair();
            ECPublicKey pub = (ECPublicKey) pair.getPublic();
            return new KeyExchange(group, pair.getPrivate(), encodePoint(pub.getW(), pub.getParams()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot generate a " + group + " key share", e);
        }
    }

    /** An X25519 key pair from a known private scalar (RFC 7748 section 5), for test vectors. */
    static KeyExchange x25519(byte[] scalar) throws GeneralSecurityException {
        PrivateKey priv = KeyFactory.getInstance("XDH")
                .generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, scalar.clone()));
        // The public key is X25519(scalar, 9), the agreement with the base point.
        byte[] basePoint = new byte[32];
        basePoint[0] = 9;
        byte[] pub = agreeX25519(priv, basePoint);
        return new KeyExchange(NamedGroup.X25519, priv, pub);
    }

    /** A key pair from known keys, for test vectors. */
    static KeyExchange of(NamedGroup group, PrivateKey privateKey, byte[] publicKey) {
        return new KeyExchange(group, privateKey, publicKey.clone());
    }

    NamedGroup group() {
        return group;
    }

    byte[] publicKey() {
        return publicKey.clone();
    }

    /** The shared secret with the peer's key share. */
    byte[] agree(byte[] peer) throws QuicException {
        if (peer.length != group.publicKeyLength()) {
            throw TlsAlert.illegalParameter(group + " key share has length " + peer.length);
        }
        byte[] secret;
        try {
            if (group == NamedGroup.X25519) {
                secret = agreeX25519(privateKey, peer);
            } else {
                ECParameterSpec params = EcCurves.forName(group.curve());
                ECPoint point = decodePoint(peer, params);
                if (point == null || !EcCurves.onCurve(params, point)) {
                    throw TlsAlert.illegalParameter(group + " key share is not a point on the curve");
                }
                PublicKey pub = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, params));
                KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                ka.init(privateKey);
                ka.doPhase(pub, true);
                secret = ka.generateSecret();
            }
        } catch (GeneralSecurityException | RuntimeException e) {
            throw TlsAlert.illegalParameter("invalid " + group + " key share");
        }
        boolean zero = true;
        for (byte b : secret) zero &= b == 0;
        if (zero) {
            // RFC 8446 section 7.4.2: an all-zero X25519 result means a small-order point.
            throw TlsAlert.illegalParameter(group + " key exchange produced zero");
        }
        return secret;
    }

    private static byte[] agreeX25519(PrivateKey priv, byte[] peer) throws GeneralSecurityException {
        byte[] le = peer.clone();
        // RFC 7748 section 5: the most significant bit of the final byte is masked.
        le[31] &= 0x7f;
        PublicKey pub = KeyFactory.getInstance("XDH")
                .generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, new BigInteger(1, reverse(le))));
        KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(priv);
        ka.doPhase(pub, true);
        return ka.generateSecret();
    }

    private static byte[] encodeX25519(BigInteger u) {
        byte[] be = u.toByteArray();
        byte[] out = new byte[32];
        // Little-endian, dropping a sign byte BigInteger may add.
        for (int i = 0; i < 32 && i < be.length; i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    private static byte[] reverse(byte[] b) {
        byte[] out = new byte[b.length];
        for (int i = 0; i < b.length; i++) out[i] = b[b.length - 1 - i];
        return out;
    }

    static byte[] encodePoint(ECPoint w, ECParameterSpec params) {
        int n = EcCurves.fieldLength(params);
        byte[] out = new byte[1 + 2 * n];
        out[0] = 4;
        copyUnsigned(w.getAffineX(), out, 1, n);
        copyUnsigned(w.getAffineY(), out, 1 + n, n);
        return out;
    }

    private static void copyUnsigned(BigInteger v, byte[] out, int offset, int length) {
        byte[] b = v.toByteArray();
        int start = Math.max(0, b.length - length);
        int count = b.length - start;
        System.arraycopy(b, start, out, offset + length - count, count);
    }

    private static ECPoint decodePoint(byte[] encoded, ECParameterSpec params) {
        int n = EcCurves.fieldLength(params);
        if (encoded.length != 1 + 2 * n || encoded[0] != 4) return null;
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 1, 1 + n));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(encoded, 1 + n, 1 + 2 * n));
        return new ECPoint(x, y);
    }
}
