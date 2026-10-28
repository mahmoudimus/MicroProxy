// Ported from rustls src/msgs/enums.rs and src/crypto/kx.rs (NamedGroup) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

/**
 * The groups the handshake offers and accepts for key exchange (RFC 8446 section 4.2.7): (EC)DHE
 * groups and the X25519MLKEM768 hybrid.
 */
public enum NamedGroup {
    /** X25519 (RFC 7748). */
    X25519(0x001d, null, 32),
    /** NIST P-256, {@code secp256r1}. */
    SECP256R1(0x0017, "secp256r1", 65),
    /** NIST P-384, {@code secp384r1}. */
    SECP384R1(0x0018, "secp384r1", 97),
    /** NIST P-521, {@code secp521r1}. */
    SECP521R1(0x0019, "secp521r1", 133),
    /**
     * X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem), the post-quantum hybrid browsers offer first: a
     * key encapsulation, so the client's share (an ML-KEM-768 encapsulation key and an X25519 key,
     * 1216 bytes) and the server's (a ciphertext and an X25519 key, 1120 bytes) differ.
     */
    X25519_MLKEM768(0x11ec, null, 1216);

    private final int code;
    private final String curve;
    private final int publicKeyLength;

    NamedGroup(int code, String curve, int publicKeyLength) {
        this.code = code;
        this.curve = curve;
        this.publicKeyLength = publicKeyLength;
    }

    /**
     * The group's TLS code point.
     *
     * @return the two-byte code, such as {@code 0x001d} for X25519
     */
    public int code() {
        return code;
    }

    /** The JCA name of the curve, or null for X25519. */
    String curve() {
        return curve;
    }

    /**
     * The length of a client's key share: the X25519 u-coordinate, an uncompressed EC point, or the
     * hybrid's encapsulation key and X25519 key.
     */
    int publicKeyLength() {
        return publicKeyLength;
    }

    /** The length of a server's key share: the client's, except for the hybrid's ciphertext and X25519 key. */
    int serverShareLength() {
        return this == X25519_MLKEM768 ? MlKem768.CIPHERTEXT_SIZE + 32 : publicKeyLength;
    }

    /**
     * The group with a TLS code point.
     *
     * @param code the code point
     * @return the group, or null if it is not one of these
     */
    public static NamedGroup forCode(int code) {
        for (NamedGroup group : values()) {
            if (group.code == code) return group;
        }
        return null;
    }
}
