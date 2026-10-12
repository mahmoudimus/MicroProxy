// Ported from rustls src/msgs/enums.rs and src/crypto/kx.rs (NamedGroup) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

/** The (EC)DHE groups the handshake offers and accepts for key exchange (RFC 8446 section 4.2.7). */
public enum NamedGroup {
    /** X25519 (RFC 7748). */
    X25519(0x001d, null, 32),
    /** NIST P-256, {@code secp256r1}. */
    SECP256R1(0x0017, "secp256r1", 65),
    /** NIST P-384, {@code secp384r1}. */
    SECP384R1(0x0018, "secp384r1", 97);

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

    /** The length of a key share: the X25519 u-coordinate, or an uncompressed EC point. */
    int publicKeyLength() {
        return publicKeyLength;
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
