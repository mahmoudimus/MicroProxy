/*
 * Ported from rustls src/quic.rs (Apache-2.0): the Version enum with its Initial salts and HKDF
 * labels; the Retry integrity keys come from quinn-proto src/crypto/rustls.rs (Apache-2.0) and
 * RFC 9369 section 3.3.3.
 */
package io.github.mahmoudimus.quic;

import java.util.HexFormat;

/**
 * The QUIC versions this module speaks: version 1 (RFC 9000) and version 2 (RFC 9369). They
 * differ only in the version number, the long header packet type bits, the Initial salt, the
 * HKDF labels and the Retry integrity key.
 *
 * <p>Instances are immutable; the byte-array accessors return copies.
 */
public enum QuicVersion {
    /** QUIC version 1, {@code 0x00000001} (RFC 9000). */
    V1(0x0000_0001, "38762cf7f55934b34d179ae6a4c80cadccbb7f0a", "quic ",
            "be0c690b9f66575a1d766b54e368c84e", "461599d35d632bf2239825bb"),
    /** QUIC version 2, {@code 0x6b3343cf} (RFC 9369). */
    V2(0x6b33_43cf, "0dede3def700a6db819381be6e269dcbf9bd2ed9", "quicv2 ",
            "8fb4b01b56ac48e260fbcbcead7ccc92", "d86969bc2d7c6d9990efb04a");

    private final int wireValue;
    private final byte[] initialSalt;
    private final String labelPrefix;
    private final byte[] retryKey;
    private final byte[] retryNonce;

    QuicVersion(int wireValue, String salt, String labelPrefix, String retryKey, String retryNonce) {
        HexFormat hex = HexFormat.of();
        this.wireValue = wireValue;
        this.initialSalt = hex.parseHex(salt);
        this.labelPrefix = labelPrefix;
        this.retryKey = hex.parseHex(retryKey);
        this.retryNonce = hex.parseHex(retryNonce);
    }

    /**
     * The 32-bit version number as it appears in long headers.
     *
     * @return the version number
     */
    public int wireValue() {
        return wireValue;
    }

    /**
     * The salt that derives Initial secrets from the client's first Destination Connection ID
     * (RFC 9001 section 5.2, RFC 9369 section 3.3.1).
     *
     * @return a copy of the 20-byte salt
     */
    public byte[] initialSalt() {
        return initialSalt.clone();
    }

    /**
     * The HKDF label for the AEAD key: {@code "quic key"} or {@code "quicv2 key"}.
     *
     * @return the label, without the TLS {@code "tls13 "} prefix
     */
    public String keyLabel() {
        return labelPrefix + "key";
    }

    /**
     * The HKDF label for the AEAD IV: {@code "quic iv"} or {@code "quicv2 iv"}.
     *
     * @return the label, without the TLS {@code "tls13 "} prefix
     */
    public String ivLabel() {
        return labelPrefix + "iv";
    }

    /**
     * The HKDF label for the header protection key: {@code "quic hp"} or {@code "quicv2 hp"}.
     *
     * @return the label, without the TLS {@code "tls13 "} prefix
     */
    public String headerProtectionLabel() {
        return labelPrefix + "hp";
    }

    /**
     * The HKDF label for the next secret of a key update: {@code "quic ku"} or {@code "quicv2
     * ku"}.
     *
     * @return the label, without the TLS {@code "tls13 "} prefix
     */
    public String keyUpdateLabel() {
        return labelPrefix + "ku";
    }

    /**
     * The fixed AES-128-GCM key of the Retry integrity tag (RFC 9001 section 5.8).
     *
     * @return a copy of the 16-byte key
     */
    public byte[] retryIntegrityKey() {
        return retryKey.clone();
    }

    /**
     * The fixed nonce of the Retry integrity tag (RFC 9001 section 5.8).
     *
     * @return a copy of the 12-byte nonce
     */
    public byte[] retryIntegrityNonce() {
        return retryNonce.clone();
    }

    /**
     * The version with a wire number.
     *
     * @param wireValue the 32-bit version number
     * @return the version, or null if this module does not speak it
     */
    public static QuicVersion forWireValue(int wireValue) {
        for (QuicVersion v : values()) {
            if (v.wireValue == wireValue) return v;
        }
        return null;
    }

    /**
     * Whether a version number is reserved for exercising version negotiation, that is, matches
     * {@code 0x?a?a?a?a} (RFC 9000 section 15).
     *
     * @param wireValue the 32-bit version number
     * @return true for a reserved (GREASE) version
     */
    public static boolean isReserved(int wireValue) {
        return (wireValue & 0x0f0f_0f0f) == 0x0a0a_0a0a;
    }
}
