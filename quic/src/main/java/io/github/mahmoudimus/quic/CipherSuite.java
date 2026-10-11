package io.github.mahmoudimus.quic;

/**
 * The TLS 1.3 cipher suites QUIC can use (RFC 9001 section 5.3), with what packet protection needs
 * to know about each: its HKDF hash, AEAD and key length.
 */
public enum CipherSuite {
    /** {@code TLS_AES_128_GCM_SHA256}, also used for Initial packets. */
    TLS_AES_128_GCM_SHA256(0x1301, Hkdf.SHA256, "AES/GCM/NoPadding", 16),
    /** {@code TLS_AES_256_GCM_SHA384}. */
    TLS_AES_256_GCM_SHA384(0x1302, Hkdf.SHA384, "AES/GCM/NoPadding", 32),
    /** {@code TLS_CHACHA20_POLY1305_SHA256}. */
    TLS_CHACHA20_POLY1305_SHA256(0x1303, Hkdf.SHA256, "ChaCha20-Poly1305", 32);

    private final int code;
    private final Hkdf hkdf;
    private final String aead;
    private final int keyLength;

    CipherSuite(int code, Hkdf hkdf, String aead, int keyLength) {
        this.code = code;
        this.hkdf = hkdf;
        this.aead = aead;
        this.keyLength = keyLength;
    }

    /**
     * The suite's TLS code point.
     *
     * @return the two-byte code, such as {@code 0x1301}
     */
    public int code() {
        return code;
    }

    /**
     * The HKDF over the suite's hash.
     *
     * @return the HKDF
     */
    public Hkdf hkdf() {
        return hkdf;
    }

    /**
     * The JCA transformation of the suite's AEAD.
     *
     * @return {@code "AES/GCM/NoPadding"} or {@code "ChaCha20-Poly1305"}
     */
    public String aead() {
        return aead;
    }

    /**
     * The AEAD key length, which is also the header protection key length.
     *
     * @return the key length in bytes
     */
    public int keyLength() {
        return keyLength;
    }

    /**
     * Whether header protection uses AES (as opposed to ChaCha20).
     *
     * @return true for the AES-GCM suites
     */
    public boolean aes() {
        return this != TLS_CHACHA20_POLY1305_SHA256;
    }

    /**
     * The suite with a TLS code point.
     *
     * @param code the code point
     * @return the suite, or null if QUIC cannot use it
     */
    public static CipherSuite forCode(int code) {
        for (CipherSuite suite : values()) {
            if (suite.code == code) return suite;
        }
        return null;
    }
}
