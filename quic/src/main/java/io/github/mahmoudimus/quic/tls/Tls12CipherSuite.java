package io.github.mahmoudimus.quic.tls;

/**
 * The TLS 1.2 cipher suites browser profiles offer (RFC 5246, 5289, 7905): ECDHE with an ECDSA or
 * RSA certificate, or RSA key transport; AES-GCM, ChaCha20-Poly1305 or AES-CBC with HMAC-SHA1.
 * The PRF hash is SHA-384 for the {@code _SHA384} suites and SHA-256 for the rest.
 */
public enum Tls12CipherSuite {
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xc02b, KeyExchange.ECDHE_ECDSA, Bulk.AES_128_GCM, false),
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0xc02c, KeyExchange.ECDHE_ECDSA, Bulk.AES_256_GCM, true),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xc02f, KeyExchange.ECDHE_RSA, Bulk.AES_128_GCM, false),
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xc030, KeyExchange.ECDHE_RSA, Bulk.AES_256_GCM, true),
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0xcca9, KeyExchange.ECDHE_ECDSA, Bulk.CHACHA20_POLY1305, false),
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xcca8, KeyExchange.ECDHE_RSA, Bulk.CHACHA20_POLY1305, false),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xc009, KeyExchange.ECDHE_ECDSA, Bulk.AES_128_CBC_SHA, false),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0xc00a, KeyExchange.ECDHE_ECDSA, Bulk.AES_256_CBC_SHA, false),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xc013, KeyExchange.ECDHE_RSA, Bulk.AES_128_CBC_SHA, false),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xc014, KeyExchange.ECDHE_RSA, Bulk.AES_256_CBC_SHA, false),
    TLS_RSA_WITH_AES_128_GCM_SHA256(0x009c, KeyExchange.RSA, Bulk.AES_128_GCM, false),
    TLS_RSA_WITH_AES_256_GCM_SHA384(0x009d, KeyExchange.RSA, Bulk.AES_256_GCM, true),
    TLS_RSA_WITH_AES_128_CBC_SHA(0x002f, KeyExchange.RSA, Bulk.AES_128_CBC_SHA, false),
    TLS_RSA_WITH_AES_256_CBC_SHA(0x0035, KeyExchange.RSA, Bulk.AES_256_CBC_SHA, false);

    /** How the premaster secret is agreed. */
    enum KeyExchange { ECDHE_ECDSA, ECDHE_RSA, RSA }

    /**
     * The record protection: key length, the IV length in the key block (the implicit part of the
     * nonce for AEADs; unused for CBC, whose IVs are explicit), and the MAC key length.
     */
    enum Bulk {
        AES_128_GCM(16, 4, 0), AES_256_GCM(32, 4, 0), CHACHA20_POLY1305(32, 12, 0),
        AES_128_CBC_SHA(16, 16, 20), AES_256_CBC_SHA(32, 16, 20);

        final int keyLength;
        final int ivLength;
        final int macLength;

        Bulk(int keyLength, int ivLength, int macLength) {
            this.keyLength = keyLength;
            this.ivLength = ivLength;
            this.macLength = macLength;
        }

        boolean cbc() {
            return macLength > 0;
        }
    }

    final int code;
    final KeyExchange keyExchange;
    final Bulk bulk;
    final boolean sha384;

    Tls12CipherSuite(int code, KeyExchange keyExchange, Bulk bulk, boolean sha384) {
        this.code = code;
        this.keyExchange = keyExchange;
        this.bulk = bulk;
        this.sha384 = sha384;
    }

    /** {@return the suite's code point} */
    public int code() {
        return code;
    }

    /** {@return the HMAC the PRF uses: {@code HmacSHA384} or {@code HmacSHA256}} */
    String prfMac() {
        return sha384 ? "HmacSHA384" : "HmacSHA256";
    }

    /** {@return the hash of the transcript for Finished and the extended master secret} */
    String transcriptHash() {
        return sha384 ? "SHA-384" : "SHA-256";
    }

    /**
     * The suite with a code point.
     *
     * @param code the code point
     * @return the suite, or null if it is not one of these
     */
    public static Tls12CipherSuite forCode(int code) {
        for (Tls12CipherSuite s : values()) {
            if (s.code == code) return s;
        }
        return null;
    }
}
