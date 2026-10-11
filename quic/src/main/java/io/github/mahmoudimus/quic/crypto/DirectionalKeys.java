/*
 * Ported from rustls src/quic.rs (DirectionalKeys) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.crypto;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.QuicVersion;
import java.util.Objects;

/**
 * The keys that protect packets in one direction at one encryption level: a header protection
 * key and a packet (payload) key. Like its parts, an instance is confined to one thread at a time.
 *
 * @param header the header protection key
 * @param packet the payload key
 */
public record DirectionalKeys(HeaderKey header, PacketKey packet) {

    /**
     * Keys from their parts.
     *
     * @param header the header protection key
     * @param packet the payload key
     */
    public DirectionalKeys {
        Objects.requireNonNull(header, "header");
        Objects.requireNonNull(packet, "packet");
    }

    /**
     * Derives both keys from one traffic secret (RFC 9001 section 5.1).
     *
     * @param suite the cipher suite the secret belongs to
     * @param secret the traffic secret
     * @param version the QUIC version, which picks the HKDF labels
     * @return the keys
     */
    public static DirectionalKeys fromSecret(CipherSuite suite, byte[] secret, QuicVersion version) {
        return new DirectionalKeys(HeaderKey.fromSecret(suite, secret, version),
                PacketKey.fromSecret(suite, secret, version));
    }
}
