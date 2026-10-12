/**
 * A TLS 1.3 handshake (RFC 8446) for QUIC (RFC 9001), client and server, ported from rustls with
 * quinn's session interface. {@link io.github.mahmoudimus.quic.tls.TlsSession} is the entry point,
 * configured by {@link io.github.mahmoudimus.quic.tls.TlsConfig}; cryptography comes from the JDK.
 *
 * <p>The JDK's {@code SSLEngine} cannot be used for QUIC: it emits TLS records, keeps the traffic
 * secrets to itself and has no {@code quic_transport_parameters} extension. This package has no
 * record layer: handshake messages are exchanged per encryption level and the secrets are handed to
 * packet protection.
 */
package io.github.mahmoudimus.quic.tls;
