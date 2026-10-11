/**
 * A TLS 1.3 handshake (RFC 8446) for QUIC (RFC 9001), client and server, ported from rustls with
 * quinn's session interface. {@link io.github.mahmoudimus.quic.tls.TlsSession} is the entry point,
 * configured by {@link io.github.mahmoudimus.quic.tls.TlsConfig}; cryptography comes from the JDK.
 *
 * <p>The JDK's {@code SSLEngine} cannot be used for QUIC: it emits TLS records, keeps the traffic
 * secrets to itself and has no {@code quic_transport_parameters} extension. This package has no
 * record layer: handshake messages are exchanged per encryption level and the secrets are handed to
 * packet protection.
 *
 * <p>Session resumption and 0-RTT: a server seals tickets with a {@link
 * io.github.mahmoudimus.quic.tls.Ticketer}, a client keeps them as {@link
 * io.github.mahmoudimus.quic.tls.SessionTicket}s in a {@link
 * io.github.mahmoudimus.quic.tls.ClientSessionStore}, and a server's {@link
 * io.github.mahmoudimus.quic.tls.EarlyDataPolicy} decides on early data, which can be replayed.
 */
package io.github.mahmoudimus.quic.tls;
