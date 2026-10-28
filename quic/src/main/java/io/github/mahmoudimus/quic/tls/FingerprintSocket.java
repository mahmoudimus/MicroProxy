package io.github.mahmoudimus.quic.tls;

/**
 * A socket of a {@link FingerprintSslContext}: the ClientHello profile it presents, and what the
 * context was given to go with it ({@link FingerprintSslContext.Builder#attach}), such as the HTTP/2
 * fingerprint for connections over it.
 */
public interface FingerprintSocket {

    /** {@return the ClientHello profile the socket presents} */
    ClientHelloProfile profile();

    /** {@return what the context was given to go with its sockets, or null} */
    Object attachment();

    /**
     * Whether the handshake was with Encrypted Client Hello (RFC 9849) and the server accepted
     * it, so the server name and the rest of the real ClientHello went encrypted.
     *
     * @return true once a handshake has completed with ECH accepted; false otherwise
     */
    default boolean echAccepted() {
        return false;
    }
}
