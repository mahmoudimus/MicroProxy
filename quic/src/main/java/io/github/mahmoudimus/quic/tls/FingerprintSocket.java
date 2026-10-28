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
}
