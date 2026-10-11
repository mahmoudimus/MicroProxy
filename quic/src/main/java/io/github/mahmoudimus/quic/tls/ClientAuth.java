// Ported from rustls src/server/config.rs and src/webpki/client_verifier.rs (whether client
// authentication is offered, and whether it is mandatory) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

/** Whether a server asks clients for a certificate (RFC 8446 section 4.3.2). */
public enum ClientAuth {
    /** No CertificateRequest is sent. */
    NONE,
    /** A certificate is requested; a client may send none, but one it sends must be valid. */
    REQUEST,
    /** A valid certificate is required: a client that sends none fails with {@code certificate_required}. */
    REQUIRE
}
