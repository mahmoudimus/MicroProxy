package io.github.mahmoudimus.quic;

/**
 * The traffic secrets for one encryption level, as the TLS handshake hands them to packet
 * protection: one secret per direction and the cipher suite they are for.
 *
 * @param level the encryption level the secrets protect
 * @param suite the negotiated cipher suite
 * @param client the client's traffic secret (what the client writes with)
 * @param server the server's traffic secret (what the server writes with)
 */
public record Secrets(EncryptionLevel level, CipherSuite suite, byte[] client, byte[] server) {}
