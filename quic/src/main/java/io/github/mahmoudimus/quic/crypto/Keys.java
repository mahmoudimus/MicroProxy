/*
 * Ported from rustls src/quic.rs (Keys::initial, Keys::new, Secrets::update and
 * Secrets::next_packet_keys) and quinn-proto src/crypto/rustls.rs (initial_keys) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.crypto;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.EncryptionLevel;
import io.github.mahmoudimus.quic.Hkdf;
import io.github.mahmoudimus.quic.QuicVersion;
import io.github.mahmoudimus.quic.Secrets;
import java.util.Objects;

/**
 * The packet protection keys of one encryption level, from one endpoint's point of view: {@code
 * local} protects what it sends and {@code remote} removes protection from what it receives.
 *
 * <p>Keys come from TLS traffic secrets ({@link #fromSecrets}), or for Initial packets from the
 * client's first Destination Connection ID ({@link #initial}). A 1-RTT key update (RFC 9001
 * section 6) derives the next secrets with {@link #nextSecrets} and the next keys with {@link
 * #update}, which keeps the header protection keys.
 *
 * @param local the keys for packets this endpoint sends
 * @param remote the keys for packets this endpoint receives
 */
public record Keys(DirectionalKeys local, DirectionalKeys remote) {

    private static final byte[] EMPTY = new byte[0];

    /**
     * Keys from their parts.
     *
     * @param local the keys for packets this endpoint sends
     * @param remote the keys for packets this endpoint receives
     */
    public Keys {
        Objects.requireNonNull(local, "local");
        Objects.requireNonNull(remote, "remote");
    }

    /**
     * QUIC version 1 keys from the traffic secrets the TLS handshake produced.
     *
     * @param secrets the client and server secrets of one level
     * @param isServer whether this endpoint is the server, which picks the local secret
     * @return the keys
     */
    public static Keys fromSecrets(Secrets secrets, boolean isServer) {
        return fromSecrets(secrets, isServer, QuicVersion.V1);
    }

    /**
     * Keys from the traffic secrets the TLS handshake produced.
     *
     * @param secrets the client and server secrets of one level
     * @param isServer whether this endpoint is the server, which picks the local secret
     * @param version the QUIC version, which picks the HKDF labels
     * @return the keys
     */
    public static Keys fromSecrets(Secrets secrets, boolean isServer, QuicVersion version) {
        CipherSuite suite = secrets.suite();
        DirectionalKeys client = DirectionalKeys.fromSecret(suite, secrets.client(), version);
        DirectionalKeys server = DirectionalKeys.fromSecret(suite, secrets.server(), version);
        return isServer ? new Keys(server, client) : new Keys(client, server);
    }

    /**
     * The Initial secrets for a client's first Destination Connection ID (RFC 9001 section 5.2):
     * HKDF-Extract with the version's salt, then the {@code "client in"} and {@code "server in"}
     * labels.
     *
     * @param version the QUIC version, which picks the salt
     * @param clientDestinationId the Destination Connection ID of the client's first Initial
     * @return the secrets, for {@link CipherSuite#TLS_AES_128_GCM_SHA256}
     */
    public static Secrets initialSecrets(QuicVersion version, ConnectionId clientDestinationId) {
        Hkdf hkdf = Hkdf.SHA256;
        byte[] initial = hkdf.extract(version.initialSalt(), clientDestinationId.toByteArray());
        byte[] client = hkdf.expandLabel(initial, "client in", EMPTY, hkdf.hashLength());
        byte[] server = hkdf.expandLabel(initial, "server in", EMPTY, hkdf.hashLength());
        return new Secrets(EncryptionLevel.INITIAL, CipherSuite.TLS_AES_128_GCM_SHA256, client, server);
    }

    /**
     * The Initial keys for a client's first Destination Connection ID.
     *
     * @param version the QUIC version
     * @param clientDestinationId the Destination Connection ID of the client's first Initial
     * @param isServer whether this endpoint is the server
     * @return the keys
     */
    public static Keys initial(QuicVersion version, ConnectionId clientDestinationId, boolean isServer) {
        return fromSecrets(initialSecrets(version, clientDestinationId), isServer, version);
    }

    /**
     * The secrets after a key update: each secret expanded with the version's {@code "quic ku"}
     * label to the hash length (RFC 9001 section 6.1).
     *
     * @param secrets the current 1-RTT secrets
     * @param version the QUIC version, which picks the label
     * @return the next secrets, for the same level and suite
     */
    public static Secrets nextSecrets(Secrets secrets, QuicVersion version) {
        return new Secrets(secrets.level(), secrets.suite(),
                nextSecret(secrets.suite(), secrets.client(), version),
                nextSecret(secrets.suite(), secrets.server(), version));
    }

    /**
     * The next secret of one direction after a key update.
     *
     * @param suite the cipher suite
     * @param secret the current traffic secret
     * @param version the QUIC version, which picks the label
     * @return the next traffic secret
     */
    public static byte[] nextSecret(CipherSuite suite, byte[] secret, QuicVersion version) {
        Hkdf hkdf = suite.hkdf();
        return hkdf.expandLabel(secret, version.keyUpdateLabel(), EMPTY, hkdf.hashLength());
    }

    /**
     * The keys of the next key phase: new packet keys from the next secrets, with these header
     * keys, which a key update does not change (RFC 9001 section 6).
     *
     * @param nextSecrets the secrets from {@link #nextSecrets}
     * @param isServer whether this endpoint is the server
     * @param version the QUIC version, which picks the labels
     * @return the keys for the next key phase
     */
    public Keys update(Secrets nextSecrets, boolean isServer, QuicVersion version) {
        CipherSuite suite = nextSecrets.suite();
        PacketKey client = PacketKey.fromSecret(suite, nextSecrets.client(), version);
        PacketKey server = PacketKey.fromSecret(suite, nextSecrets.server(), version);
        return new Keys(new DirectionalKeys(local.header(), isServer ? server : client),
                new DirectionalKeys(remote.header(), isServer ? client : server));
    }
}
