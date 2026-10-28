package io.github.mahmoudimus.quic.tls;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.random.RandomGenerator;

/**
 * What one ClientHello says that its profile does not: the server's name, the ALPN protocols
 * offered on this connection, the public keys of the key shares, the GREASE values, and where
 * the random bytes (client random, session id, GREASE ECH, shuffling) come from.
 *
 * @param serverName the SNI host name, or null to send none
 * @param alpnProtocols the ALPN protocols, in preference order; empty to send no ALPN
 * @param keyShares each key share's public key, by named group code, as the share carries it
 * @param grease the hello's GREASE values
 * @param random the source of the hello's random bytes; a {@link java.security.SecureRandom} on a
 *     real connection
 * @param supplied extension bodies the connection makes itself, by type, such as QUIC's
 *     {@code quic_transport_parameters}, for {@link ProfileExtensions#supplied}
 */
public record HelloContext(String serverName, List<String> alpnProtocols, Map<Integer, byte[]> keyShares,
        Grease grease, RandomGenerator random, Map<Integer, byte[]> supplied) {

    public HelloContext {
        alpnProtocols = List.copyOf(alpnProtocols);
        keyShares = Map.copyOf(keyShares);
        Objects.requireNonNull(grease, "grease");
        Objects.requireNonNull(random, "random");
        supplied = Map.copyOf(supplied);
    }

    /** A context with no supplied extension bodies. */
    public HelloContext(String serverName, List<String> alpnProtocols, Map<Integer, byte[]> keyShares, Grease grease,
            RandomGenerator random) {
        this(serverName, alpnProtocols, keyShares, grease, random, Map.of());
    }
}
