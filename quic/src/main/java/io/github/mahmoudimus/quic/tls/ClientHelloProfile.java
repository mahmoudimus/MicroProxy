package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.random.RandomGenerator;

/**
 * What a client's ClientHello looks like:
 * <ul>
 *   <li>its cipher suites, in order;</li>
 *   <li>its extensions, in order, with how each body is made;</li>
 *   <li>whether the extensions are shuffled per hello, as Chrome has done since version 110
 *       (BoringSSL {@code SSL_set_permute_extensions});</li>
 *   <li>the length of its {@code legacy_session_id}.</li>
 * </ul>
 * A {@link HelloContext} supplies what changes per connection.
 */
public final class ClientHelloProfile {

    private final String name;
    private final int[] cipherSuites;
    private final List<ExtensionSpec> extensions;
    private final boolean shuffleExtensions;
    private final int sessionIdLength;

    /**
     * @param name the profile's name, such as {@code chrome-156}
     * @param cipherSuites the cipher suites in order, {@link ProfileExtensions#GREASE} for the
     *     hello's GREASE suite
     * @param extensions the extensions in order (the order they are shuffled from, if shuffled)
     * @param shuffleExtensions whether each hello permutes the extensions that are not {@link
     *     ExtensionSpec#fixedPosition() fixed}
     * @param sessionIdLength the length of the random {@code legacy_session_id}: 32 for a client
     *     in middlebox compatibility mode (RFC 8446 appendix D.4), 0 for none
     */
    public ClientHelloProfile(String name, int[] cipherSuites, List<ExtensionSpec> extensions,
            boolean shuffleExtensions, int sessionIdLength) {
        if (sessionIdLength < 0 || sessionIdLength > 32) {
            throw new IllegalArgumentException("session id length " + sessionIdLength);
        }
        this.name = Objects.requireNonNull(name, "name");
        this.cipherSuites = cipherSuites.clone();
        this.extensions = List.copyOf(extensions);
        this.shuffleExtensions = shuffleExtensions;
        this.sessionIdLength = sessionIdLength;
    }

    /** {@return the profile's name} */
    public String name() {
        return name;
    }

    /**
     * The ClientHello handshake message for one connection: type, 24-bit length and body.
     *
     * @param context the connection's inputs
     * @return the message
     */
    public byte[] encode(HelloContext context) {
        return clientHello(context).encode();
    }

    ClientHello clientHello(HelloContext context) {
        RandomGenerator random = context.random();
        byte[] clientRandom = new byte[32];
        random.nextBytes(clientRandom);
        byte[] sessionId = new byte[sessionIdLength];
        random.nextBytes(sessionId);
        int[] suites = cipherSuites.clone();
        for (int i = 0; i < suites.length; i++) {
            if (suites[i] == ProfileExtensions.GREASE) suites[i] = context.grease().cipher();
        }
        List<ExtensionSpec> order = shuffleExtensions ? shuffle(extensions, random) : extensions;
        List<Extension> out = new ArrayList<>(order.size());
        for (ExtensionSpec spec : order) {
            byte[] body = spec.body().encode(context);
            if (body != null) out.add(new Extension(spec.resolvedType(context.grease()), body));
        }
        return new ClientHello(0x0303, clientRandom, sessionId, suites, new byte[] {0}, out);
    }

    /** A random permutation of the extensions that are not fixed, the fixed ones keeping their places. */
    static List<ExtensionSpec> shuffle(List<ExtensionSpec> extensions, RandomGenerator random) {
        List<ExtensionSpec> movable = new ArrayList<>();
        for (ExtensionSpec e : extensions) {
            if (!e.fixedPosition()) movable.add(e);
        }
        for (int i = movable.size() - 1; i > 0; i--) {
            Collections.swap(movable, i, random.nextInt(i + 1));
        }
        Iterator<ExtensionSpec> next = movable.iterator();
        List<ExtensionSpec> out = new ArrayList<>(extensions.size());
        for (ExtensionSpec e : extensions) out.add(e.fixedPosition() ? e : next.next());
        return out;
    }
}
