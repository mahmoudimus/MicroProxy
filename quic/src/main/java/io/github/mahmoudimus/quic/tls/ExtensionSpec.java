package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import java.util.List;

/**
 * One extension of a {@link ClientHelloProfile}: its type, and how its body is made for a
 * connection.
 *
 * @param type the extension type, or {@link #GREASE_FIRST} or {@link #GREASE_LAST} for the
 *     hello's two GREASE extensions
 * @param body makes the body
 * @param keyShareGroups for {@code key_share}, the groups it carries shares for (GREASE as
 *     {@link ProfileExtensions#GREASE}), so a client can make the keys first; null otherwise
 * @param pinned whether shuffling leaves it where it is, as NSS leaves the extensions it adds
 *     after its own (QUIC's transport parameters, ECH)
 */
public record ExtensionSpec(int type, Body body, int[] keyShareGroups, boolean pinned) {

    /** An extension that shuffling may move. */
    public ExtensionSpec(int type, Body body, int[] keyShareGroups) {
        this(type, body, keyShareGroups, false);
    }

    /** An extension that is not {@code key_share}. */
    public ExtensionSpec(int type, Body body) {
        this(type, body, null);
    }

    /** {@return this extension, in a place that shuffling does not change} */
    public ExtensionSpec pin() {
        return new ExtensionSpec(type, body, keyShareGroups, true);
    }

    /** The type of the first GREASE extension, {@link Grease#extension1()}. */
    public static final int GREASE_FIRST = -1;

    /** The type of the last GREASE extension, {@link Grease#extension2()}. */
    public static final int GREASE_LAST = -2;

    /** Makes an extension's body for one hello. */
    @FunctionalInterface
    public interface Body {

        /**
         * The body for this hello.
         *
         * @param context the hello's per-connection inputs
         * @return the body, or null to leave the extension out of this hello
         */
        byte[] encode(HelloContext context);
    }

    /**
     * A body made from the rest of the hello, as Firefox's GREASE ECH is sized from the inner hello
     * it would encrypt: encoded after the other extensions' bodies.
     */
    @FunctionalInterface
    public interface WholeHelloBody extends Body {

        /**
         * The body for this hello.
         *
         * @param context the hello's per-connection inputs
         * @param cipherSuites the hello's cipher suites
         * @param others the hello's other extensions, in order (without {@code pre_shared_key},
         *     which the client adds after them: its length is {@link HelloContext#pskLength()})
         * @return the body, or null to leave the extension out of this hello
         */
        byte[] encode(HelloContext context, int[] cipherSuites, List<Extension> others);

        @Override
        default byte[] encode(HelloContext context) {
            throw new UnsupportedOperationException("made from the whole hello");
        }
    }

    /** The type on the wire, GREASE placeholders replaced by the hello's values. */
    int resolvedType(Grease grease) {
        return switch (type) {
            case GREASE_FIRST -> grease.extension1();
            case GREASE_LAST -> grease.extension2();
            default -> type;
        };
    }

    /**
     * Whether shuffling leaves this extension in place: the GREASE extensions, as BoringSSL keeps
     * them first and last, {@code pre_shared_key}, which RFC 8446 requires to be last, and those
     * {@link #pinned}.
     */
    boolean fixedPosition() {
        return pinned || type < 0 || type == ExtensionType.PRE_SHARED_KEY;
    }
}
