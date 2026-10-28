package io.github.mahmoudimus.quic.tls;

/**
 * One extension of a {@link ClientHelloProfile}: its type, and how its body is made for a
 * connection.
 *
 * @param type the extension type, or {@link #GREASE_FIRST} or {@link #GREASE_LAST} for the
 *     hello's two GREASE extensions
 * @param body makes the body
 * @param keyShareGroups for {@code key_share}, the groups it carries shares for (GREASE as
 *     {@link ProfileExtensions#GREASE}), so a client can make the keys first; null otherwise
 */
public record ExtensionSpec(int type, Body body, int[] keyShareGroups) {

    /** An extension that is not {@code key_share}. */
    public ExtensionSpec(int type, Body body) {
        this(type, body, null);
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
     * them first and last, and {@code pre_shared_key}, which RFC 8446 requires to be last.
     */
    boolean fixedPosition() {
        return type < 0 || type == ExtensionType.PRE_SHARED_KEY;
    }
}
