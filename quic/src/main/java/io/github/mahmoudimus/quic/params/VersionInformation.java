/*
 * Written from RFC 9368 section 3 (quinn has no version_information parameter); it follows the
 * coding style of quinn-proto src/transport_parameters.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.params;

import java.nio.ByteBuffer;
import java.util.List;

/**
 * The {@code version_information} transport parameter (RFC 9368 section 3), which authenticates
 * version negotiation.
 *
 * @param chosenVersion the version the sender chose for the connection, not zero
 * @param availableVersions the sender's other versions: a client lists what its first flight is
 *     compatible with, the chosen version included; a server lists its fully deployed versions
 */
public record VersionInformation(int chosenVersion, List<Integer> availableVersions) {

    /** The {@code VERSION_NEGOTIATION_ERROR} transport error code (RFC 9368 section 10.2). */
    public static final long VERSION_NEGOTIATION_ERROR = 0x11;

    /**
     * Version information.
     *
     * @param chosenVersion the chosen version
     * @param availableVersions the available versions
     */
    public VersionInformation {
        availableVersions = List.copyOf(availableVersions);
    }

    int encodedLength() {
        return 4 * (1 + availableVersions.size());
    }

    void encode(ByteBuffer out) {
        out.putInt(chosenVersion);
        for (int v : availableVersions) {
            out.putInt(v);
        }
    }
}
