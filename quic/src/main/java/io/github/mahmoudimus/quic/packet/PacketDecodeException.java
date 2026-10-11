/*
 * Ported from quinn-proto src/packet.rs (PacketDecodeError) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.packet;

import java.io.Serial;

/**
 * A packet header that cannot be decoded. Such packets are dropped without affecting the
 * connection (RFC 9000 section 12.2 and 17), so this is not a {@link
 * io.github.mahmoudimus.quic.QuicException}.
 */
public class PacketDecodeException extends Exception {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * A decode failure.
     *
     * @param reason what was wrong with the header
     */
    public PacketDecodeException(String reason) {
        super(reason);
    }
}
