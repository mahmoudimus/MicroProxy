/*
 * Ported from quinn-proto src/shared.rs (IssuedCid) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.StatelessResetToken;
import java.util.Objects;

/**
 * A local connection ID issued to the peer, to be sent in a NEW_CONNECTION_ID frame.
 *
 * @param sequence the connection ID's sequence number
 * @param id the connection ID
 * @param resetToken the stateless reset token bound to it
 */
public record IssuedCid(long sequence, ConnectionId id, StatelessResetToken resetToken) {

    /**
     * An issued connection ID.
     *
     * @param sequence the sequence number, non-negative
     * @param id the connection ID
     * @param resetToken the reset token
     */
    public IssuedCid {
        if (sequence < 0) {
            throw new IllegalArgumentException("sequence " + sequence);
        }
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(resetToken, "resetToken");
    }
}
