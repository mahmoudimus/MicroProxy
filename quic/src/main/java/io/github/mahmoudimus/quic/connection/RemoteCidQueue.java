/*
 * Ported from quinn-proto src/cid_queue.rs (CidQueue) and the NEW_CONNECTION_ID handling of
 * src/connection/mod.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.StatelessResetToken;
import io.github.mahmoudimus.quic.frame.Frame;
import java.util.Objects;

/**
 * The connection IDs the peer issued to this endpoint (RFC 9000 section 5.1.2): a window of at
 * most {@code limit} IDs, our {@code active_connection_id_limit}, starting with the one in use. It
 * may have gaps from loss or reordering.
 *
 * <p>NEW_CONNECTION_ID frames that would exceed the limit are a {@code CONNECTION_ID_LIMIT_ERROR};
 * Retire Prior To retires the IDs below it, and the caller sends RETIRE_CONNECTION_ID for them.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class RemoteCidQueue {

    /** quinn's window, and the {@code active_connection_id_limit} it advertises. */
    public static final int DEFAULT_LIMIT = 5;

    /** The outcome of {@link #insert}. */
    public enum InsertError {
        /** The ID was already retired. */
        RETIRED,
        /** The sequence number is beyond the window: the peer exceeded our limit. */
        EXCEEDS_LIMIT
    }

    /**
     * Sequence numbers to retire, and the reset token of the ID now in use.
     *
     * @param start the first sequence number to retire
     * @param end one past the last
     * @param resetToken the reset token of the new active ID
     */
    public record Retired(long start, long end, StatelessResetToken resetToken) {}

    private final ConnectionId[] cids;
    private final StatelessResetToken[] tokens;
    /** The index of the active ID in the ring buffer. */
    private int cursor;
    /** The sequence number of the active ID, the smallest in the buffer. */
    private long offset;

    /**
     * A queue holding the ID the handshake used, sequence number 0.
     *
     * @param initial the peer's first Source Connection ID
     * @param limit our {@code active_connection_id_limit}, at least 2
     */
    public RemoteCidQueue(ConnectionId initial, int limit) {
        if (limit < 2) {
            throw new IllegalArgumentException("active_connection_id_limit " + limit + " < 2");
        }
        cids = new ConnectionId[limit];
        tokens = new StatelessResetToken[limit];
        cids[0] = Objects.requireNonNull(initial);
    }

    /**
     * A queue with quinn's window of {@value #DEFAULT_LIMIT}.
     *
     * @param initial the peer's first Source Connection ID
     */
    public RemoteCidQueue(ConnectionId initial) {
        this(initial, DEFAULT_LIMIT);
    }

    private int len() {
        return cids.length;
    }

    /**
     * Stores a NEW_CONNECTION_ID frame's ID, retiring those below its Retire Prior To.
     *
     * @param frame the frame
     * @return null if nothing was retired, else the sequence numbers to retire and the new active
     *     ID's reset token
     * @throws CidInsertException if the ID was already retired or exceeds the limit
     */
    public Retired insert(Frame.NewConnectionId frame) throws CidInsertException {
        long index = frame.sequence() - offset;
        if (index < 0) {
            throw new CidInsertException(InsertError.RETIRED);
        }
        long retiredCount = Math.max(0, frame.retirePriorTo() - offset);
        if (index >= len() + retiredCount) {
            throw new CidInsertException(InsertError.EXCEEDS_LIMIT);
        }
        // Discard retired IDs
        for (int i = 0; i < Math.min(retiredCount, len()); i++) {
            int slot = (cursor + i) % len();
            cids[slot] = null;
            tokens[slot] = null;
        }
        // Record the new ID
        int slot = (int) ((cursor + index) % len());
        cids[slot] = frame.connectionId();
        tokens[slot] = frame.resetToken();
        if (retiredCount == 0) {
            return null;
        }
        // The active ID was retired: move to the first known ID at or after retire_prior_to
        cursor = (int) ((cursor + retiredCount) % len());
        int step = firstPresent(0);
        if (step < 0) {
            throw new IllegalStateException("retired every connection ID without supplying one");
        }
        cursor = (cursor + step) % len();
        long origOffset = offset;
        offset = frame.retirePriorTo() + step;
        // IDs in (origOffset + len)..offset were never received, or the peer would have exceeded
        // our limit; if they arrive later they are retired then, so the RETIRE_CONNECTION_ID
        // frames queued here stay bounded
        StatelessResetToken token = tokens[cursor];
        return new Retired(origOffset, Math.min(offset, origOffset + len()), Objects.requireNonNull(token));
    }

    /**
     * Processes a NEW_CONNECTION_ID frame as the connection does: stores the ID and queues
     * RETIRE_CONNECTION_ID frames for the IDs it retires.
     *
     * @param frame the frame
     * @param pending where to queue RETIRE_CONNECTION_ID
     * @return the reset token of a new active ID, or null if the active ID did not change
     * @throws QuicException {@code PROTOCOL_VIOLATION} if the peer uses zero-length IDs or reuses a
     *     sequence number for another ID, {@code CONNECTION_ID_LIMIT_ERROR} if it exceeds our limit
     */
    public StatelessResetToken onNewConnectionId(Frame.NewConnectionId frame, Retransmits pending)
            throws QuicException {
        if (active().isEmpty()) {
            throw new QuicException(QuicException.PROTOCOL_VIOLATION, "NEW_CONNECTION_ID when CIDs aren't in use");
        }
        long index = frame.sequence() - offset;
        if (index >= 0 && index < len()) {
            ConnectionId known = cids[(int) ((cursor + index) % len())];
            if (known != null && index > 0 && !known.equals(frame.connectionId())) {
                throw new QuicException(QuicException.PROTOCOL_VIOLATION,
                        "NEW_CONNECTION_ID reuses sequence number " + frame.sequence() + " for another ID");
            }
        }
        try {
            Retired retired = insert(frame);
            if (retired == null) {
                return null;
            }
            pending.retireCids(retired.start(), retired.end());
            return retired.resetToken();
        } catch (CidInsertException e) {
            if (e.error() == InsertError.EXCEEDS_LIMIT) {
                throw new QuicException(QuicException.CONNECTION_ID_LIMIT_ERROR, "too many connection IDs");
            }
            // A range larger than the window may have been retired at once without
            // RETIRE_CONNECTION_ID for this one
            pending.retireCids(frame.sequence(), frame.sequence() + 1);
            return null;
        }
    }

    /**
     * The ID {@link #next()} would switch to, without switching: a probe of a new path uses it
     * before the connection moves there (RFC 9000 section 9.5).
     *
     * @return the ID, or null if the peer supplied no unused one
     */
    public ConnectionId peekNext() {
        int step = firstPresent(1);
        return step < 0 ? null : cids[(cursor + step) % len()];
    }

    /**
     * Switches to the next known ID, as when migrating or for a server leaving the handshake ID.
     *
     * @return the new ID's reset token and the sequence numbers to retire, or null if no other ID
     *     is known
     */
    public Retired next() {
        int step = firstPresent(1);
        if (step < 0) {
            return null;
        }
        cids[cursor] = null;
        tokens[cursor] = null;
        long origOffset = offset;
        offset += step;
        cursor = (cursor + step) % len();
        return new Retired(origOffset, offset, tokens[cursor]);
    }

    /** The first step at or after {@code from} holding an ID, or -1. */
    private int firstPresent(int from) {
        for (int step = from; step < len(); step++) {
            if (cids[(cursor + step) % len()] != null) {
                return step;
            }
        }
        return -1;
    }

    /**
     * Replaces the initial ID, after a Retry or the server's first Initial.
     *
     * @param cid the new ID
     */
    public void updateInitialCid(ConnectionId cid) {
        if (offset != 0) {
            throw new IllegalStateException("the initial connection ID was already retired");
        }
        cids[cursor] = cid;
    }

    /**
     * The ID in use.
     *
     * @return the ID
     */
    public ConnectionId active() {
        return cids[cursor];
    }

    /**
     * The sequence number of the ID in use.
     *
     * @return the sequence number
     */
    public long activeSeq() {
        return offset;
    }

    /**
     * The reset token of the ID in use.
     *
     * @return the token, or null for the handshake ID (whose token, if any, came in the transport
     *     parameters)
     */
    public StatelessResetToken activeResetToken() {
        return tokens[cursor];
    }

    /** Signals that an ID could not be stored; see {@link InsertError}. */
    public static final class CidInsertException extends Exception {

        @java.io.Serial
        private static final long serialVersionUID = 1L;

        /** Why the ID was refused. */
        private final InsertError error;

        /**
         * An exception.
         *
         * @param error why the ID was refused
         */
        public CidInsertException(InsertError error) {
            super(error.name(), null, false, false);
            this.error = error;
        }

        /**
         * Why the ID was refused.
         *
         * @return the error
         */
        public InsertError error() {
            return error;
        }
    }
}
