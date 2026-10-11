/*
 * Ported from quinn-proto src/connection/cid_state.rs (CidState), with the issuance of
 * src/endpoint.rs (send_new_identifiers) and src/transport_parameters.rs (issue_cids_limit)
 * (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.StatelessResetToken;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The connection IDs this endpoint issued to its peer (RFC 9000 section 5.1.1): sequence numbers,
 * stateless reset tokens derived from a static key, retirement by the peer, and periodic rotation
 * through {@code retire_prior_to} when IDs have a lifetime.
 *
 * <p>No more than {@code min(peer's active_connection_id_limit, 8)} IDs are active at once.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class LocalCidState {

    /** The most connection IDs issued to a peer at once, as in quinn. */
    public static final long LOC_CID_COUNT = 8;

    /**
     * The outcome of a RETIRE_CONNECTION_ID.
     *
     * @param retired the retired ID, to stop routing to; null if it was already retired
     * @param issueReplacement whether a new ID may be issued to replace it
     */
    public record Retirement(ConnectionId retired, boolean issueReplacement) {}

    /** A batch of IDs that expire together: the highest sequence number and when. */
    private record CidTimestamp(long sequence, long timestamp) {}

    private final ConnectionIdGenerator generator;
    private final byte[] resetKey;
    private final ArrayDeque<CidTimestamp> retireTimestamps = new ArrayDeque<>();
    /** IDs issued and not retired, by sequence number. */
    private final TreeMap<Long, ConnectionId> active = new TreeMap<>();
    /** The number of IDs issued. */
    private long issued;
    /** All IDs below this were retired by the peer at our request. */
    private long prevRetireSeq;
    /** The Retire Prior To value to send. */
    private long retireSeq;

    /**
     * The state after the handshake, during which {@code handshakeCids} were used: the first with
     * sequence number 0, then for example a server's preferred address with 1.
     *
     * @param generator generates new IDs
     * @param resetKey the static key reset tokens are derived from (see {@link
     *     StatelessResetToken#derive}), at least 32 random bytes
     * @param now the current time
     * @param handshakeCids the IDs already in use, in sequence order
     */
    public LocalCidState(ConnectionIdGenerator generator, byte[] resetKey, long now, ConnectionId... handshakeCids) {
        this.generator = generator;
        this.resetKey = resetKey.clone();
        for (ConnectionId cid : handshakeCids) {
            active.put(issued, cid);
            trackLifetime(issued, now);
            issued++;
        }
    }

    /**
     * How many IDs to issue after the handshake: the peer's limit (at most {@value #LOC_CID_COUNT})
     * less those already in use.
     *
     * @param peerActiveConnectionIdLimit the peer's {@code active_connection_id_limit}
     * @return the count, zero for zero-length IDs
     */
    public long initialIssueCount(long peerActiveConnectionIdLimit) {
        if (generator.cidLength() == 0) {
            return 0;
        }
        return Math.max(0, issueLimit(peerActiveConnectionIdLimit) - active.size());
    }

    /**
     * The most IDs to keep active for a peer.
     *
     * @param peerActiveConnectionIdLimit the peer's {@code active_connection_id_limit}
     * @return {@code min(limit, 8)}
     */
    public static long issueLimit(long peerActiveConnectionIdLimit) {
        return Math.min(peerActiveConnectionIdLimit, LOC_CID_COUNT);
    }

    /**
     * Issues new IDs, to send in NEW_CONNECTION_ID frames with {@link #retirePriorTo()}.
     *
     * @param now the current time
     * @param count how many
     * @return the IDs, with sequence numbers and reset tokens
     */
    public List<IssuedCid> issue(long now, long count) {
        if (count <= 0 || generator.cidLength() == 0) {
            return List.of();
        }
        List<IssuedCid> ids = new ArrayList<>();
        for (long i = 0; i < count; i++) {
            ConnectionId cid = generator.generateCid();
            long sequence = issued++;
            active.put(sequence, cid);
            ids.add(new IssuedCid(sequence, cid, StatelessResetToken.derive(resetKey, cid)));
        }
        trackLifetime(ids.get(ids.size() - 1).sequence(), now);
        return ids;
    }

    /**
     * The reset token of one of our IDs.
     *
     * @param cid the ID
     * @return the token, HMAC-derived from the static key
     */
    public StatelessResetToken resetToken(ConnectionId cid) {
        return StatelessResetToken.derive(resetKey, cid);
    }

    /**
     * Processes a RETIRE_CONNECTION_ID frame.
     *
     * @param sequence the retired sequence number
     * @param packetDestinationId the Destination Connection ID of the packet that carried the frame
     * @param peerActiveConnectionIdLimit the peer's {@code active_connection_id_limit}
     * @return the retired ID and whether to issue a replacement
     * @throws QuicException {@code PROTOCOL_VIOLATION} when IDs are zero-length, for a sequence
     *     number never issued, or for the ID the packet itself was sent to (RFC 9000 section 19.16)
     */
    public Retirement onRetireConnectionId(long sequence, ConnectionId packetDestinationId,
            long peerActiveConnectionIdLimit) throws QuicException {
        if (generator.cidLength() == 0) {
            throw new QuicException(QuicException.PROTOCOL_VIOLATION, "RETIRE_CONNECTION_ID when CIDs aren't in use");
        }
        if (sequence >= issued) {
            throw new QuicException(QuicException.PROTOCOL_VIOLATION, "RETIRE_CONNECTION_ID for unissued sequence number");
        }
        ConnectionId cid = active.get(sequence);
        if (cid != null && cid.equals(packetDestinationId)) {
            throw new QuicException(QuicException.PROTOCOL_VIOLATION,
                    "RETIRE_CONNECTION_ID for the connection ID of its own packet");
        }
        active.remove(sequence);
        // Check the limit here, or a peer that already retired the ID could exceed it after a
        // retire_prior_to crossed with this frame
        boolean replace = cid != null && issueLimit(peerActiveConnectionIdLimit) > active.size();
        return new Retirement(cid, replace);
    }

    /**
     * When the next batch of IDs reaches the end of its lifetime.
     *
     * @return the time, or {@link NanoClock#NONE}
     */
    public long nextTimeout() {
        CidTimestamp first = retireTimestamps.peekFirst();
        return first == null ? NanoClock.NONE : first.timestamp();
    }

    /**
     * Handles the expiry of {@link Timer#PUSH_NEW_CID}: advances Retire Prior To past the expired
     * batch, unless the peer has not yet retired the IDs the previous value asked for (RFC 9000
     * section 5.1.2).
     *
     * @return true if an ID must be issued now to carry the new Retire Prior To
     */
    public boolean onCidTimeout() {
        boolean unretired = !active.subMap(prevRetireSeq, retireSeq).isEmpty();
        long current = retireSeq;
        CidTimestamp expired = retireTimestamps.pollFirst();
        if (!unretired) {
            prevRetireSeq = retireSeq;
            if (expired != null) {
                retireSeq = expired.sequence() + 1;
            }
        }
        // Push a new ID only if expired IDs remain active; otherwise the peer already retired
        // them, and another ID could exceed its limit
        return !active.subMap(current, retireSeq).isEmpty();
    }

    /**
     * The Retire Prior To value for NEW_CONNECTION_ID frames.
     *
     * @return the sequence number below which the peer must retire IDs
     */
    public long retirePriorTo() {
        return retireSeq;
    }

    /**
     * The length of the IDs, to parse short headers.
     *
     * @return bytes
     */
    public int cidLength() {
        return generator.cidLength();
    }

    /**
     * The IDs issued and not retired, by sequence number.
     *
     * @return an unmodifiable view
     */
    public Map<Long, ConnectionId> activeCids() {
        return Collections.unmodifiableMap(active);
    }

    /**
     * The number of IDs issued so far.
     *
     * @return the count
     */
    public long issuedCount() {
        return issued;
    }

    private void trackLifetime(long sequence, long now) {
        long lifetime = generator.cidLifetime();
        if (lifetime < 0) {
            return;
        }
        long expireAt;
        try {
            expireAt = Math.addExact(now, lifetime);
        } catch (ArithmeticException e) {
            return;
        }
        CidTimestamp last = retireTimestamps.peekLast();
        if (last != null && last.timestamp() == expireAt) {
            // Same expiry as the last batch: extend it
            retireTimestamps.pollLast();
            retireTimestamps.addLast(new CidTimestamp(sequence, expireAt));
            return;
        }
        retireTimestamps.addLast(new CidTimestamp(sequence, expireAt));
    }

    /** The active sequence numbers, for tests. */
    /**
     * Asks the peer to retire every ID below a sequence number, as a test hook (quinn's {@code
     * assign_retire_seq}).
     *
     * @return how many new IDs to issue in their place
     */
    long assignRetireSeq(long v) {
        long n = v - retireSeq;
        retireSeq = v;
        return n;
    }

    Collection<Long> activeSequences() {
        return active.keySet();
    }
}
