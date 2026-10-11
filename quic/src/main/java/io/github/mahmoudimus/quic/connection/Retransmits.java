/*
 * Ported from quinn-proto src/connection/spaces.rs (Retransmits, ThinRetransmits) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.frame.Frame;
import java.net.InetSocketAddress;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Control frames waiting to be sent in one packet number space, and, attached to a {@link
 * SentPacket}, the control frames that packet carried, to queue again if it is lost.
 *
 * <p>Most entries record only that a frame is needed; its current value is computed when the
 * packet is built, so a retransmission carries fresh limits (RFC 9000 section 13.3). Stream data
 * itself is not here: it stays in the streams' {@link SendBuffer}s.
 *
 * <p>This is a plain mutable holder of public fields. <b>Threads:</b> not thread-safe; owned by one
 * connection.
 */
public final class Retransmits {

    /**
     * A RESET_STREAM to send.
     *
     * @param id the stream
     * @param errorCode the application error code
     */
    public record PendingReset(StreamId id, long errorCode) {}

    /** The most RETIRE_CONNECTION_ID frames that may wait to be sent: ten times quinn's CID window of 5. */
    static final long MAX_PENDING_RETIRED_CIDS = 50;

    /** Whether a MAX_DATA is needed. */
    public boolean maxData;
    /** Whether a DATA_BLOCKED is needed. */
    public boolean dataBlocked;
    /** Whether a MAX_STREAMS is needed, indexed by {@link Dir#ordinal()}. */
    public final boolean[] maxStreamId = new boolean[2];
    /** Whether a STREAMS_BLOCKED is needed, indexed by {@link Dir#ordinal()}. */
    public final boolean[] streamsBlocked = new boolean[2];
    /** RESET_STREAM frames to send. */
    public final List<PendingReset> resetStream = new ArrayList<>();
    /** STOP_SENDING frames to send. */
    public final List<Frame.StopSending> stopSending = new ArrayList<>();
    /** Streams that need a MAX_STREAM_DATA. */
    public final Set<StreamId> maxStreamData = new LinkedHashSet<>();
    /** Streams that need a STREAM_DATA_BLOCKED. */
    public final Set<StreamId> streamDataBlocked = new LinkedHashSet<>();
    /** CRYPTO frames to send, retransmissions first. */
    public final ArrayDeque<Frame.Crypto> crypto = new ArrayDeque<>();
    /** NEW_CONNECTION_ID frames to send. */
    public final List<IssuedCid> newCids = new ArrayList<>();
    /** Sequence numbers to retire in RETIRE_CONNECTION_ID frames. */
    public final List<Long> retireCids = new ArrayList<>();
    /** Whether an ACK_FREQUENCY is needed. */
    public boolean ackFrequency;
    /** Whether a HANDSHAKE_DONE is needed. */
    public boolean handshakeDone;
    /**
     * One entry per NEW_TOKEN frame to send, holding the path's remote address: a lost token is
     * replaced by a fresh one, and only for the path it was meant for.
     */
    public final List<InetSocketAddress> newTokens = new ArrayList<>();

    /** Nothing pending. */
    public Retransmits() {}

    /**
     * Queues RETIRE_CONNECTION_ID frames for a range of sequence numbers.
     *
     * @param start the first sequence number
     * @param end one past the last
     * @throws QuicException {@code CONNECTION_ID_LIMIT_ERROR} if too many would be queued, which
     *     only a peer that keeps retiring connection IDs causes
     */
    public void retireCids(long start, long end) throws QuicException {
        long num = Math.max(0, end - start);
        if (retireCids.size() + num > MAX_PENDING_RETIRED_CIDS) {
            throw new QuicException(QuicException.CONNECTION_ID_LIMIT_ERROR, "queued too many retired CIDs");
        }
        for (long seq = start; seq < end; seq++) {
            retireCids.add(seq);
        }
    }

    /**
     * Whether nothing needs sending. Stream entries count only while still meaningful: a
     * MAX_STREAM_DATA for a stream that no longer takes data, or a blocked frame whose limit the peer
     * has since raised, does not.
     *
     * @param streams the connection's streams
     * @return true if no frame is needed
     */
    public boolean isEmpty(StreamsState streams) {
        if (maxData || (dataBlocked && streams.canSendDataBlocked())) {
            return false;
        }
        if (maxStreamId[0] || maxStreamId[1] || streamsBlocked[0] || streamsBlocked[1]) {
            return false;
        }
        if (!resetStream.isEmpty() || !stopSending.isEmpty()) {
            return false;
        }
        for (StreamId id : maxStreamData) {
            if (streams.canSendFlowControl(id)) {
                return false;
            }
        }
        for (StreamId id : streamDataBlocked) {
            if (streams.streamDataBlockedLimit(id) >= 0) {
                return false;
            }
        }
        return crypto.isEmpty() && newCids.isEmpty() && retireCids.isEmpty() && !ackFrequency && !handshakeDone
                && newTokens.isEmpty();
    }

    /**
     * Merges another set of pending frames into this one. CRYPTO frames from {@code other} go first,
     * which reduces head-of-line blocking when they are retransmissions.
     *
     * @param other the frames to add; not changed
     */
    public void merge(Retransmits other) {
        maxData |= other.maxData;
        dataBlocked |= other.dataBlocked;
        for (int dir = 0; dir < 2; dir++) {
            maxStreamId[dir] |= other.maxStreamId[dir];
            streamsBlocked[dir] |= other.streamsBlocked[dir];
        }
        resetStream.addAll(other.resetStream);
        stopSending.addAll(other.stopSending);
        maxStreamData.addAll(other.maxStreamData);
        streamDataBlocked.addAll(other.streamDataBlocked);
        for (Iterator<Frame.Crypto> it = other.crypto.descendingIterator(); it.hasNext(); ) {
            crypto.addFirst(it.next());
        }
        newCids.addAll(other.newCids);
        retireCids.addAll(other.retireCids);
        ackFrequency |= other.ackFrequency;
        handshakeDone |= other.handshakeDone;
        newTokens.addAll(other.newTokens);
    }
}
