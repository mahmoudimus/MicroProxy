/*
 * Ported from quinn-proto src/connection/streams/state.rs and src/connection/streams/mod.rs
 * (Streams, SendStream, RecvStream), with the stream frame checks of src/connection/mod.rs
 * (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.VarInt;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.params.TransportParameters;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * The streams of one connection (RFC 9000 sections 2 to 4): opening and accepting streams,
 * stream and connection flow control, the send and receive state machines, RESET_STREAM and
 * STOP_SENDING, priorities, and the control and STREAM frames they produce.
 *
 * <p>The application side ({@link #open}, {@link #accept}, {@link #write}, {@link #finish}, {@link
 * #reset}, {@link #read}, {@link #stop}) never blocks: it reports {@link StreamException.Kind#BLOCKED}
 * and later a {@link StreamEvent} from {@link #poll()} says when to retry. That is what a blocking
 * stream layer waits on.
 *
 * <p>Frames the operations need go into a {@link Retransmits} the caller passes, normally the
 * application data space's pending frames; {@link #writeControlFrames} and {@link
 * #writeStreamFrames} put them into packets.
 *
 * <p><b>Flow control.</b> Credit is issued as quinn does: a stream's MAX_STREAM_DATA moves with
 * what the application reads, to {@code bytes read + stream receive window}, and is sent once it
 * has moved by an eighth of the window; MAX_DATA likewise with the connection receive window;
 * MAX_STREAMS keeps the configured number of remote streams open and is sent once an eighth of
 * them have closed. The windows can be changed at run time; quinn does not auto-tune them, and
 * neither does this port. Writes are limited by the peer's credit and by a local send window of
 * buffered, unacknowledged data.
 *
 * <p><b>Threads.</b> Not thread-safe and takes no locks: one connection owns it and serializes
 * every call, including the blocking stream layer's.
 */
public final class StreamsState {

    /** The largest stream count MAX_STREAMS may carry, 2<sup>60</sup>. */
    public static final long MAX_STREAM_COUNT = 1L << 60;

    /** The number of bytes and whole chunks {@link #writeChunks} took. */
    public record Written(long bytes, int chunks) {}

    private final Side side;
    /** Send halves of open streams and of remote streams the peer may open; null until first used. */
    final Map<StreamId, Send> send = new HashMap<>();
    /** Receive halves, likewise. */
    final Map<StreamId, Recv> recv = new HashMap<>();
    /** The number of local streams opened, per direction. */
    final long[] next = new long[2];
    /** How many local streams the peer allows over the connection's lifetime, per direction. */
    final long[] max = new long[2];
    /** How many remote streams we allow over the connection's lifetime, per direction. */
    final long[] maxRemote = new long[2];
    /** The {@code maxRemote} last sent in MAX_STREAMS. */
    private final long[] sentMaxRemote = new long[2];
    /** Remote streams we allowed that are not fully closed. */
    final long[] allocatedRemoteCount = new long[2];
    /** The number of remote streams to keep open. */
    private final long[] maxConcurrentRemoteCount = new long[2];
    private boolean flowControlAdjusted;
    /** The lowest remote stream index the peer has not opened. */
    final long[] nextRemote = new long[2];
    /** Whether the peer opened streams the application has not been told about. */
    private final boolean[] opened = new boolean[2];
    /** The next remote stream index to report through {@link #accept}. */
    final long[] nextReportedRemote = new long[2];
    /** Streams that may have unacknowledged outgoing data. */
    int sendStreams;
    /** Streams with data to send. */
    final PendingStreamsQueue pending = new PendingStreamsQueue();
    final ArrayDeque<StreamEvent> events = new ArrayDeque<>();
    /** Streams whose writes failed on connection flow control or the send window. */
    final List<StreamId> connectionBlocked = new ArrayList<>();
    /** The peer's connection-level limit (MAX_DATA). */
    long maxData;
    /** The connection receive window. */
    long receiveWindow;
    /** Our connection-level limit on incoming data. */
    long localMaxData;
    /** The MAX_DATA last queued. */
    private long sentMaxData;
    /** The sum of the send streams' offsets. */
    long dataSent;
    /** The sum of the receive streams' highest offsets. */
    long dataRecvd;
    /** Outgoing data held in send buffers, acknowledged or not. */
    long bufferedData;
    /** The bound on {@code bufferedData}; may be below it after being lowered. */
    long sendWindow;
    /** The per-stream receive window. */
    final long streamReceiveWindow;
    private long initialMaxStreamDataUni;
    private long initialMaxStreamDataBidiLocal;
    private long initialMaxStreamDataBidiRemote;
    /** How much a shrunk receive window still has to absorb from future credit. */
    long receiveWindowShrinkDebt;
    /** Whether opening a local stream hit the peer's limit, per direction. */
    final boolean[] streamsBlocked = new boolean[2];
    /** The {@code maxData} a DATA_BLOCKED was last queued for, or -1. */
    long dataBlockedLimit = -1;
    private boolean connectionClosed;

    /**
     * The stream state of a new connection.
     *
     * @param side this endpoint's role
     * @param maxRemoteUni how many unidirectional streams the peer may have open
     * @param maxRemoteBi how many bidirectional streams the peer may have open
     * @param sendWindow the most outgoing data to buffer, in bytes
     * @param receiveWindow the connection receive window, in bytes
     * @param streamReceiveWindow the per-stream receive window, in bytes
     */
    public StreamsState(Side side, long maxRemoteUni, long maxRemoteBi, long sendWindow, long receiveWindow,
            long streamReceiveWindow) {
        this.side = side;
        int bi = Dir.BI.ordinal();
        int uni = Dir.UNI.ordinal();
        maxRemote[bi] = sentMaxRemote[bi] = allocatedRemoteCount[bi] = maxConcurrentRemoteCount[bi] = maxRemoteBi;
        maxRemote[uni] = sentMaxRemote[uni] = allocatedRemoteCount[uni] = maxConcurrentRemoteCount[uni] = maxRemoteUni;
        this.receiveWindow = receiveWindow;
        this.localMaxData = receiveWindow;
        this.sentMaxData = Math.min(receiveWindow, VarInt.MAX);
        this.sendWindow = sendWindow;
        this.streamReceiveWindow = streamReceiveWindow;
    }

    // ---------------------------------------------------------------------------------------
    // Configuration

    /**
     * Applies the peer's transport parameters: initial stream and connection limits.
     *
     * @param params the peer's parameters
     */
    public void setParams(TransportParameters params) {
        initialMaxStreamDataUni = params.initialMaxStreamDataUni();
        initialMaxStreamDataBidiLocal = params.initialMaxStreamDataBidiLocal();
        initialMaxStreamDataBidiRemote = params.initialMaxStreamDataBidiRemote();
        max[Dir.BI.ordinal()] = params.initialMaxStreamsBidi();
        max[Dir.UNI.ordinal()] = params.initialMaxStreamsUni();
        receivedMaxData(params.initialMaxData());
        for (Map.Entry<StreamId, Send> e : send.entrySet()) {
            StreamId id = e.getKey();
            if (id.initiator() != side && id.dir() == Dir.BI && e.getValue() != null) {
                e.getValue().maxData = params.initialMaxStreamDataBidiLocal();
            }
        }
    }

    /** Marks the connection closed: writes are refused from now on. */
    public void onConnectionClosed() {
        connectionClosed = true;
    }

    /** Forgets every local stream after the server rejected 0-RTT. */
    public void zeroRttRejected() {
        for (Dir dir : Dir.values()) {
            for (long i = 0; i < next[dir.ordinal()]; i++) {
                StreamId id = StreamId.of(side, dir, i);
                send.remove(id);
                if (dir == Dir.BI) {
                    recv.remove(id);
                }
            }
            next[dir.ordinal()] = 0;
            if (flowControlAdjusted) {
                sentMaxRemote[dir.ordinal()] = 0; // any MAX_STREAMS sent was lost with 0-RTT
            }
        }
        pending.clear();
        sendStreams = 0;
        dataSent = 0;
        bufferedData = 0;
        connectionBlocked.clear();
        dataBlockedLimit = -1;
    }

    /**
     * Changes how many remote streams of a directionality may be open at once.
     *
     * @param dir the directionality
     * @param count the number of concurrent streams
     */
    public void setMaxConcurrent(Dir dir, long count) {
        flowControlAdjusted = true;
        maxConcurrentRemoteCount[dir.ordinal()] = count;
        ensureRemoteStreams(dir);
    }

    /**
     * How many remote streams of a directionality are allowed and not fully closed.
     *
     * @param dir the directionality
     * @return the count
     */
    public long maxConcurrent(Dir dir) {
        return allocatedRemoteCount[dir.ordinal()];
    }

    /**
     * Changes the send window, the most outgoing data to buffer.
     *
     * @param sendWindow bytes; may be below what is already buffered
     */
    public void setSendWindow(long sendWindow) {
        this.sendWindow = sendWindow;
    }

    /**
     * Changes the connection receive window. A larger window raises the limit at once; a smaller
     * one is absorbed from credit as data is read.
     *
     * @param receiveWindow bytes
     * @return true if the window grew, so a MAX_DATA is worth sending
     */
    public boolean setReceiveWindow(long receiveWindow) {
        boolean expanded = false;
        if (receiveWindow > this.receiveWindow) {
            localMaxData = saturatingAdd(localMaxData, receiveWindow - this.receiveWindow);
            expanded = true;
        } else {
            receiveWindowShrinkDebt = saturatingAdd(receiveWindowShrinkDebt, this.receiveWindow - receiveWindow);
        }
        this.receiveWindow = receiveWindow;
        return expanded;
    }

    // ---------------------------------------------------------------------------------------
    // Opening and accepting

    /**
     * Opens a local stream.
     *
     * @param dir the directionality
     * @return the new stream, or null if the peer's limit is reached (a STREAMS_BLOCKED is then
     *     queued) or the connection is closed
     */
    public StreamId open(Dir dir) {
        if (connectionClosed) {
            return null;
        }
        int d = dir.ordinal();
        if (next[d] >= max[d]) {
            streamsBlocked[d] = true;
            return null;
        }
        next[d]++;
        StreamId id = StreamId.of(side, dir, next[d] - 1);
        insertLocal(id);
        sendStreams++;
        return id;
    }

    /**
     * Accepts a stream the peer opened. Does not change flow control or stream limits.
     *
     * @param dir the directionality
     * @return the next stream not yet accepted, or null if there is none
     */
    public StreamId accept(Dir dir) {
        int d = dir.ordinal();
        if (nextRemote[d] == nextReportedRemote[d]) {
            return null;
        }
        long x = nextReportedRemote[d]++;
        if (dir == Dir.BI) {
            sendStreams++;
        }
        return StreamId.of(side.opposite(), dir, x);
    }

    /**
     * The number of streams that may have unacknowledged outgoing data.
     *
     * @return the count
     */
    public int sendStreams() {
        return sendStreams;
    }

    /**
     * The number of open remote streams, accepted or not, which count against the concurrency limit.
     *
     * @param dir the directionality
     * @return the count
     */
    public long remoteOpenStreams(Dir dir) {
        int d = dir.ordinal();
        return nextRemote[d] - (maxRemote[d] - allocatedRemoteCount[d]);
    }

    // ---------------------------------------------------------------------------------------
    // Sending: the application side

    /**
     * Writes data, copying as much as flow control and the send window accept.
     *
     * @param id the stream
     * @param data the bytes between the position and limit; the position advances past the bytes
     *     taken
     * @param pending where to queue DATA_BLOCKED and STREAM_DATA_BLOCKED
     * @return the number of bytes taken, at least 1 unless {@code data} is empty
     * @throws StreamException {@code BLOCKED} if no byte could be taken, {@code STOPPED} after
     *     STOP_SENDING, {@code CLOSED_STREAM} if the stream is not writable
     */
    public int write(StreamId id, ByteBuffer data, Retransmits pending) throws StreamException {
        return (int) writeSource(id, new Send.CopyingSource(data), pending)[0];
    }

    /**
     * Writes buffers without copying them: the stream keeps views until the data is acknowledged,
     * so their contents must not change. A buffer only partly taken has its position advanced.
     *
     * @param id the stream
     * @param chunks the data
     * @param pending where to queue DATA_BLOCKED and STREAM_DATA_BLOCKED
     * @return the bytes and whole chunks taken
     * @throws StreamException as for {@link #write}
     */
    public Written writeChunks(StreamId id, ByteBuffer[] chunks, Retransmits pending) throws StreamException {
        long[] r = writeSource(id, new Send.ChunksSource(chunks), pending);
        return new Written(r[0], (int) r[1]);
    }

    private long[] writeSource(StreamId id, Send.Source source, Retransmits retransmits) throws StreamException {
        if (connectionClosed) {
            throw new StreamException(StreamException.Kind.BLOCKED);
        }
        long limit = writeLimit();
        Send stream = sendFor(id);
        if (limit == 0) {
            if (!stream.connectionBlocked) {
                stream.connectionBlocked = true;
                connectionBlocked.add(id);
            }
            // Only report blocking on the peer's limit, not on our own send window
            if (dataSent == maxData && dataBlockedLimit != maxData) {
                dataBlockedLimit = maxData;
                retransmits.dataBlocked = true;
            }
            throw new StreamException(StreamException.Kind.BLOCKED);
        }
        boolean wasPending = stream.isPending();
        long[] written;
        try {
            written = stream.write(source, limit);
        } catch (StreamException e) {
            if (e.kind() == StreamException.Kind.BLOCKED && stream.dataBlockedLimit != stream.maxData) {
                stream.dataBlockedLimit = stream.maxData;
                retransmits.streamDataBlocked.add(id);
            }
            throw e;
        }
        dataSent += written[0];
        bufferedData += written[0];
        if (!wasPending) {
            pending.pushPending(id, stream.priority);
        }
        return written;
    }

    /**
     * Whether the peer stopped a stream.
     *
     * @param id the stream
     * @return the STOP_SENDING error code, or -1 if not stopped
     * @throws StreamException {@code CLOSED_STREAM} if the stream's send side is gone
     */
    public long stopped(StreamId id) throws StreamException {
        if (!send.containsKey(id)) {
            throw new StreamException(StreamException.Kind.CLOSED_STREAM);
        }
        Send s = send.get(id);
        return s == null ? -1 : s.stopReason;
    }

    /**
     * Finishes a stream: no more data will be written, and a FIN is queued. {@link
     * StreamEvent.Finished} follows once everything is acknowledged.
     *
     * @param id the stream
     * @throws StreamException {@code STOPPED} after STOP_SENDING, {@code CLOSED_STREAM} if already
     *     finished or reset
     */
    public void finish(StreamId id) throws StreamException {
        Send stream = sendFor(id);
        boolean wasPending = stream.isPending();
        stream.finish();
        if (!wasPending) {
            pending.pushPending(id, stream.priority);
        }
    }

    /**
     * Abandons sending on a stream (RESET_STREAM). Unsent and unacknowledged data is discarded.
     *
     * @param id the stream
     * @param errorCode the application error code
     * @param retransmits where to queue the RESET_STREAM
     * @throws StreamException {@code CLOSED_STREAM} if the stream was already reset or is gone
     */
    public void reset(StreamId id, long errorCode, Retransmits retransmits) throws StreamException {
        Send stream = sendFor(id);
        if (stream.isReset()) {
            throw new StreamException(StreamException.Kind.CLOSED_STREAM);
        }
        // Release the send window held by data that will not be sent; the peer issues new
        // connection credit from the final size in the RESET_STREAM
        bufferedData -= stream.pending.buffered();
        stream.reset();
        retransmits.resetStream.add(new Retransmits.PendingReset(id, errorCode));
    }

    /**
     * Sets a stream's priority; streams with a higher priority send first.
     *
     * @param id the stream
     * @param priority the priority, 0 by default
     * @throws StreamException {@code CLOSED_STREAM} if the stream's send side is gone
     */
    public void setPriority(StreamId id, int priority) throws StreamException {
        sendFor(id).priority = priority;
    }

    /**
     * A stream's priority.
     *
     * @param id the stream
     * @return the priority
     * @throws StreamException {@code CLOSED_STREAM} if the stream's send side is gone
     */
    public int priority(StreamId id) throws StreamException {
        if (!send.containsKey(id)) {
            throw new StreamException(StreamException.Kind.CLOSED_STREAM);
        }
        Send s = send.get(id);
        return s == null ? 0 : s.priority;
    }

    /**
     * The state of a stream's sending part.
     *
     * @param id the stream
     * @return the state, or null if the stream has no sending part or it was released
     */
    public SendState sendState(StreamId id) {
        if (!send.containsKey(id)) {
            return null;
        }
        Send s = send.get(id);
        return s == null ? SendState.READY : s.state;
    }

    // ---------------------------------------------------------------------------------------
    // Receiving: the application side

    /**
     * Starts reading a stream. Call {@link Chunks#next(int)} for data, then {@link
     * Chunks#close()} (or use try-with-resources) to issue the flow control credit for what was read.
     *
     * @param id the stream
     * @param ordered true to read bytes in order; false for chunks in any order, after which ordered
     *     reads are refused
     * @param retransmits where to queue MAX_DATA, MAX_STREAM_DATA and MAX_STREAMS
     * @return the reader
     * @throws StreamException {@code CLOSED_STREAM} if the stream is gone or stopped, {@code
     *     ILLEGAL_ORDERED_READ} for an ordered read after an unordered one
     */
    public Chunks read(StreamId id, boolean ordered, Retransmits retransmits) throws StreamException {
        if (!recv.containsKey(id)) {
            throw new StreamException(StreamException.Kind.CLOSED_STREAM);
        }
        Recv rs = recvFor(id);
        if (rs.stopped) {
            throw new StreamException(StreamException.Kind.CLOSED_STREAM);
        }
        if (!rs.assembler.ensureOrdering(ordered)) {
            throw new StreamException(StreamException.Kind.ILLEGAL_ORDERED_READ);
        }
        return new Chunks(id, ordered, this, rs, retransmits);
    }

    /**
     * Stops receiving a stream (STOP_SENDING). Unread data is discarded and its connection credit
     * returned.
     *
     * @param id the stream
     * @param errorCode the application error code
     * @param retransmits where to queue STOP_SENDING and MAX_DATA
     * @throws StreamException {@code CLOSED_STREAM} if the stream is gone or already stopped
     */
    public void stop(StreamId id, long errorCode, Retransmits retransmits) throws StreamException {
        if (!recv.containsKey(id)) {
            throw new StreamException(StreamException.Kind.CLOSED_STREAM);
        }
        Recv stream = recvFor(id);
        long[] r = stream.stop();
        if (r[1] != 0) {
            retransmits.stopSending.add(new Frame.StopSending(id.value(), errorCode));
        }
        // Stopped streams stay until their final size is known, to account for the data in
        // connection flow control; otherwise they can go now
        if (!stream.finalOffsetUnknown()) {
            recv.remove(id);
            streamRecvFreed(id);
        }
        if (addReadCredits(r[0])) {
            retransmits.maxData = true;
        }
    }

    /**
     * Whether the peer reset a stream. Once a reset is returned the stream is released, and later
     * calls fail with {@code CLOSED_STREAM}.
     *
     * @param id the stream
     * @param retransmits where to queue MAX_STREAMS
     * @return the RESET_STREAM error code, or -1 if the stream was not reset
     * @throws StreamException {@code CLOSED_STREAM} if the stream is gone or stopped
     */
    public long takeReset(StreamId id, Retransmits retransmits) throws StreamException {
        if (!recv.containsKey(id)) {
            throw new StreamException(StreamException.Kind.CLOSED_STREAM);
        }
        Recv s = recv.get(id);
        if (s == null) {
            return -1;
        }
        if (s.stopped) {
            throw new StreamException(StreamException.Kind.CLOSED_STREAM);
        }
        long code = s.resetCode();
        if (code < 0) {
            return -1;
        }
        recv.remove(id);
        streamRecvFreed(id);
        queueMaxStreamId(retransmits);
        return code;
    }

    /**
     * The state of a stream's receiving part.
     *
     * @param id the stream
     * @return the state, or null if the stream has no receiving part or it was released
     */
    public RecvState recvState(StreamId id) {
        if (!recv.containsKey(id)) {
            return null;
        }
        Recv r = recv.get(id);
        return r == null ? RecvState.RECV : r.state();
    }

    // ---------------------------------------------------------------------------------------
    // Frames from the peer

    /**
     * Processes a STREAM frame. The stream keeps a view of the frame's data until it is read, so
     * copy the data out of a reusable packet buffer first.
     *
     * @param frame the frame
     * @param payloadLength the size of the buffer behind the frame's data, for memory accounting
     * @return true if a MAX_DATA should be queued
     * @throws QuicException {@code STREAM_STATE_ERROR} for a send-only or unopened stream, {@code
     *     STREAM_LIMIT_ERROR} beyond the stream limit, {@code FLOW_CONTROL_ERROR} beyond a credit
     *     limit, {@code FINAL_SIZE_ERROR} for a changed or exceeded final size
     */
    public boolean received(Frame.Stream frame, int payloadLength) throws QuicException {
        StreamId id = new StreamId(frame.streamId());
        validateReceiveId(id);
        insertRemote(id);
        if (!recv.containsKey(id)) {
            return false; // a frame for a closed stream
        }
        Recv rs = recvFor(id);
        if (!rs.isReceiving()) {
            return false; // a frame for a reset stream
        }
        ByteBuffer data = frame.data();
        long[] r = rs.ingest(frame.offset(), data, frame.fin(), Math.max(payloadLength, data.remaining()), dataRecvd,
                localMaxData);
        long newBytes = r[0];
        dataRecvd = saturatingAdd(dataRecvd, newBytes);
        if (!rs.stopped) {
            events.addLast(new StreamEvent.Readable(id));
            return false;
        }
        // A stopped stream closes as soon as its FIN arrives
        if (r[1] != 0) {
            recv.remove(id);
            streamRecvFreed(id);
        }
        // Data on stopped streams is not buffered, so its credit is returned at once
        return addReadCredits(newBytes);
    }

    /**
     * Processes a RESET_STREAM frame.
     *
     * @param frame the frame
     * @return true if a MAX_DATA should be queued
     * @throws QuicException as for {@link #received}
     */
    public boolean receivedReset(Frame.ResetStream frame) throws QuicException {
        StreamId id = new StreamId(frame.streamId());
        long finalOffset = frame.finalSize();
        validateReceiveId(id);
        insertRemote(id);
        if (!recv.containsKey(id)) {
            return false; // the stream is closed
        }
        Recv rs = recvFor(id);
        if (!rs.reset(frame.errorCode(), finalOffset, dataRecvd, localMaxData)) {
            return false; // redundant
        }
        long bytesRead = rs.assembler.bytesRead();
        boolean stopped = rs.stopped;
        long end = rs.end;
        // Stopped streams already returned credit up to their highest offset
        long credited = stopped ? end : bytesRead;
        if (stopped) {
            recv.remove(id); // stopped streams go as soon as they are reset
            streamRecvFreed(id);
        } else {
            events.addLast(new StreamEvent.Readable(id));
        }
        if (credited != finalOffset) {
            dataRecvd = saturatingAdd(dataRecvd, finalOffset - end);
            return addReadCredits(finalOffset - credited);
        }
        return false;
    }

    /**
     * Processes a STOP_SENDING frame.
     *
     * @param frame the frame
     * @throws QuicException {@code STREAM_STATE_ERROR} for a receive-only or unopened stream, {@code
     *     STREAM_LIMIT_ERROR} beyond the stream limit
     */
    public void receivedStopSending(Frame.StopSending frame) throws QuicException {
        StreamId id = new StreamId(frame.streamId());
        if (id.initiator() != side) {
            if (id.dir() == Dir.UNI) {
                throw new QuicException(QuicException.STREAM_STATE_ERROR, "STOP_SENDING on receive-only stream");
            }
            if (id.index() >= maxRemote[id.dir().ordinal()]) {
                throw new QuicException(QuicException.STREAM_LIMIT_ERROR, "STOP_SENDING beyond the stream limit");
            }
        } else if (isLocalUnopened(id)) {
            throw new QuicException(QuicException.STREAM_STATE_ERROR, "STOP_SENDING on unopened stream");
        }
        insertRemote(id);
        if (!send.containsKey(id)) {
            return;
        }
        Send stream = sendSlot(id);
        if (stream.tryStop(frame.errorCode())) {
            events.addLast(new StreamEvent.Stopped(id, frame.errorCode()));
        }
    }

    /**
     * Processes a STREAM_DATA_BLOCKED frame, which needs no response.
     *
     * @param frame the frame
     * @throws QuicException {@code STREAM_STATE_ERROR} for a stream this endpoint only sends on
     */
    public void receivedStreamDataBlocked(Frame.StreamDataBlocked frame) throws QuicException {
        StreamId id = new StreamId(frame.streamId());
        if (id.initiator() == side && id.dir() == Dir.UNI) {
            throw new QuicException(QuicException.STREAM_STATE_ERROR, "STREAM_DATA_BLOCKED on send-only stream");
        }
    }

    /**
     * Processes a STREAMS_BLOCKED frame, which needs no response.
     *
     * @param frame the frame
     * @throws QuicException {@code FRAME_ENCODING_ERROR} for a limit above 2<sup>60</sup>
     */
    public void receivedStreamsBlocked(Frame.StreamsBlocked frame) throws QuicException {
        if (frame.limit() > MAX_STREAM_COUNT) {
            throw new QuicException(QuicException.FRAME_ENCODING_ERROR, "unrepresentable stream limit");
        }
    }

    /**
     * Processes a MAX_STREAMS frame.
     *
     * @param dir the directionality
     * @param count the new limit
     * @throws QuicException {@code FRAME_ENCODING_ERROR} for a limit above 2<sup>60</sup>
     */
    public void receivedMaxStreams(Dir dir, long count) throws QuicException {
        if (count > MAX_STREAM_COUNT) {
            throw new QuicException(QuicException.FRAME_ENCODING_ERROR, "unrepresentable stream limit");
        }
        int d = dir.ordinal();
        if (count > max[d]) {
            max[d] = count;
            streamsBlocked[d] = false;
            events.addLast(new StreamEvent.Available(dir));
        }
    }

    /**
     * Processes a MAX_DATA frame; smaller limits than the current one are ignored.
     *
     * @param n the new connection-level limit
     */
    public void receivedMaxData(long n) {
        maxData = Math.max(maxData, n);
    }

    /**
     * Processes a MAX_STREAM_DATA frame.
     *
     * @param id the stream
     * @param offset the new limit
     * @throws QuicException {@code STREAM_STATE_ERROR} for a receive-only or unopened stream, {@code
     *     STREAM_LIMIT_ERROR} beyond the stream limit
     */
    public void receivedMaxStreamData(StreamId id, long offset) throws QuicException {
        if (id.initiator() != side && id.dir() == Dir.UNI) {
            throw new QuicException(QuicException.STREAM_STATE_ERROR, "MAX_STREAM_DATA on receive-only stream");
        }
        if (id.dir() == Dir.BI) {
            validateReceiveId(id); // don't implicitly open more streams than permitted
        }
        insertRemote(id);
        long writeLimit = writeLimit();
        if (send.containsKey(id)) {
            Send ss = sendSlot(id);
            if (ss.increaseMaxData(offset)) {
                if (writeLimit > 0) {
                    events.addLast(new StreamEvent.Writable(id));
                } else if (!ss.connectionBlocked) {
                    // Still blocked by the connection: wait on that list
                    ss.connectionBlocked = true;
                    connectionBlocked.add(id);
                }
            }
        } else if (id.initiator() == side && isLocalUnopened(id)) {
            throw new QuicException(QuicException.STREAM_STATE_ERROR, "MAX_STREAM_DATA on unopened stream");
        }
    }

    // ---------------------------------------------------------------------------------------
    // Acknowledgement and loss of sent frames

    /**
     * Releases a stream whose RESET_STREAM was acknowledged.
     *
     * @param id the stream
     */
    public void resetAcked(StreamId id) {
        Send s = send.get(id);
        if (s != null && s.isReset()) {
            s.state = SendState.RESET_RECVD;
            send.remove(id);
            streamFreed(id, true);
        }
    }

    /**
     * Records that a STREAM frame was acknowledged; may release the stream and report {@link
     * StreamEvent.Finished}.
     *
     * @param frame what the frame carried
     */
    public void receivedAckOf(StreamMeta frame) {
        Send stream = send.get(frame.id());
        if (stream == null || stream.isReset()) {
            return; // reset streams were accounted for at the reset
        }
        long buffered = stream.pending.buffered();
        boolean finished = stream.ack(frame);
        bufferedData -= buffered - stream.pending.buffered();
        if (!finished) {
            return;
        }
        stream.state = SendState.DATA_RECVD;
        send.remove(frame.id());
        streamFreed(frame.id(), true);
        events.addLast(new StreamEvent.Finished(frame.id()));
    }

    /**
     * Queues a lost STREAM frame's data to be sent again.
     *
     * @param frame what the frame carried
     */
    public void retransmit(StreamMeta frame) {
        Send stream = send.get(frame.id());
        if (stream == null || stream.isReset()) {
            return;
        }
        if (!stream.isPending()) {
            pending.pushPending(frame.id(), stream.priority);
        }
        stream.finPending |= frame.fin();
        stream.pending.retransmit(frame.start(), frame.end());
    }

    /** Queues everything written on local streams to be sent again after 0-RTT was rejected. */
    public void retransmitAllForZeroRtt() {
        for (Dir dir : Dir.values()) {
            for (long index = 0; index < next[dir.ordinal()]; index++) {
                StreamId id = StreamId.of(Side.CLIENT, dir, index);
                Send stream = send.get(id);
                if (stream == null || (stream.pending.isFullyAcked() && !stream.finPending)) {
                    continue; // nothing was sent
                }
                if (!stream.isPending()) {
                    pending.pushPending(id, stream.priority);
                }
                stream.pending.retransmitAllForZeroRtt();
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Flow control and events

    /**
     * How much the application may write now: the peer's remaining connection credit, limited by
     * the send window.
     *
     * @return bytes
     */
    public long writeLimit() {
        return Math.min(maxData - dataSent, Math.max(0, sendWindow - bufferedData));
    }

    /**
     * The next stream event.
     *
     * @return the event, or null if there is none
     */
    public StreamEvent poll() {
        for (Dir dir : Dir.values()) {
            if (opened[dir.ordinal()]) {
                opened[dir.ordinal()] = false;
                return new StreamEvent.Opened(dir);
            }
        }
        if (writeLimit() > 0) {
            while (!connectionBlocked.isEmpty()) {
                StreamId id = connectionBlocked.remove(connectionBlocked.size() - 1);
                Send stream = send.get(id);
                if (stream == null) {
                    continue;
                }
                stream.connectionBlocked = false;
                // Report only streams that can still be written, even to find an error
                if (stream.isWritable() && stream.maxData > stream.offset()) {
                    return new StreamEvent.Writable(id);
                }
            }
        }
        return events.pollFirst();
    }

    /**
     * Queues MAX_STREAMS if enough remote streams closed: more than an eighth of the concurrency
     * limit.
     *
     * @param retransmits where to queue the frames
     * @return true if any were queued
     */
    public boolean queueMaxStreamId(Retransmits retransmits) {
        boolean queued = false;
        for (Dir dir : Dir.values()) {
            int d = dir.ordinal();
            long diff = maxRemote[d] - sentMaxRemote[d];
            if (diff > maxConcurrentRemoteCount[d] / 8) {
                retransmits.maxStreamId[d] = true;
                queued = true;
            }
        }
        return queued;
    }

    /**
     * Whether any stream has data to send, ignoring control frames.
     *
     * @return true if {@link #writeStreamFrames} would write a frame
     */
    public boolean canSendStreamData() {
        // Reset streams may linger in the queue but never produce STREAM frames
        for (PendingStreamsQueue.Entry e : pending.entries()) {
            Send s = send.get(e.id());
            if (s != null && !s.isReset()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether a MAX_STREAM_DATA for a stream would still be useful.
     *
     * @param id the stream
     * @return true if the stream is still receiving with an unknown final size
     */
    public boolean canSendFlowControl(StreamId id) {
        Recv r = recv.get(id);
        return r != null && r.canSendFlowControl();
    }

    /**
     * Whether a queued DATA_BLOCKED is still accurate.
     *
     * @return true if the peer has not raised MAX_DATA since it was queued
     */
    public boolean canSendDataBlocked() {
        return dataBlockedLimit == maxData;
    }

    /**
     * The limit to put in a STREAM_DATA_BLOCKED for a stream.
     *
     * @param id the stream
     * @return the limit, or -1 if the frame is no longer accurate: the stream is not writable, was
     *     stopped, or the peer raised its limit
     */
    public long streamDataBlockedLimit(StreamId id) {
        Send stream = send.get(id);
        if (stream == null || stream.dataBlockedLimit < 0) {
            return -1;
        }
        return stream.isWritable() && stream.stopReason < 0 && stream.dataBlockedLimit == stream.maxData
                ? stream.dataBlockedLimit
                : -1;
    }

    /**
     * Whether a local stream has never been opened.
     *
     * @param id a locally initiated stream
     * @return true if its index is beyond those opened
     */
    public boolean isLocalUnopened(StreamId id) {
        return id.index() >= next[id.dir().ordinal()];
    }

    // ---------------------------------------------------------------------------------------
    // Packet assembly

    /**
     * Writes pending stream control frames: RESET_STREAM, STOP_SENDING, MAX_DATA,
     * MAX_STREAM_DATA, MAX_STREAMS, STREAMS_BLOCKED, DATA_BLOCKED and STREAM_DATA_BLOCKED, as many as
     * fit. Each one written is recorded in {@code sent}, to be queued again if the packet is lost.
     *
     * @param buf the packet payload, written at its position
     * @param retransmits the pending frames; written ones are removed
     * @param sent the frames this packet carries
     * @param maxSize the position the frames must stay below
     */
    public void writeControlFrames(ByteBuffer buf, Retransmits retransmits, Retransmits sent, int maxSize) {
        // RESET_STREAM
        while (buf.position() + 25 < maxSize && !retransmits.resetStream.isEmpty()) {
            Retransmits.PendingReset r = retransmits.resetStream.remove(retransmits.resetStream.size() - 1);
            Send stream = send.get(r.id());
            if (stream == null) {
                continue;
            }
            sent.resetStream.add(r);
            new Frame.ResetStream(r.id().value(), r.errorCode(), stream.offset()).encode(buf);
        }
        // STOP_SENDING, even for streams already released: the peer may still be sending
        while (buf.position() + 17 < maxSize && !retransmits.stopSending.isEmpty()) {
            Frame.StopSending f = retransmits.stopSending.remove(retransmits.stopSending.size() - 1);
            f.encode(buf);
            sent.stopSending.add(f);
        }
        // MAX_DATA
        if (retransmits.maxData && buf.position() + 9 < maxSize) {
            retransmits.maxData = false;
            long max = Math.min(localMaxData, VarInt.MAX); // localMaxData may exceed a varint
            if (max > sentMaxData) {
                sentMaxData = max;
            }
            sent.maxData = true;
            new Frame.MaxData(max).encode(buf);
        }
        // MAX_STREAM_DATA
        for (Iterator<StreamId> it = retransmits.maxStreamData.iterator(); it.hasNext() && buf.position() + 17 < maxSize; ) {
            StreamId id = it.next();
            it.remove();
            Recv rs = recv.get(id);
            if (rs == null || !rs.canSendFlowControl()) {
                continue;
            }
            sent.maxStreamData.add(id);
            long max = rs.maxStreamData(streamReceiveWindow)[0];
            rs.recordSentMaxStreamData(max);
            new Frame.MaxStreamData(id.value(), max).encode(buf);
        }
        // MAX_STREAMS
        for (Dir dir : Dir.values()) {
            int d = dir.ordinal();
            if (!retransmits.maxStreamId[d] || buf.position() + 9 >= maxSize) {
                continue;
            }
            retransmits.maxStreamId[d] = false;
            sent.maxStreamId[d] = true;
            sentMaxRemote[d] = maxRemote[d];
            new Frame.MaxStreams(dir == Dir.BI, maxRemote[d]).encode(buf);
        }
        // STREAMS_BLOCKED
        for (Dir dir : Dir.values()) {
            int d = dir.ordinal();
            if (streamsBlocked[d]) {
                retransmits.streamsBlocked[d] = true;
                streamsBlocked[d] = false;
            }
            if (!retransmits.streamsBlocked[d] || buf.position() + 9 >= maxSize) {
                continue;
            }
            retransmits.streamsBlocked[d] = false;
            sent.streamsBlocked[d] = true;
            new Frame.StreamsBlocked(dir == Dir.BI, max[d]).encode(buf);
        }
        // DATA_BLOCKED, unless the peer raised the limit since it was queued
        if (retransmits.dataBlocked && buf.position() + 9 < maxSize) {
            retransmits.dataBlocked = false;
            if (canSendDataBlocked()) {
                sent.dataBlocked = true;
                new Frame.DataBlocked(maxData).encode(buf);
            }
        }
        // STREAM_DATA_BLOCKED
        for (Iterator<StreamId> it = retransmits.streamDataBlocked.iterator();
                it.hasNext() && buf.position() + 17 < maxSize; ) {
            StreamId id = it.next();
            it.remove();
            long limit = streamDataBlockedLimit(id);
            if (limit < 0) {
                continue;
            }
            sent.streamDataBlocked.add(id);
            Send s = send.get(id);
            if (s.state == SendState.READY) {
                s.state = SendState.SEND;
            }
            new Frame.StreamDataBlocked(id.value(), limit).encode(buf);
        }
    }

    /**
     * Writes STREAM frames from the pending streams, highest priority first, as many as fit.
     *
     * @param buf the packet payload, written at its position
     * @param maxBufSize the position the frames must stay below
     * @param fair true to requeue a partly written stream behind others of its priority, false to
     *     finish it first
     * @return what each frame carried, to keep with the sent packet
     */
    public List<StreamMeta> writeStreamFrames(ByteBuffer buf, int maxBufSize, boolean fair) {
        List<StreamMeta> frames = new ArrayList<>();
        while (buf.position() + StreamMeta.SIZE_BOUND < maxBufSize) {
            PendingStreamsQueue.Entry entry = pending.pop();
            if (entry == null) {
                break;
            }
            StreamId id = entry.id();
            Send stream = send.get(id);
            if (stream == null || stream.isReset()) {
                // Released after an acknowledged reset, or reset: no STREAM frames
                continue;
            }
            int room = maxBufSize - buf.position() - 1 - VarInt.size(id.value());
            SendBuffer.Transmit t = stream.pending.pollTransmit(room);
            boolean fin = t.end() == stream.pending.offset() && stream.finished;
            if (fin) {
                stream.finPending = false;
            }
            if (stream.isPending()) {
                // Requeue, possibly with a new priority
                if (fair) {
                    pending.pushPending(id, stream.priority);
                } else {
                    pending.reinsertPending(id, stream.priority);
                }
            }
            if (fin) {
                stream.state = SendState.DATA_SENT;
            } else if (stream.state == SendState.READY) {
                stream.state = SendState.SEND;
            }
            StreamMeta meta = new StreamMeta(id, t.start(), t.end(), fin);
            meta.encodeHeader(t.encodeLength(), buf);
            // The range may be stored in pieces
            long start = t.start();
            while (start != t.end()) {
                ByteBuffer data = stream.pending.get(start, t.end());
                start += data.remaining();
                buf.put(data);
            }
            frames.add(meta);
        }
        return frames;
    }

    // ---------------------------------------------------------------------------------------
    // Internals

    /** The initial MAX_STREAM_DATA the peer gave for a stream. */
    long maxSendData(StreamId id) {
        boolean remote = side != id.initiator();
        if (id.dir() == Dir.UNI) {
            return initialMaxStreamDataUni;
        }
        // The parameters are named from the peer's point of view
        return remote ? initialMaxStreamDataBidiLocal : initialMaxStreamDataBidiRemote;
    }

    /** The send half, created on first use, or CLOSED_STREAM if the stream is gone. */
    private Send sendFor(StreamId id) throws StreamException {
        if (!send.containsKey(id)) {
            throw new StreamException(StreamException.Kind.CLOSED_STREAM);
        }
        return sendSlot(id);
    }

    /** The send half of a tracked stream, created on first use. */
    private Send sendSlot(StreamId id) {
        Send s = send.get(id);
        if (s == null) {
            s = new Send(maxSendData(id));
            send.put(id, s);
        }
        return s;
    }

    /** The receive half, created on first use; the stream must be tracked. */
    Recv recvFor(StreamId id) {
        Recv r = recv.get(id);
        if (r == null) {
            r = new Recv(streamReceiveWindow);
            recv.put(id, r);
        }
        return r;
    }

    /** Ensures a full window of remote streams may be open, raising the limit as streams close. */
    private void ensureRemoteStreams(Dir dir) {
        int d = dir.ordinal();
        long newCount = Math.max(0, maxConcurrentRemoteCount[d] - allocatedRemoteCount[d]);
        allocatedRemoteCount[d] += newCount;
        maxRemote[d] += newCount;
    }

    /** Checks the peer may send on a stream. */
    private void validateReceiveId(StreamId id) throws QuicException {
        if (side == id.initiator()) {
            if (id.dir() == Dir.UNI) {
                throw new QuicException(QuicException.STREAM_STATE_ERROR, "illegal operation on send-only stream");
            }
            if (id.index() >= next[Dir.BI.ordinal()]) {
                throw new QuicException(QuicException.STREAM_STATE_ERROR, "operation on unopened stream");
            }
        } else if (id.index() >= maxRemote[id.dir().ordinal()]) {
            throw new QuicException(QuicException.STREAM_LIMIT_ERROR, "stream " + id + " beyond the stream limit");
        }
    }

    private void insertLocal(StreamId id) {
        send.put(id, null);
        if (id.dir() == Dir.BI) {
            recv.put(id, null);
        }
    }

    /** Tracks remote streams up to and including {@code id}, which a frame for it implicitly opens. */
    private void insertRemote(StreamId id) {
        int d = id.dir().ordinal();
        // STOP_SENDING is not limit-checked by validateReceiveId
        if (id.initiator() == side || id.index() >= maxRemote[d] || id.index() < nextRemote[d]) {
            return;
        }
        for (long i = nextRemote[d]; i <= id.index(); i++) {
            StreamId tid = StreamId.of(side.opposite(), id.dir(), i);
            recv.put(tid, null);
            if (id.dir() == Dir.BI) {
                send.put(tid, null);
            }
        }
        nextRemote[d] = id.index() + 1;
        opened[d] = true;
    }

    /**
     * Adds connection credit for data read or discarded.
     *
     * @return true if MAX_DATA moved by an eighth of the window and should be sent
     */
    boolean addReadCredits(long credits) {
        if (credits > receiveWindowShrinkDebt) {
            long net = credits - receiveWindowShrinkDebt;
            localMaxData = saturatingAdd(localMaxData, net);
            receiveWindowShrinkDebt = 0;
        } else {
            receiveWindowShrinkDebt -= credits;
        }
        if (localMaxData > VarInt.MAX) {
            return false;
        }
        long diff = localMaxData - sentMaxData;
        return diff >= receiveWindow / 8;
    }

    /** Updates counters when one half of a stream is released. */
    void streamFreed(StreamId id, boolean sendHalf) {
        if (id.initiator() != side) {
            boolean fullyFree = id.dir() == Dir.UNI || (sendHalf ? !recv.containsKey(id) : !send.containsKey(id));
            if (fullyFree) {
                allocatedRemoteCount[id.dir().ordinal()]--;
                ensureRemoteStreams(id.dir());
            }
        }
        if (sendHalf) {
            sendStreams--;
        }
    }

    void streamRecvFreed(StreamId id) {
        streamFreed(id, false);
    }

    private static long saturatingAdd(long a, long b) {
        long r = a + b;
        return ((a ^ r) & (b ^ r)) < 0 ? Long.MAX_VALUE : r;
    }
}
