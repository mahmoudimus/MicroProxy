package org.microproxy.impl;

import io.github.mahmoudimus.http3.FieldSectionSizeException;
import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3ErrorCode;
import io.github.mahmoudimus.http3.Http3Exception;
import io.github.mahmoudimus.http3.Http3FrameReader;
import io.github.mahmoudimus.http3.Http3FrameWriter;
import io.github.mahmoudimus.http3.Http3Settings;
import io.github.mahmoudimus.http3.Http3StreamType;
import io.github.mahmoudimus.http3.Http3StreamValidator;
import io.github.mahmoudimus.http3.QpackDecoder;
import io.github.mahmoudimus.http3.QpackEncoder;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicConnectionException;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.QuicStreamException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.lang.System.Logger.Level;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import org.microproxy.Http3Options;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.Http3Frame;

/**
 * What both ends of the proxy's HTTP/3 connections share (RFC 9114, RFC 9204), on a {@link
 * QuicConnection}: the control streams with SETTINGS and GOAWAY, the QPACK encoder and decoder
 * with their streams, the peer's unidirectional streams, and the connection's limits. {@link
 * Http3Connection} serves a client's requests; {@link Http3UpstreamConnection} sends requests to a
 * server. Request streams are each read by an {@link Http3StreamReader} and written by an {@link
 * Http3MessageWriter}.
 *
 * <p>Threads and locks (no {@code synchronized}):
 *
 * <ul>
 *   <li>One thread accepts the peer's streams ({@link #acceptStreams}); each unidirectional stream
 *       of the peer is read on a virtual thread of its own, and each request stream by its reader.
 *   <li>{@link #encoderLock} guards the QPACK encoder and its stream: a field section is encoded
 *       and the instructions it needs are written under one hold, so they reach the peer in
 *       order. {@link #decoderLock} guards the QPACK decoder and the decoder stream; a stream whose
 *       field section waits for the peer's encoder stream waits on its condition.
 *   <li>{@link #stateLock} guards the peer's settings, GOAWAY and the rate limits; {@link
 *       #controlLock} the writing of the control stream.
 * </ul>
 *
 * <p>Flow control and the stream limits are QUIC's: a request stream's bytes are read as its
 * exchange reads them (with at most a small buffer ahead, {@link Http3StreamReader}), so a peer
 * can never send more than the stream's and the connection's QUIC windows ahead.
 */
abstract class Http3Endpoint {

    private static final System.Logger LOG = System.getLogger(Http3Endpoint.class.getName());

    /** The largest frame on a control stream, and of any type other than DATA on a request stream, beyond a field section. */
    static final int MAX_CONTROL_FRAME = 16 * 1024;

    // Events counted against the rate limits.
    static final int UNKNOWN_FRAME = 0;
    static final int UNKNOWN_STREAM = 1;
    static final int RAPID_RESET = 2;
    private static final String[] KINDS = {"unknown or empty frame", "unknown stream", "rapid reset"};

    final DefaultHttpProxyServer server;
    final QuicConnection quic;
    final String logPrefix;
    final Http3Options options;
    /** Runs the frame interceptor; null without one. */
    final Http3Frames frames;
    /** SETTINGS_MAX_FIELD_SECTION_SIZE, the largest decoded field section accepted. */
    final long maxFieldSectionSize;
    /** The largest frame payload read on a request stream: a field section, or a piece of DATA. */
    final int maxFramePayload;
    private final Http3StreamValidator.Role role;
    private final int[] limits;
    private final long rateWindowNanos;

    private final ReentrantLock controlLock = new ReentrantLock();
    private Http3FrameWriter control;
    private long controlStreamId = -1;

    final ReentrantLock encoderLock = new ReentrantLock();
    private final QpackEncoder encoder;
    private OutputStream encoderOut;

    final ReentrantLock decoderLock = new ReentrantLock();
    private final Condition decoderReady = decoderLock.newCondition();
    private final QpackDecoder decoder;
    /** Blocked streams the encoder stream has unblocked, until they resume. Guarded by decoderLock. */
    private final Set<Long> resumable = new HashSet<>();
    private OutputStream decoderOut;

    final ReentrantLock stateLock = new ReentrantLock();
    /** Signalled when the peer's settings or GOAWAY arrive, or the connection ends. */
    final Condition stateChanged = stateLock.newCondition();
    private Http3Settings peerSettings = Http3Settings.DEFAULT;
    private boolean settingsReceived;
    private final Http3StreamValidator.UnidirectionalStreams uniStreams;
    /** The id in the peer's GOAWAY, or -1 before one. Guarded by stateLock. */
    long peerGoAway = -1;
    private final int[] counts = new int[KINDS.length];
    private long rateWindowStart = System.nanoTime();

    volatile boolean closed;
    /** A connection error has closed the connection, once. */
    private final java.util.concurrent.atomic.AtomicBoolean failed = new java.util.concurrent.atomic.AtomicBoolean();

    Http3Endpoint(DefaultHttpProxyServer server, QuicConnection quic, String logPrefix, Http3StreamValidator.Role role) {
        this.server = server;
        this.quic = quic;
        this.logPrefix = logPrefix;
        this.options = server.http3Options;
        this.role = role;
        this.frames = server.frameInterceptor == null ? null : new Http3Frames(server.frameInterceptor);
        this.maxFieldSectionSize = options.maxFieldSectionSize() > 0 ? options.maxFieldSectionSize()
                : server.limits.maxHeaderSize() + server.limits.maxInitialLineLength();
        this.maxFramePayload = (int) Math.min(Integer.MAX_VALUE - 8, Math.max(64 * 1024, maxFieldSectionSize + 4096));
        this.limits = new int[] {options.maxUnknownFrames(), options.maxUnknownStreams(), options.maxRapidResets()};
        this.rateWindowNanos = options.rateWindow().toNanos();
        this.encoder = new QpackEncoder(options.qpackMaxTableCapacity());
        this.decoder = new QpackDecoder(options.qpackMaxTableCapacity(), options.qpackBlockedStreams());
        decoder.setMaxFieldSectionSize(maxFieldSectionSize);
        this.uniStreams = new Http3StreamValidator.UnidirectionalStreams(role);
    }

    /** Frames the proxy receives on this connection travel this way. */
    abstract FrameDirection receivedDirection();

    /** Frames the proxy sends on this connection travel this way. */
    abstract FrameDirection sentDirection();

    /** Who frames of this connection that belong to no exchange belong to. */
    abstract Http3Frames.Origin frameOrigin();

    /** A request stream the peer opened. */
    abstract void onRequestStream(QuicStream stream) throws IOException;

    /** The peer sent GOAWAY with {@code id}: a stream id from a server, a push id from a client. */
    abstract void onGoAway(long id);

    /** The connection ended: wakes everything that waits on it. Subclasses fail their streams. */
    void closed() {
        closed = true;
        decoderLock.lock();
        try {
            decoderReady.signalAll();
        } finally {
            decoderLock.unlock();
        }
        stateLock.lock();
        try {
            stateChanged.signalAll();
        } finally {
            stateLock.unlock();
        }
    }

    // ---------------------------------------------------------------------------------------
    // Starting
    // ---------------------------------------------------------------------------------------

    /**
     * Opens the proxy's control stream, with its SETTINGS, and its QPACK encoder and decoder
     * streams.
     */
    void start() throws IOException {
        QuicStream c = quic.openUnidirectionalStream();
        Http3FrameWriter w = new Http3FrameWriter(c.getOutputStream());
        w.writeStreamType(Http3StreamType.CONTROL);
        Http3Settings.Builder local = Http3Settings.builder()
                .qpackMaxTableCapacity(options.qpackMaxTableCapacity())
                .maxFieldSectionSize(maxFieldSectionSize)
                .qpackBlockedStreams(options.qpackBlockedStreams());
        extensionSettings(local);
        Http3Settings ours = local.build();
        controlLock.lock();
        try {
            control = w;
            controlStreamId = c.id();
            Http3Frame.Settings settings = new Http3Frame.Settings(ours.values());
            for (Http3Frame f : frames == null ? List.<Http3Frame>of(settings)
                    : frames.onControl(settings, sentDirection(), frameOrigin(), c.id())) {
                writeControlFrame(f);
            }
            w.flush();
        } finally {
            controlLock.unlock();
        }
        QuicStream enc = quic.openUnidirectionalStream();
        encoderLock.lock();
        try {
            encoderOut = enc.getOutputStream();
            encoderOut.write(Http3StreamType.encode(Http3StreamType.QPACK_ENCODER));
        } finally {
            encoderLock.unlock();
        }
        QuicStream dec = quic.openUnidirectionalStream();
        decoderLock.lock();
        try {
            decoderOut = dec.getOutputStream();
            decoderOut.write(Http3StreamType.encode(Http3StreamType.QPACK_DECODER));
        } finally {
            decoderLock.unlock();
        }
    }

    /**
     * Adds the settings of the extensions this end supports to its SETTINGS: none by default; a
     * client's connection adds extended CONNECT (RFC 9220) and HTTP Datagrams (RFC 9297).
     */
    void extensionSettings(Http3Settings.Builder settings) {}

    /** Writes one frame of the control stream; holds controlLock. */
    private void writeControlFrame(Http3Frame f) throws IOException {
        switch (f) {
            case Http3Frame.Settings s -> control.writeFrame(new io.github.mahmoudimus.http3.Http3Frame.Settings(s.values()));
            case Http3Frame.GoAway g -> control.writeGoAway(g.id());
            case Http3Frame.MaxPushId m -> control.writeMaxPushId(m.pushId());
            case Http3Frame.CancelPush c -> control.writeCancelPush(c.pushId());
            case Http3Frame.Unknown u -> control.writeFrame(new io.github.mahmoudimus.http3.Http3Frame.Unknown(u.type(), u.payload()));
            default -> throw new IllegalArgumentException(f.typeName() + " on a control stream");
        }
    }

    /** Sends GOAWAY with {@code id} on the control stream. */
    void sendGoAway(long id) throws IOException {
        controlLock.lock();
        try {
            if (control == null) return;
            Http3Frame.GoAway goAway = new Http3Frame.GoAway(id);
            for (Http3Frame f : frames == null ? List.<Http3Frame>of(goAway)
                    : frames.onControl(goAway, sentDirection(), frameOrigin(), controlStreamId)) {
                writeControlFrame(f);
            }
            control.flush();
        } finally {
            controlLock.unlock();
        }
    }

    // ---------------------------------------------------------------------------------------
    // The peer's streams
    // ---------------------------------------------------------------------------------------

    /** Accepts the peer's streams until the connection ends; runs on the calling thread. */
    void acceptStreams() {
        try {
            while (!closed) {
                QuicStream s = quic.acceptStream();
                if (s.isBidirectional()) {
                    onRequestStream(s);
                } else {
                    Thread.ofVirtual().name(server.name + "-h3-uni-" + s.id()).start(() -> readUniStream(s));
                }
            }
        } catch (QuicConnectionException e) {
            if (!closed) LOG.log(Level.DEBUG, logPrefix + "QUIC connection ended: " + e.getMessage());
        } catch (IOException e) {
            if (!closed) LOG.log(Level.DEBUG, logPrefix + "HTTP/3 connection failed: " + e);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, logPrefix + "unexpected error on HTTP/3 connection", e);
            connectionError(Http3ErrorCode.H3_INTERNAL_ERROR, "internal error");
        } finally {
            closed();
        }
    }

    private void readUniStream(QuicStream s) {
        long type = -1;
        try {
            InputStream in = s.getInputStream();
            type = Http3StreamType.read(in);
            if (type < 0) return; // ended before its type: ignored (RFC 9114 section 6.2)
            boolean known;
            stateLock.lock();
            try {
                known = uniStreams.onStream(type);
            } finally {
                stateLock.unlock();
            }
            if (!known) {
                // Unknown and reserved (grease) types are abandoned, within a limit.
                count(UNKNOWN_STREAM);
                s.stopSending(Http3ErrorCode.H3_STREAM_CREATION_ERROR.code());
                return;
            }
            if (type == Http3StreamType.CONTROL) {
                readControl(in, s.id());
            } else if (type == Http3StreamType.QPACK_ENCODER) {
                readEncoderStream(in);
            } else if (type == Http3StreamType.QPACK_DECODER) {
                readDecoderStream(in);
            } else {
                // A push stream: the proxy never sends MAX_PUSH_ID, so no push id is valid.
                throw Http3Exception.connectionError(Http3ErrorCode.H3_ID_ERROR, "a push stream without MAX_PUSH_ID");
            }
            // A critical stream ended.
            uniStreams.onStreamClosed(type);
        } catch (Http3Exception e) {
            if (e.isConnectionError()) {
                connectionError(e.errorCode(), e.getMessage());
            } else {
                LOG.log(Level.DEBUG, logPrefix + "unidirectional stream " + s.id() + ": " + e.getMessage());
            }
        } catch (QuicStreamException e) {
            if (Http3StreamType.isCritical(type)) {
                connectionError(Http3ErrorCode.H3_CLOSED_CRITICAL_STREAM,
                        "the " + Http3StreamType.name(type) + " stream was reset");
            }
        } catch (QuicConnectionException e) {
            // the connection is over; acceptStreams sees it too
        } catch (IOException e) {
            if (!closed) LOG.log(Level.DEBUG, logPrefix + "unidirectional stream " + s.id() + " failed: " + e);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, logPrefix + "unexpected error on unidirectional stream " + s.id(), e);
            connectionError(Http3ErrorCode.H3_INTERNAL_ERROR, "internal error");
        }
    }

    private void readControl(InputStream in, long streamId) throws IOException {
        Http3FrameReader reader = new Http3FrameReader(in);
        reader.setMaxFramePayloadSize(MAX_CONTROL_FRAME);
        Http3StreamValidator rules = Http3StreamValidator.forControlStream(role);
        for (io.github.mahmoudimus.http3.Http3Frame frame; (frame = reader.readFrame()) != null; ) {
            rules.onFrame(frame);
            if (frame instanceof io.github.mahmoudimus.http3.Http3Frame.Unknown) count(UNKNOWN_FRAME);
            Http3Frame original = Http3Frames.toPublic(frame);
            List<Http3Frame> acted = frames == null ? List.of(original)
                    : frames.onControl(original, receivedDirection(), frameOrigin(), streamId);
            for (Http3Frame f : acted) {
                switch (f) {
                    case Http3Frame.Settings s -> applyPeerSettings(Http3Settings.fromFrame(
                            new io.github.mahmoudimus.http3.Http3Frame.Settings(s.values())));
                    case Http3Frame.GoAway g -> peerGoingAway(g.id());
                    default -> {
                        // MAX_PUSH_ID and CANCEL_PUSH: the proxy never pushes; extension frames are ignored.
                    }
                }
            }
        }
    }

    private void applyPeerSettings(Http3Settings settings) {
        encoderLock.lock();
        try {
            encoder.applyPeerSettings(settings);
        } finally {
            encoderLock.unlock();
        }
        stateLock.lock();
        try {
            peerSettings = settings;
            settingsReceived = true;
            stateChanged.signalAll();
        } finally {
            stateLock.unlock();
        }
    }

    private void peerGoingAway(long id) {
        stateLock.lock();
        try {
            peerGoAway = id;
            stateChanged.signalAll();
        } finally {
            stateLock.unlock();
        }
        LOG.log(Level.DEBUG, logPrefix + "peer sent GOAWAY " + id);
        onGoAway(id);
    }

    /** The peer's settings, the defaults until its SETTINGS arrive. */
    Http3Settings peerSettings() {
        stateLock.lock();
        try {
            return peerSettings;
        } finally {
            stateLock.unlock();
        }
    }

    boolean settingsReceived() {
        stateLock.lock();
        try {
            return settingsReceived;
        } finally {
            stateLock.unlock();
        }
    }

    private void readEncoderStream(InputStream in) throws IOException {
        byte[] buffer = new byte[4096];
        for (int n; (n = in.read(buffer)) >= 0; ) {
            if (n == 0) continue;
            decoderLock.lock();
            try {
                List<Long> unblocked = decoder.onEncoderStream(buffer, 0, n);
                if (!unblocked.isEmpty()) {
                    resumable.addAll(unblocked);
                    decoderReady.signalAll();
                }
                flushDecoderStream();
            } finally {
                decoderLock.unlock();
            }
        }
    }

    private void readDecoderStream(InputStream in) throws IOException {
        byte[] buffer = new byte[4096];
        for (int n; (n = in.read(buffer)) >= 0; ) {
            if (n == 0) continue;
            encoderLock.lock();
            try {
                encoder.onDecoderStream(buffer, 0, n);
            } finally {
                encoderLock.unlock();
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // QPACK
    // ---------------------------------------------------------------------------------------

    /**
     * Decodes a field section that arrived on {@code streamId}, waiting (up to the idle timeout)
     * if it needs encoder-stream instructions that have not arrived yet.
     *
     * @throws FieldSectionSizeException if the section is over the limit (a stream error; the
     *     section was still processed, so the connection goes on)
     * @throws Http3Exception for a malformed section (a connection error), or one blocked for too
     *     long (a stream error)
     */
    List<HeaderField> decodeFields(long streamId, byte[] section) throws IOException {
        decoderLock.lock();
        try {
            List<HeaderField> fields;
            try {
                fields = decoder.decode(streamId, section);
            } catch (FieldSectionSizeException e) {
                flushDecoderStream();
                throw e;
            }
            if (fields == null) fields = awaitUnblocked(streamId);
            flushDecoderStream();
            return fields;
        } finally {
            decoderLock.unlock();
        }
    }

    /** Waits for a blocked section to become decodable, and decodes it. Holds decoderLock. */
    private List<HeaderField> awaitUnblocked(long streamId) throws IOException {
        int idle = server.idleTimeoutMillis();
        long remaining = idle > 0 ? TimeUnit.MILLISECONDS.toNanos(idle) : Long.MAX_VALUE;
        try {
            while (!resumable.remove(streamId)) {
                if (closed) throw new IOException("the HTTP/3 connection closed");
                if (remaining <= 0) {
                    decoder.cancelStream(streamId);
                    flushDecoderStream();
                    throw Http3Exception.streamError(streamId, Http3ErrorCode.H3_REQUEST_REJECTED,
                            "field section blocked on the QPACK encoder stream for " + idle + " ms");
                }
                remaining = decoderReady.awaitNanos(remaining);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            decoder.cancelStream(streamId);
            throw new InterruptedIOException("interrupted waiting for the QPACK encoder stream");
        }
        try {
            return decoder.resume(streamId);
        } catch (FieldSectionSizeException e) {
            flushDecoderStream();
            throw e;
        }
    }

    /** A stream ended before its field sections were decoded: tells the peer's encoder (Stream Cancellation). */
    void cancelDecoding(long streamId) {
        decoderLock.lock();
        try {
            resumable.remove(streamId);
            decoder.cancelStream(streamId);
            flushDecoderStream();
        } catch (IOException e) {
            // the connection is failing
        } finally {
            decoderLock.unlock();
        }
    }

    /** Sends the decoder's queued instructions; holds decoderLock. */
    private void flushDecoderStream() throws IOException {
        byte[] bytes = decoder.decoderStreamBytes();
        if (bytes.length > 0 && decoderOut != null) {
            decoderOut.write(bytes);
            decoderOut.flush();
        }
    }

    /**
     * Encodes a field section for {@code streamId}, after writing the encoder-stream instructions
     * it needs, under one hold of {@link #encoderLock}.
     *
     * @throws IOException if the section is larger than the peer accepts, or writing fails
     */
    byte[] encodeFields(long streamId, List<HeaderField> fields) throws IOException {
        encoderLock.lock();
        try {
            byte[] section;
            try {
                section = encoder.encode(streamId, fields);
            } catch (IllegalArgumentException e) {
                throw new IOException("cannot encode the field section: " + e.getMessage(), e);
            }
            byte[] instructions = encoder.encoderStreamBytes();
            if (instructions.length > 0) {
                encoderOut.write(instructions);
                encoderOut.flush();
            }
            return section;
        } finally {
            encoderLock.unlock();
        }
    }

    // ---------------------------------------------------------------------------------------
    // Limits and errors
    // ---------------------------------------------------------------------------------------

    /** Counts an event against its rate limit; over it, the connection ends with H3_EXCESSIVE_LOAD. */
    void count(int kind) throws Http3Exception {
        boolean over;
        stateLock.lock();
        try {
            long now = System.nanoTime();
            if (now - rateWindowStart > rateWindowNanos) {
                Arrays.fill(counts, 0);
                rateWindowStart = now;
            }
            over = ++counts[kind] > limits[kind];
        } finally {
            stateLock.unlock();
        }
        if (over) {
            throw Http3Exception.connectionError(Http3ErrorCode.H3_EXCESSIVE_LOAD, KINDS[kind] + " flood: more than "
                    + limits[kind] + " in " + options.rateWindow().toMillis() + " ms");
        }
    }

    /** Closes the connection with an HTTP/3 error code: CONNECTION_CLOSE, and every stream fails. */
    void connectionError(Http3ErrorCode code, String reason) {
        if (closed || !failed.compareAndSet(false, true)) return;
        LOG.log(Level.DEBUG, logPrefix + "closing the HTTP/3 connection: " + code + " " + reason);
        // Closed with the code before anything sees the connection as closed, so nothing closes
        // it with another code first.
        quic.close(code.code(), reason == null ? "" : reason);
        closed = true;
        closed();
    }

    /** How long reads of streams wait for the peer before they time out, in nanoseconds. */
    long readTimeoutNanos() {
        int idle = server.idleTimeoutMillis();
        return idle > 0 ? TimeUnit.MILLISECONDS.toNanos(idle) : Long.MAX_VALUE;
    }

    /** A timeout as a request stream's read reports it, as an HTTP/1 connection's read does. */
    SocketTimeoutException timedOut(String what) {
        return new SocketTimeoutException("no " + what + " for " + server.idleTimeoutMillis() + " ms");
    }
}
