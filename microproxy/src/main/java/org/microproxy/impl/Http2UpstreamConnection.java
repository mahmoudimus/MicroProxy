package org.microproxy.impl;

import io.github.mahmoudimus.http2.ErrorCode;
import io.github.mahmoudimus.http2.FlowController;
import io.github.mahmoudimus.http2.Frame;
import io.github.mahmoudimus.http2.FrameReader;
import io.github.mahmoudimus.http2.HeaderField;
import io.github.mahmoudimus.http2.HeaderListSizeException;
import io.github.mahmoudimus.http2.HpackDecoder;
import io.github.mahmoudimus.http2.Http2Exception;
import io.github.mahmoudimus.http2.Http2Headers;
import io.github.mahmoudimus.http2.Http2Settings;
import io.github.mahmoudimus.http2.ResponseHeaders;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.lang.System.Logger.Level;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Condition;
import org.microproxy.FullFlowContext;
import org.microproxy.http.DefaultHttpContent;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.DefaultLastHttpContent;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.http.LastHttpContent;

/**
 * The client side of an HTTP/2 connection to an origin server (RFC 9113), over a TLS connection
 * whose handshake negotiated {@code h2}. It carries the exchanges of any number of client streams
 * and client connections at once, one stream each, up to the server's
 * SETTINGS_MAX_CONCURRENT_STREAMS; {@link Http2Origins} hands out its streams ({@link
 * Http2UpstreamStream}).
 *
 * <p>Threads and locks (writing and send flow control are {@link Http2Endpoint}'s):
 *
 * <ul>
 *   <li>A virtual thread of the connection's own reads frames ({@link #readFrames}) and hands them
 *       to streams. The frame reader and HPACK decoder are its alone.
 *   <li>Exchanges write their requests from their own threads, under {@link #writeLock}. A
 *       stream gets its id as its HEADERS are written, so ids reach the server in increasing
 *       order: {@link #stateLock} is taken briefly under {@link #writeLock} to register it, the
 *       one place both are held. {@link #writeLock} is never taken under {@link #stateLock}.
 *   <li>{@link #stateLock} guards the streams, their buffered response data, the windows and the
 *       count of streams reserved against the server's limit. Exchange threads wait on each
 *       stream's condition for response heads and data.
 *   <li>A shared timer closes the connection once it has had no streams for the idle timeout, or
 *       when a write has stalled for that long.
 * </ul>
 *
 * <p>Flow control: response data is buffered per stream, never more than the stream's window,
 * which is credited back only as the exchange reads the data, so a slow client stops its server
 * stream rather than making the proxy buffer. The connection's window is credited back as data
 * arrives, so one slow stream cannot hold up the others; what the connection buffers is bounded
 * by the windows of its streams.
 *
 * <p>Failures: a GOAWAY from the server stops new streams, and fails the streams it did not
 * process ({@link Unprocessed}), which the exchange retries elsewhere when it can. A stream the
 * server resets fails its exchange (a 502, or a reset client stream once the response started);
 * so do all open streams when the connection fails.
 */
final class Http2UpstreamConnection extends Http2Endpoint {

    private static final System.Logger LOG = System.getLogger(Http2UpstreamConnection.class.getName());

    /** Streams recently reset by the proxy, whose late frames are ignored rather than errors. */
    private static final int RECENTLY_CLOSED = 1024;

    /** The request was never processed by the server (RFC 9113 section 8.7): it may be sent again. */
    static final class Unprocessed extends IOException {
        Unprocessed(String message) {
            super(message);
        }
    }

    /** The server connection the HTTP/2 connection runs over: its socket, pool slot and trackers. */
    final ServerConnection carrier;
    /** The key {@link Http2Origins} keeps the connection under. */
    final String key;
    /** The client connection the connection is private to, or null if it is shared. */
    final Object owner;
    private final Http2Origins origins;
    private final int maxHeaderListSize;
    private final AtomicBoolean closing = new AtomicBoolean();

    // The reading thread's.
    private FrameReader reader;
    private HpackDecoder decoder;
    private CountingInput countedIn;

    // Guarded by writeLock.
    private CountingOutput countedOut;
    private long countedOutReported;

    // Guarded by stateLock.
    private final Map<Integer, StreamState> streams = new HashMap<>();
    private final Map<Integer, Boolean> recentlyClosed = new LinkedHashMap<>(64, 0.75f, false) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Integer, Boolean> eldest) {
            return size() > RECENTLY_CLOSED;
        }
    };
    private int nextStreamId = 1;
    /** Streams reserved or open, counted against the server's SETTINGS_MAX_CONCURRENT_STREAMS. */
    private int reserved;
    /** GOAWAY received (or the connection is closing): no new streams. */
    private boolean goingAway;
    /** Received bytes not yet credited back to the connection's receive window. */
    private int pendingConnectionCredit;

    private volatile long lastActiveNanos = System.nanoTime();
    private ScheduledFuture<?> watchdog;

    /** One stream's state, shared by the exchange's thread and the reading thread. */
    final class StreamState extends Http2Endpoint.Stream {
        /** Signalled when a response head, data, trailers or a reset arrive. */
        final Condition changed = stateLock.newCondition();
        final boolean headRequest;
        final String logPrefix;
        /** The exchange's server side, for the bytes trackers count. */
        volatile FullFlowContext flowContext;

        // Guarded by stateLock.
        final ArrayDeque<HttpResponse> heads = new ArrayDeque<>();
        boolean finalHead;
        final ArrayDeque<byte[]> inbound = new ArrayDeque<>();
        int headOffset;
        long buffered;
        long received;
        long declaredLength = -1;
        boolean bodyless;
        /** Bytes read (or padding received) and not yet credited back to the stream's window. */
        int unacked;
        /** END_STREAM received: the response is complete. */
        boolean remoteClosed;
        /** END_STREAM sent: the request is complete. */
        boolean localClosed;
        HttpHeaders trailers;
        /** Counted in {@link #reserved} until the stream closes or is given up. */
        boolean holdsSlot = true;

        StreamState(boolean headRequest, String logPrefix, FullFlowContext flowContext) {
            this.headRequest = headRequest;
            this.logPrefix = logPrefix;
            this.flowContext = flowContext;
        }

        Http2UpstreamConnection connection() {
            return Http2UpstreamConnection.this;
        }

        /** Marks the stream reset; holds stateLock. */
        void markReset(IOException cause) {
            reset = true;
            resetCause = cause;
            changed.signalAll();
        }

        @Override
        IOException failure() {
            IOException cause = resetCause;
            if (cause instanceof Unprocessed u) return new Unprocessed(u.getMessage());
            return new IOException(cause != null ? cause.getMessage() : "stream " + id + " reset", cause);
        }
    }

    Http2UpstreamConnection(DefaultHttpProxyServer server, Http2Origins origins, ServerConnection carrier, String key,
            Object owner) {
        // The larger receive window applies at once: it only lets the server send more sooner.
        super(server, "[h2 " + carrier.hostAndPort + "] ",
                new FlowController(server.http2Options.initialWindowSize(), Http2Settings.DEFAULT_INITIAL_WINDOW_SIZE));
        this.origins = origins;
        this.carrier = carrier;
        this.key = key;
        this.owner = owner;
        this.maxHeaderListSize = options.maxHeaderListSize() > 0 ? options.maxHeaderListSize()
                : server.limits.maxHeaderSize() + server.limits.maxInitialLineLength();
    }

    @Override
    String peer() {
        return "server";
    }

    @Override
    void writeFailed() {
        close(new IOException("writing to the server failed"));
    }

    // ---------------------------------------------------------------------------------------
    // The connection
    // ---------------------------------------------------------------------------------------

    /**
     * Sends the connection preface and SETTINGS, reads the server's SETTINGS (so its limits are
     * known before the first stream), then starts reading frames on a thread of its own.
     */
    void start() throws IOException {
        Socket socket = carrier.socket;
        // Raw socket streams, throttled like the carrier's; the carrier's own reader and writer,
        // which nothing has used yet, are left alone. Bytes are counted per stream, by frame.
        InputStream is = new BufferedInputStream(server.readLimiter.wrap(socket.getInputStream()), 16_384);
        countedIn = new CountingInput(is);
        countedOut = new CountingOutput(new BufferedOutputStream(server.writeLimiter.wrap(socket.getOutputStream()), 16_384));
        reader = new FrameReader(countedIn);
        int maxBlock = Math.max(FrameReader.DEFAULT_MAX_HEADER_BLOCK_SIZE, maxHeaderListSize + 4096);
        reader.setMaxHeaderBlockSize(maxBlock);
        decoder = new HpackDecoder();
        decoder.setMaxHeaderListSize(maxHeaderListSize);
        decoder.setMaxStringLength(maxBlock * 2);
        startWriting(countedOut);
        Http2Settings ours = Http2Settings.builder()
                .enablePush(false)
                .initialWindowSize(options.initialWindowSize())
                .maxHeaderListSize(maxHeaderListSize)
                .build();
        int connectionIncrement = options.connectionWindowSize() - Http2Settings.DEFAULT_INITIAL_WINDOW_SIZE;
        stateLock.lock();
        try {
            if (connectionIncrement > 0) flow.onWindowUpdateSent(0, connectionIncrement);
        } finally {
            stateLock.unlock();
        }
        try {
            write(null, () -> {
                writer.writeClientPreface();
                writer.writeSettings(ours);
                if (connectionIncrement > 0) writer.writeWindowUpdate(0, connectionIncrement);
            }, true);
            int idle = server.idleTimeoutMillis();
            socket.setSoTimeout(idle > 0 ? idle : (int) options.settingsAckTimeout().toMillis());
            Frame first = reader.readFrame();
            if (!(first instanceof Frame.Settings settings) || settings.ack()) {
                throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, "the server preface must be SETTINGS");
            }
            countRead(first);
            applySettings(settings);
            socket.setSoTimeout(0);
        } catch (IOException | RuntimeException e) {
            if (e instanceof Http2Exception h2) writeGoAway(0, h2.errorCode(), h2.getMessage());
            close(e instanceof IOException io ? io : new IOException(e));
            throw e;
        }
        LOG.log(Level.DEBUG, logPrefix + "HTTP/2 to the server (ALPN h2), at most "
                + describe(peerSettings.maxConcurrentStreams()) + " streams");
        long tick = tickMillis();
        watchdog = TIMERS.scheduleWithFixedDelay(this::tick, tick, tick, TimeUnit.MILLISECONDS);
        Thread.ofVirtual().name(server.name + "-h2-upstream-" + carrier.hostAndPort).start(this::run);
    }

    private static String describe(long limit) {
        return limit == Http2Settings.UNLIMITED ? "unlimited" : Long.toString(limit);
    }

    private void run() {
        IOException failure = null;
        try {
            readFrames();
        } catch (Http2Exception e) {
            LOG.log(Level.DEBUG, logPrefix + "HTTP/2 " + e.getMessage());
            writeGoAway(0, e.errorCode(), e.getMessage());
            failure = e;
        } catch (IOException e) {
            if (!closed) LOG.log(Level.DEBUG, logPrefix + "HTTP/2 connection to the server failed: " + e);
            failure = e;
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, logPrefix + "unexpected error on the HTTP/2 connection to the server", e);
            failure = new IOException(e);
        } finally {
            close(failure != null ? failure : new EOFException("the server closed the HTTP/2 connection"));
        }
    }

    private void readFrames() throws IOException {
        while (true) {
            Frame frame;
            try {
                frame = reader.readFrame();
            } catch (Http2Exception e) {
                if (e.isConnectionError()) throw e;
                resetStream(e.streamId(), e.errorCode(), e);
                continue;
            }
            if (frame == null) return;
            countRead(frame);
            try {
                onFrame(frame);
            } catch (Http2Exception e) {
                if (e.isConnectionError()) throw e;
                resetStream(e.streamId(), e.errorCode(), e);
            }
        }
    }

    private void onFrame(Frame frame) throws IOException {
        switch (frame) {
            case Frame.Headers h -> onHeaders(h);
            case Frame.Data d -> onData(d);
            case Frame.Settings s -> {
                if (!s.ack()) applySettings(s);
            }
            case Frame.Ping p -> answerPing(p);
            case Frame.WindowUpdate w -> onWindowUpdate(w);
            case Frame.RstStream r -> onRstStream(r);
            case Frame.GoAway g -> onGoAway(g);
            case Frame.Priority p -> {
                // deprecated; ignored
            }
            case Frame.PushPromise p ->
                    throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, "PUSH_PROMISE with push disabled");
            case Frame.Continuation c -> throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, "stray CONTINUATION");
            case Frame.Unknown u -> {
                // Extension frames are ignored (RFC 9113 section 5.5).
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Frames from the server
    // ---------------------------------------------------------------------------------------

    private void onHeaders(Frame.Headers h) throws IOException {
        int id = h.streamId();
        // Decoded first, whatever becomes of the stream, to keep HPACK in step.
        List<HeaderField> fields = null;
        HeaderListSizeException tooLarge = null;
        try {
            fields = decoder.decode(id, h.fieldBlock());
        } catch (HeaderListSizeException e) {
            tooLarge = e;
        }
        StreamState s;
        boolean trailers;
        stateLock.lock();
        try {
            s = known(id, "HEADERS");
            if (s == null) return;
            if (s.remoteClosed) throw Http2Exception.streamError(id, ErrorCode.STREAM_CLOSED, "HEADERS after END_STREAM");
            trailers = s.finalHead;
        } finally {
            stateLock.unlock();
        }
        if (tooLarge != null) throw tooLarge;
        if (trailers) {
            if (!h.endStream()) throw Http2Exception.streamError(id, ErrorCode.PROTOCOL_ERROR, "trailers without END_STREAM");
            HttpHeaders t = new HttpHeaders();
            for (HeaderField f : Http2Headers.validateTrailers(id, fields)) t.add(f.name(), f.value());
            stateLock.lock();
            try {
                if (s.reset) return;
                if (!s.bodyless) Http2Headers.checkContentLength(id, s.declaredLength, s.received, true);
                s.trailers = t;
                s.remoteClosed = true;
                s.changed.signalAll();
                closeIfDone(s);
            } finally {
                stateLock.unlock();
            }
            return;
        }
        ResponseHeaders head = Http2Headers.toResponse(id, fields);
        int status = head.status();
        if (head.isInformational()) {
            if (status == 101) throw Http2Exception.streamError(id, ErrorCode.PROTOCOL_ERROR, "101 in HTTP/2");
            if (h.endStream()) throw Http2Exception.streamError(id, ErrorCode.PROTOCOL_ERROR, "interim response with END_STREAM");
        }
        stateLock.lock();
        try {
            if (s.reset) return;
            boolean bodyless = s.headRequest || status == 204 || status == 304;
            s.heads.addLast(toHttp1(head, h.endStream(), bodyless));
            if (!head.isInformational()) {
                s.finalHead = true;
                s.bodyless = bodyless;
                s.declaredLength = head.contentLength();
                if (h.endStream()) {
                    if (!bodyless) Http2Headers.checkContentLength(id, s.declaredLength, 0, true);
                    s.remoteClosed = true;
                }
            }
            s.changed.signalAll();
            closeIfDone(s);
        } finally {
            stateLock.unlock();
        }
    }

    /**
     * The HTTP/1-style response the exchange logic relays: version HTTP/2.0, and, when the server
     * gave no {@code content-length}, a chunked body (with trailers, if any) or an empty one.
     */
    private static HttpResponse toHttp1(ResponseHeaders head, boolean endStream, boolean bodyless) {
        HttpHeaders headers = new HttpHeaders();
        for (HeaderField f : head.fields()) headers.add(f.name(), f.value());
        if (!bodyless && !head.isInformational() && head.contentLength() < 0) {
            if (endStream) {
                headers.set(HttpHeaderNames.CONTENT_LENGTH, "0");
            } else {
                headers.set(HttpHeaderNames.TRANSFER_ENCODING, "chunked");
            }
        }
        return new DefaultHttpResponse(HttpVersion.HTTP_2_0, HttpResponseStatus.valueOf(head.status()), headers);
    }

    private void onData(Frame.Data d) throws IOException {
        int id = d.streamId();
        int length = d.flowControlledLength();
        byte[] data = d.data();
        int credit;
        Http2Exception streamError = null;
        stateLock.lock();
        try {
            if ((id & 1) == 0 || id >= nextStreamId) {
                throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, "DATA on idle stream " + id);
            }
            // The connection's window is credited back as data arrives, whatever becomes of it.
            pendingConnectionCredit += length;
            try {
                flow.onDataReceived(id, length);
                buffer(id, d, data, length);
            } catch (Http2Exception e) {
                if (e.isConnectionError()) throw e;
                streamError = e;
            }
            credit = takeConnectionCredit();
        } finally {
            stateLock.unlock();
        }
        sendWindowUpdates(0, 0, credit);
        if (streamError != null) throw streamError;
    }

    /** Hands a DATA frame's data to its stream. Holds stateLock. */
    private void buffer(int id, Frame.Data d, byte[] data, int length) throws Http2Exception {
        StreamState s = streams.get(id);
        if (s == null || s.reset) {
            if (s == null && !recentlyClosed.containsKey(id)) {
                throw Http2Exception.streamError(id, ErrorCode.STREAM_CLOSED, "DATA on closed stream " + id);
            }
            return;
        }
        if (!s.finalHead) throw Http2Exception.streamError(id, ErrorCode.PROTOCOL_ERROR, "DATA before the response head");
        if (s.remoteClosed) throw Http2Exception.streamError(id, ErrorCode.STREAM_CLOSED, "DATA after END_STREAM");
        if (!s.bodyless) Http2Headers.checkContentLength(id, s.declaredLength, s.received + data.length, d.endStream());
        // Padding is never read: it is credited back with the data.
        s.unacked += length - data.length;
        s.received += data.length;
        if (data.length > 0 && !s.bodyless) {
            s.inbound.addLast(data);
            s.buffered += data.length;
        } else {
            s.unacked += data.length;
        }
        if (d.endStream()) s.remoteClosed = true;
        s.changed.signalAll();
        closeIfDone(s);
    }

    private void onWindowUpdate(Frame.WindowUpdate update) throws IOException {
        int id = update.streamId();
        stateLock.lock();
        try {
            if (id != 0 && ((id & 1) == 0 || id >= nextStreamId)) {
                throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, "WINDOW_UPDATE on idle stream " + id);
            }
            flow.onWindowUpdateReceived(id, update.increment());
            windowOpened.signalAll();
        } finally {
            stateLock.unlock();
        }
    }

    private void onRstStream(Frame.RstStream rst) throws IOException {
        int id = rst.streamId();
        StreamState s;
        stateLock.lock();
        try {
            if ((id & 1) == 0 || id >= nextStreamId) {
                throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, "RST_STREAM on idle stream " + id);
            }
            s = streams.get(id);
            if (s == null || s.reset) return;
            s.rstWritten = true;
            // REFUSED_STREAM: not processed at all, so it may be retried (RFC 9113 section 8.7).
            IOException cause = rst.error() == ErrorCode.REFUSED_STREAM
                    ? new Unprocessed("the server refused stream " + id)
                    : new IOException("the server reset stream " + id + " (" + rst.error() + ")");
            s.markReset(cause);
            forget(s);
            windowOpened.signalAll();
        } finally {
            stateLock.unlock();
        }
        LOG.log(Level.DEBUG, s.logPrefix + "server reset stream " + id + " (" + rst.error() + ")");
    }

    private void onGoAway(Frame.GoAway goAway) {
        int last = goAway.lastStreamId();
        int unprocessed = 0;
        boolean idle;
        stateLock.lock();
        try {
            goingAway = true;
            for (StreamState s : List.copyOf(streams.values())) {
                if (s.id > last && !s.reset) {
                    // Never processed: the exchange may retry it on another connection.
                    s.rstWritten = true;
                    s.markReset(new Unprocessed("the server sent GOAWAY before processing stream " + s.id));
                    forget(s);
                    unprocessed++;
                }
            }
            idle = reserved == 0;
            windowOpened.signalAll();
        } finally {
            stateLock.unlock();
        }
        LOG.log(Level.DEBUG, logPrefix + "server sent GOAWAY (" + goAway.error() + ", last stream " + last + ")"
                + (unprocessed > 0 ? "; " + unprocessed + " streams to retry" : ""));
        origins.remove(this);
        if (idle) close(new IOException("the server sent GOAWAY"));
    }

    /** The stream {@code id} refers to; null for one recently closed (its frame is ignored). Holds stateLock. */
    private StreamState known(int id, String frame) throws Http2Exception {
        if ((id & 1) == 0) {
            throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, frame + " on stream " + id + ", which the server cannot open");
        }
        if (id >= nextStreamId) throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, frame + " on idle stream " + id);
        StreamState s = streams.get(id);
        if (s == null && !recentlyClosed.containsKey(id)) {
            throw Http2Exception.connectionError(ErrorCode.STREAM_CLOSED, frame + " on closed stream " + id);
        }
        return s == null || s.reset ? null : s;
    }

    /** Resets stream {@code id} for a stream error in what the server sent, failing its exchange. */
    private void resetStream(int id, ErrorCode code, IOException cause) {
        StreamState s;
        stateLock.lock();
        try {
            s = streams.get(id);
            recentlyClosed.put(id, Boolean.TRUE);
            if (s != null) {
                if (s.reset) return;
                s.markReset(new IOException("invalid response from the server: " + cause.getMessage(), cause));
                forget(s);
                windowOpened.signalAll();
            }
        } finally {
            stateLock.unlock();
        }
        LOG.log(Level.DEBUG, logPrefix + "resetting stream " + id + ": " + cause.getMessage());
        writeReset(s, id, code);
    }

    // ---------------------------------------------------------------------------------------
    // Streams
    // ---------------------------------------------------------------------------------------

    /** Whether new streams can still be started here. */
    boolean usable() {
        stateLock.lock();
        try {
            return !goingAway && !closed;
        } finally {
            stateLock.unlock();
        }
    }

    /**
     * Reserves room for one more stream within the server's SETTINGS_MAX_CONCURRENT_STREAMS; null
     * if there is none, or the connection takes no new streams.
     */
    StreamState reserve(boolean headRequest, String logPrefix, FullFlowContext flowContext) {
        stateLock.lock();
        try {
            if (goingAway || closed || reserved >= peerSettings.maxConcurrentStreams()) return null;
            reserved++;
            lastActiveNanos = System.nanoTime();
            return new StreamState(headRequest, logPrefix, flowContext);
        } finally {
            stateLock.unlock();
        }
    }

    /**
     * Starts stream {@code s} with its request head. The stream gets its id here, under {@link
     * #writeLock}, so ids reach the server in order.
     *
     * @throws Unprocessed if the connection can take no new stream: nothing was sent
     */
    void open(StreamState s, List<HeaderField> fields, boolean endStream) throws IOException {
        writeLock.lock();
        try {
            if (writesFailed || closed) throw new Unprocessed("the HTTP/2 connection to the server closed");
            stateLock.lock();
            try {
                if (s.reset) throw s.failure();
                if (goingAway || closed || nextStreamId < 0) {
                    goingAway = true;
                    throw new Unprocessed("the HTTP/2 connection to the server takes no new streams");
                }
                s.id = nextStreamId;
                nextStreamId += 2;
                streams.put(s.id, s);
                flow.addStream(s.id);
                s.localClosed = endStream;
            } finally {
                stateLock.unlock();
            }
            write(s, () -> writer.writeHeaders(s.id, encoder.encode(fields), endStream), true);
        } finally {
            writeLock.unlock();
        }
    }

    /** Writes request data for {@code s}; with {@code endStream} the request is complete. */
    void send(StreamState s, byte[] data, int off, int len, boolean endStream, boolean flush) throws IOException {
        writeData(s, data, off, len, endStream, flush);
        if (endStream) localEnded(s);
    }

    /** Writes the request's trailers for {@code s}, which end it. */
    void sendTrailers(StreamState s, List<HeaderField> fields) throws IOException {
        writeHeaders(s, fields, true);
        localEnded(s);
    }

    private void localEnded(StreamState s) {
        stateLock.lock();
        try {
            s.localClosed = true;
            closeIfDone(s);
        } finally {
            stateLock.unlock();
        }
    }

    /**
     * Waits up to {@code nanos} for the next response head (or the stream's end or reset); returns
     * whether there is something to read.
     */
    boolean awaitHead(StreamState s, long nanos) throws IOException {
        stateLock.lock();
        try {
            long remaining = nanos;
            while (s.heads.isEmpty() && !s.reset && !s.remoteClosed) {
                if (remaining <= 0) return false;
                remaining = s.changed.awaitNanos(remaining);
            }
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted waiting for the server");
        } finally {
            stateLock.unlock();
        }
    }

    /** The next response head; heads that arrived before a reset are still returned. */
    HttpResponse takeHead(StreamState s) throws IOException {
        stateLock.lock();
        try {
            HttpResponse head = s.heads.pollFirst();
            if (head != null) return head;
            if (s.reset) throw s.failure();
            throw new EOFException("the server ended stream " + s.id + " without a response");
        } finally {
            stateLock.unlock();
        }
    }

    /**
     * The exchange is done with {@code s}: a stream still open either way is reset ({@code
     * CANCEL}), and its slot is given back.
     */
    void cancel(StreamState s) {
        boolean rst;
        boolean idleAndGoingAway;
        stateLock.lock();
        try {
            rst = s.id != 0 && !s.reset && !(s.localClosed && s.remoteClosed);
            if (!s.reset && (rst || s.id == 0)) s.markReset(new IOException("stream " + s.id + " cancelled"));
            if (s.id != 0) {
                forget(s);
            } else {
                releaseSlot(s);
            }
            s.inbound.clear();
            s.buffered = 0;
            idleAndGoingAway = goingAway && reserved == 0;
            windowOpened.signalAll();
        } finally {
            stateLock.unlock();
        }
        if (rst) writeReset(s, s.id, ErrorCode.CANCEL);
        if (idleAndGoingAway) close(new IOException("no streams left after GOAWAY"));
    }

    /** Closes {@code s} once both sides have ended it. Holds stateLock. */
    private void closeIfDone(StreamState s) {
        if (s.localClosed && s.remoteClosed) forget(s);
    }

    /** The stream is closed: stops tracking it and gives back its slot. Holds stateLock. */
    private void forget(StreamState s) {
        if (streams.remove(s.id, s)) flow.removeStream(s.id);
        recentlyClosed.put(s.id, Boolean.TRUE);
        releaseSlot(s);
    }

    private void releaseSlot(StreamState s) {
        if (s.holdsSlot) {
            s.holdsSlot = false;
            reserved--;
            lastActiveNanos = System.nanoTime();
        }
    }

    /** The exchange read {@code n} bytes of the response body: credits the stream's window back as needed. */
    private void consumed(StreamState s, int n) throws IOException {
        int credit = 0;
        stateLock.lock();
        try {
            s.unacked += n;
            if (!s.remoteClosed && !s.reset && streams.get(s.id) == s && s.unacked >= options.initialWindowSize() / 2) {
                credit = s.unacked;
                s.unacked = 0;
                flow.onWindowUpdateSent(s.id, credit);
            }
        } finally {
            stateLock.unlock();
        }
        sendWindowUpdates(s.id, credit, 0);
    }

    /** Takes the connection credit owed, once it is worth a WINDOW_UPDATE. Holds stateLock. */
    private int takeConnectionCredit() {
        int credit = pendingConnectionCredit;
        if (credit < options.connectionWindowSize() / 2) return 0;
        pendingConnectionCredit = 0;
        try {
            flow.onWindowUpdateSent(0, credit);
        } catch (Http2Exception e) {
            return 0; // cannot happen: the window never exceeds what the proxy granted
        }
        return credit;
    }

    /** The response body of {@code s}: its DATA frames, then its trailers. */
    MessageBody body(StreamState s) {
        return new Body(s);
    }

    private final class Body implements MessageBody {
        private final StreamState s;
        /** The end has been returned to the exchange. */
        private boolean done;

        Body(StreamState s) {
            this.s = s;
        }

        @Override
        public boolean hasBody() {
            stateLock.lock();
            try {
                return !s.bodyless && !(s.remoteClosed && s.inbound.isEmpty() && s.received == 0);
            } finally {
                stateLock.unlock();
            }
        }

        @Override
        public long declaredLength() {
            stateLock.lock();
            try {
                return s.declaredLength;
            } finally {
                stateLock.unlock();
            }
        }

        @Override
        public boolean isDone() {
            stateLock.lock();
            try {
                return done || (s.remoteClosed && s.inbound.isEmpty());
            } finally {
                stateLock.unlock();
            }
        }

        @Override
        public HttpContent next() throws IOException {
            if (done) return null;
            byte[] chunk;
            stateLock.lock();
            try {
                chunk = awaitChunk();
                if (chunk == null) {
                    done = true;
                    HttpHeaders t = s.trailers;
                    return t == null || t.isEmpty() ? LastHttpContent.empty() : new DefaultLastHttpContent(new byte[0], t);
                }
                s.inbound.pollFirst();
                if (s.headOffset > 0) {
                    chunk = Arrays.copyOfRange(chunk, s.headOffset, chunk.length);
                    s.headOffset = 0;
                }
                s.buffered -= chunk.length;
            } finally {
                stateLock.unlock();
            }
            consumed(s, chunk.length);
            return new DefaultHttpContent(chunk);
        }

        @Override
        public int read(byte[] dst, int off, int len) throws IOException {
            if (done) return -1;
            int n;
            stateLock.lock();
            try {
                byte[] chunk = awaitChunk();
                if (chunk == null) {
                    done = true;
                    return -1;
                }
                n = Math.min(len, chunk.length - s.headOffset);
                System.arraycopy(chunk, s.headOffset, dst, off, n);
                s.headOffset += n;
                if (s.headOffset == chunk.length) {
                    s.inbound.pollFirst();
                    s.headOffset = 0;
                }
                s.buffered -= n;
            } finally {
                stateLock.unlock();
            }
            consumed(s, n);
            return n;
        }

        /** The first buffered chunk, waiting for one; null at the end of the body. Holds stateLock. */
        private byte[] awaitChunk() throws IOException {
            int idle = server.idleTimeoutMillis();
            long remaining = idle > 0 ? TimeUnit.MILLISECONDS.toNanos(idle) : Long.MAX_VALUE;
            try {
                while (s.inbound.isEmpty()) {
                    if (s.remoteClosed) return null;
                    if (s.reset) throw s.failure();
                    if (remaining <= 0) {
                        throw new SocketTimeoutException("no response data from the server for " + idle + " ms");
                    }
                    remaining = s.changed.awaitNanos(remaining);
                }
                return s.inbound.peekFirst();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("interrupted reading the response body");
            }
        }

        @Override
        public HttpHeaders trailers() {
            stateLock.lock();
            try {
                return s.trailers != null ? s.trailers : new HttpHeaders();
            } finally {
                stateLock.unlock();
            }
        }

        @Override
        public boolean hasBufferedInput() {
            stateLock.lock();
            try {
                return !s.inbound.isEmpty();
            } finally {
                stateLock.unlock();
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Ending
    // ---------------------------------------------------------------------------------------

    /** Ends the connection politely: GOAWAY, then closes it (open streams fail). */
    void shutdown(String why) {
        if (closed) return;
        writeGoAway(0, ErrorCode.NO_ERROR, why);
        close(new IOException("HTTP/2 connection to the server closed: " + why));
    }

    /**
     * Closes the connection: streams still open fail with {@code cause} (those never started, with
     * {@link Unprocessed}), and the carrier connection closes, which counts it out of any pool.
     */
    void close(IOException cause) {
        if (!closing.compareAndSet(false, true)) return;
        ScheduledFuture<?> w = watchdog;
        if (w != null) w.cancel(false);
        stateLock.lock();
        try {
            closed = true;
            goingAway = true;
            for (StreamState s : streams.values()) {
                if (!s.reset) {
                    s.rstWritten = true;
                    s.markReset(cause instanceof Unprocessed ? cause
                            : new IOException("the HTTP/2 connection to the server failed: " + cause.getMessage(), cause));
                }
                releaseSlot(s);
            }
            streams.clear();
            windowOpened.signalAll();
        } finally {
            stateLock.unlock();
        }
        origins.remove(this);
        carrier.close();
    }

    boolean isClosed() {
        return closed;
    }

    /** Streams reserved or open (for tests). */
    int streamCount() {
        stateLock.lock();
        try {
            return reserved;
        } finally {
            stateLock.unlock();
        }
    }

    // ---------------------------------------------------------------------------------------
    // Timers
    // ---------------------------------------------------------------------------------------

    private long tickMillis() {
        int idle = server.idleTimeoutMillis();
        return idle > 0 ? Math.max(25, Math.min(1000, idle / 4)) : 1000;
    }

    /** Runs on the shared timer: must not block, so anything that writes gets a thread of its own. */
    private void tick() {
        if (closed) return;
        int idle = server.idleTimeoutMillis();
        if (idle <= 0) return;
        long now = System.nanoTime();
        long idleNanos = TimeUnit.MILLISECONDS.toNanos(idle);
        long writeStarted = writeStartedNanos;
        if (writeStarted != 0 && now - writeStarted > idleNanos) {
            LOG.log(Level.DEBUG, logPrefix + "closing: no write progress for " + idle + " ms");
            Thread.ofVirtual().start(() -> close(new SocketTimeoutException("the server stopped reading")));
            return;
        }
        boolean idleNow;
        stateLock.lock();
        try {
            idleNow = reserved == 0 && now - lastActiveNanos > idleNanos;
        } finally {
            stateLock.unlock();
        }
        if (idleNow) {
            LOG.log(Level.DEBUG, logPrefix + "closing the idle HTTP/2 connection to the server");
            origins.remove(this);
            Thread.ofVirtual().start(() -> shutdown("idle"));
        }
    }

    // ---------------------------------------------------------------------------------------
    // Bytes, counted per stream for the trackers
    // ---------------------------------------------------------------------------------------

    private void countRead(Frame frame) {
        long n = countedIn.take();
        if (n <= 0 || server.trackers.isEmpty()) return;
        FullFlowContext ctx = carrier.flowContext;
        if (frame.streamId() != 0) {
            stateLock.lock();
            try {
                StreamState s = streams.get(frame.streamId());
                if (s != null) ctx = s.flowContext;
            } finally {
                stateLock.unlock();
            }
        }
        FullFlowContext context = ctx;
        server.trackers.fire(t -> t.bytesReceivedFromServer(context, (int) n));
    }

    @Override
    void written(Stream s) {
        long total = countedOut.count;
        long n = total - countedOutReported;
        countedOutReported = total;
        if (n <= 0 || server.trackers.isEmpty()) return;
        FullFlowContext ctx = s instanceof StreamState state ? state.flowContext : carrier.flowContext;
        server.trackers.fire(t -> t.bytesSentToServer(ctx, (int) n));
    }

    /** Counts the bytes the frame reader takes, above the buffer, so each frame's bytes are known. */
    private static final class CountingInput extends FilterInputStream {
        private long count;

        CountingInput(InputStream in) {
            super(in);
        }

        @Override
        public int read() throws IOException {
            int b = in.read();
            if (b >= 0) count++;
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = in.read(b, off, len);
            if (n > 0) count += n;
            return n;
        }

        /** The bytes read since the last call. */
        long take() {
            long n = count;
            count = 0;
            return n;
        }
    }

    /** Counts the bytes written, above the buffer. Guarded by writeLock. */
    private static final class CountingOutput extends FilterOutputStream {
        private long count;

        CountingOutput(OutputStream out) {
            super(out);
        }

        @Override
        public void write(int b) throws IOException {
            out.write(b);
            count++;
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            out.write(b, off, len);
            count += len;
        }
    }

    /** For log lines and tests. */
    @Override
    public String toString() {
        return "Http2UpstreamConnection[" + carrier.hostAndPort + ", " + streamCount() + " streams]";
    }

    /** The open streams' ids (for tests). */
    List<Integer> streamIds() {
        stateLock.lock();
        try {
            return new ArrayList<>(streams.keySet());
        } finally {
            stateLock.unlock();
        }
    }
}
