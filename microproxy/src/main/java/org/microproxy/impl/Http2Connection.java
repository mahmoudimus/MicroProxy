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
import io.github.mahmoudimus.http2.RequestHeaders;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.lang.System.Logger.Level;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/**
 * The server side of an HTTP/2 connection from a client (RFC 9113): over an intercepted TLS
 * session that negotiated {@code h2}, or over a plain connection that started with the connection
 * preface ({@code h2c} with prior knowledge), whose requests are proxy requests for any target.
 * Each stream's request is an exchange of its own, run by the same exchange logic as HTTP/1
 * requests ({@link ClientConnection#handleStream}) through an {@link Http2StreamChannel}, on a
 * virtual thread of its own.
 *
 * <p>Threads and locks (writing and flow control are {@link Http2Endpoint}'s, shared with {@link
 * Http2UpstreamConnection}):
 *
 * <ul>
 *   <li>The client connection's thread reads frames ({@link #serve}) and hands them to streams.
 *       The frame reader and HPACK decoder are its alone.
 *   <li>Each stream runs on its own virtual thread, so a slow stream never holds up the others.
 *   <li>{@link #writeLock} serializes writes: the frame writer, the HPACK encoder (header blocks
 *       are encoded and written under one hold, so they reach the client in encoding order) and
 *       the socket. Nothing else is locked while writing.
 *   <li>{@link #stateLock} guards the streams, flow-control windows and buffered request data.
 *       It is never held while writing and never taken while {@link #writeLock} is held. Stream
 *       threads wait on its conditions: for request data, and for send window.
 *   <li>A shared timer checks each connection for idleness, a missing SETTINGS acknowledgement,
 *       and writes stalled by a client that stopped reading; it never blocks.
 * </ul>
 *
 * <p>Flow control: request data is buffered per stream, never more than the stream's window
 * (and the connection's in total). Windows are credited back with WINDOW_UPDATE as streams consume
 * their data; data a stream will never read is credited back when the stream ends. Response data
 * waits for window: a stream's thread blocks until the client opens it.
 */
final class Http2Connection extends Http2Endpoint {

    private static final System.Logger LOG = System.getLogger(Http2Connection.class.getName());

    /** Streams recently reset or ended early, whose late frames are ignored rather than errors. */
    private static final int RECENTLY_CLOSED = 1024;
    /** The proxy reset or ended the stream: frames the client sent meanwhile are ignored. */
    private static final int CLOSED_HERE = 0;
    /** The client reset the stream: a frame it sends after that is a stream error STREAM_CLOSED. */
    private static final int RESET_BY_CLIENT = 1;
    /** ... answered once with RST_STREAM STREAM_CLOSED; later frames are ignored. */
    private static final int ANSWERED = 2;
    /** How long a connection that sent GOAWAY and has no streams waits for the client to close. */
    private static final long CLOSE_GRACE_NANOS = TimeUnit.SECONDS.toNanos(2);

    // Frame kinds counted against the rate limits.
    private static final int PING = 0;
    private static final int SETTINGS = 1;
    private static final int RESET = 2;
    private static final int WINDOW_UPDATE = 3;
    private static final int EMPTY_FRAME = 4;
    private static final int RAPID_RESET = 5;
    private static final String[] KINDS = {"PING", "SETTINGS", "RST_STREAM/PRIORITY", "WINDOW_UPDATE", "empty frame",
        "rapid reset"};

    private final ClientConnection client;
    private final Socket socket;
    /** Bytes the client sent before the connection was handed over (the preface, for h2c). */
    private final byte[] received;
    private final ClientFlowContext connectionFlow;
    /**
     * The {@code CONNECT} target: requests for another authority get 421. Null for a forward proxy
     * connection (h2c), whose requests name any target.
     */
    private final HostAndPort target;
    private final int maxHeaderListSize;
    private final int[] limits;
    private final long rateWindowNanos;

    // The reading thread's.
    private FrameReader reader;
    private HpackDecoder decoder;
    private InputStream in;
    private final int[] counts = new int[KINDS.length];
    private long rateWindowStart = System.nanoTime();

    // Guarded by stateLock.
    private final Map<Integer, Http2StreamChannel> streams = new HashMap<>();
    /** How each recently closed stream ended: {@link #CLOSED_HERE}, {@link #RESET_BY_CLIENT} or {@link #ANSWERED}. */
    private final Map<Integer, Integer> recentlyClosed = new LinkedHashMap<>(64, 0.75f, false) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Integer, Integer> eldest) {
            return size() > RECENTLY_CLOSED;
        }
    };
    /** The highest stream id the client has used (opened or refused). */
    private int lastStreamId;
    /** Received bytes not yet credited back to the connection's receive window. */
    private int pendingConnectionCredit;
    private boolean goAwaySent;
    private boolean peerGoingAway;

    private volatile int activeStreams;
    private volatile long lastFrameNanos = System.nanoTime();
    private volatile long lastStreamEndNanos;
    /** When the proxy's SETTINGS were sent, until the client acknowledges them; then 0. */
    private volatile long settingsSentNanos;
    /** When GOAWAY was sent; 0 before. */
    private volatile long goAwayNanos;
    private ScheduledFuture<?> watchdog;

    Http2Connection(DefaultHttpProxyServer server, ClientConnection client, Socket socket, byte[] received,
            ClientFlowContext connectionFlow, String logPrefix, HostAndPort target) {
        // The larger receive window applies at once: it only lets the client send more sooner.
        super(server, logPrefix,
                new FlowController(server.http2Options.initialWindowSize(), Http2Settings.DEFAULT_INITIAL_WINDOW_SIZE));
        this.client = client;
        this.socket = socket;
        this.received = received;
        this.connectionFlow = connectionFlow;
        this.target = target;
        this.maxHeaderListSize = options.maxHeaderListSize() > 0 ? options.maxHeaderListSize()
                : server.limits.maxHeaderSize() + server.limits.maxInitialLineLength();
        this.limits = new int[] {options.maxPings(), options.maxSettings(), options.maxResets(),
            options.maxWindowUpdates(), options.maxEmptyFrames(), options.maxRapidResets()};
        this.rateWindowNanos = options.rateWindow().toNanos();
    }

    @Override
    String peer() {
        return "client";
    }

    @Override
    void writeFailed() {
        client.close();
    }

    // ---------------------------------------------------------------------------------------
    // The connection
    // ---------------------------------------------------------------------------------------

    /** Serves the connection on the calling thread until it ends. */
    void serve() throws IOException {
        InputStream is = socket.getInputStream();
        OutputStream os = socket.getOutputStream();
        if (!server.trackers.isEmpty()) {
            is = CountingStreams.counting(is, n -> server.trackers.fire(t -> t.bytesReceivedFromClient(connectionFlow, n)));
            os = CountingStreams.counting(os, n -> server.trackers.fire(t -> t.bytesSentToClient(connectionFlow, n)));
        }
        if (received.length > 0) is = new SequenceInputStream(new ByteArrayInputStream(received), is);
        in = new BufferedInputStream(is, 16_384);
        reader = new FrameReader(in);
        int maxBlock = Math.max(FrameReader.DEFAULT_MAX_HEADER_BLOCK_SIZE, maxHeaderListSize + 4096);
        reader.setMaxHeaderBlockSize(maxBlock);
        decoder = new HpackDecoder();
        decoder.setMaxHeaderListSize(maxHeaderListSize);
        // Any string a block can carry (Huffman expands at most 8/5): an oversized field is then
        // caught by the header list limit, a stream error, rather than ending the connection.
        decoder.setMaxStringLength(maxBlock * 2);
        startWriting(new BufferedOutputStream(os, 16_384));
        long tick = tickMillis();
        watchdog = TIMERS.scheduleWithFixedDelay(this::tick, tick, tick, TimeUnit.MILLISECONDS);
        LOG.log(Level.DEBUG, logPrefix + "serving HTTP/2 (" + (target != null ? "ALPN h2" : "prior knowledge") + ")");
        try {
            int idle = server.idleTimeoutMillis();
            socket.setSoTimeout(idle > 0 ? idle : (int) options.settingsAckTimeout().toMillis());
            // The server's preface: SETTINGS (and a larger connection window), sent at once.
            Http2Settings ours = Http2Settings.builder()
                    .enablePush(false)
                    .maxConcurrentStreams(options.maxConcurrentStreams())
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
            write(null, () -> {
                writer.writeSettings(ours);
                if (connectionIncrement > 0) writer.writeWindowUpdate(0, connectionIncrement);
            }, true);
            settingsSentNanos = nanoTime();

            reader.readClientPreface();
            Frame first = reader.readFrame();
            if (!(first instanceof Frame.Settings settings) || settings.ack()) {
                throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR,
                        "the client preface must be followed by SETTINGS");
            }
            // From now on the timer watches for idleness; reads wait for as long as streams need.
            socket.setSoTimeout(0);
            lastFrameNanos = System.nanoTime();
            onSettings(settings);
            readFrames();
        } catch (Http2Exception e) {
            LOG.log(Level.DEBUG, logPrefix + "HTTP/2 " + e.getMessage());
            goAway(e.errorCode(), e.getMessage());
            drainInput();
        } catch (SocketTimeoutException e) {
            LOG.log(Level.DEBUG, logPrefix + "no HTTP/2 preface from the client in time");
        } catch (IOException e) {
            if (!closed) LOG.log(Level.DEBUG, logPrefix + "HTTP/2 connection failed: " + e);
        } finally {
            closed();
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
            if (frame == null) {
                LOG.log(Level.DEBUG, logPrefix + "client closed the HTTP/2 connection");
                return;
            }
            lastFrameNanos = System.nanoTime();
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
            case Frame.Settings s -> onSettings(s);
            case Frame.Ping p -> onPing(p);
            case Frame.WindowUpdate w -> onWindowUpdate(w);
            case Frame.RstStream r -> onRstStream(r);
            case Frame.GoAway g -> onGoAway(g);
            case Frame.Priority p -> count(RESET);
            case Frame.PushPromise p ->
                    throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, "a client sent PUSH_PROMISE");
            case Frame.Continuation c -> throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, "stray CONTINUATION");
            case Frame.Unknown u -> {
                // Extension frames are ignored (RFC 9113 section 5.5).
            }
        }
    }

    /** Counts a frame against its rate limit; over it, the connection ends with ENHANCE_YOUR_CALM. */
    private void count(int kind) throws Http2Exception {
        long now = System.nanoTime();
        if (now - rateWindowStart > rateWindowNanos) {
            Arrays.fill(counts, 0);
            rateWindowStart = now;
        }
        if (++counts[kind] > limits[kind]) {
            throw Http2Exception.connectionError(ErrorCode.ENHANCE_YOUR_CALM, KINDS[kind] + " flood: more than "
                    + limits[kind] + " in " + options.rateWindow().toMillis() + " ms");
        }
    }

    private static Http2Exception idleStream(String frame, int id) {
        return Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, frame + " on idle stream " + id);
    }

    // ---------------------------------------------------------------------------------------
    // Frames
    // ---------------------------------------------------------------------------------------

    private void onHeaders(Frame.Headers h) throws IOException {
        int id = h.streamId();
        if ((id & 1) == 0) {
            throw Http2Exception.connectionError(ErrorCode.PROTOCOL_ERROR, "HEADERS on even stream " + id);
        }
        // The block is decoded first, whatever becomes of the stream, to keep HPACK in step.
        List<HeaderField> fields = null;
        HeaderListSizeException tooLarge = null;
        try {
            fields = decoder.decode(id, h.fieldBlock());
        } catch (HeaderListSizeException e) {
            tooLarge = e;
        }
        Http2StreamChannel existing;
        boolean recent;
        boolean afterReset;
        int last;
        stateLock.lock();
        try {
            existing = streams.get(id);
            recent = recentlyClosed.containsKey(id);
            afterReset = answerAfterReset(id);
            last = lastStreamId;
            if (existing == null && id > last) lastStreamId = id;
        } finally {
            stateLock.unlock();
        }
        if (afterReset) {
            writeReset(null, id, ErrorCode.STREAM_CLOSED);
            return;
        }
        if (h.priority() != null && h.priority().streamDependency() == id && (existing != null || id > last)) {
            // (Checked here, not by the reader, which leaves decoding the block to the caller.)
            throw Http2Exception.streamError(id, ErrorCode.PROTOCOL_ERROR, "stream depends on itself");
        }
        if (existing != null) {
            onTrailers(existing, h, fields, tooLarge);
            return;
        }
        if (id <= last) {
            if (recent) return;
            throw Http2Exception.connectionError(ErrorCode.STREAM_CLOSED, "HEADERS on closed stream " + id);
        }
        if (tooLarge != null) {
            LOG.log(Level.DEBUG, logPrefix + "refusing stream " + id + ": " + tooLarge.getMessage());
            resetStream(id, tooLarge.errorCode(), tooLarge);
            return;
        }
        if (goingAway() || server.isStopping()) {
            resetStream(id, ErrorCode.REFUSED_STREAM, null);
            if (server.isStopping()) stopGracefully();
            return;
        }
        if (activeStreams >= options.maxConcurrentStreams()) {
            // Refused streams cost as much as reset ones: count them alike.
            count(RAPID_RESET);
            LOG.log(Level.DEBUG, logPrefix + "refusing stream " + id + ": " + activeStreams + " streams open");
            resetStream(id, ErrorCode.REFUSED_STREAM, null);
            return;
        }
        RequestHeaders head = Http2Headers.toRequest(id, fields);
        HttpRequest request = toHttp1(id, head, h.endStream(), target == null);
        Http2StreamChannel stream = new Http2StreamChannel(this, id, new ClientFlowContext(connectionFlow, id),
                request, head.contentLength(), h.endStream());
        stateLock.lock();
        try {
            streams.put(id, stream);
            flow.addStream(id);
            activeStreams = streams.size();
        } finally {
            stateLock.unlock();
        }
        boolean misdirected = !head.isConnect() && misdirected(head.authority());
        stream.flowContext().startExchange();
        try {
            Thread.ofVirtual().name(server.name + "-h2-" + connectionFlow.getConnectionId() + "-" + id)
                    .start(() -> runStream(stream, misdirected));
        } catch (RuntimeException | OutOfMemoryError e) {
            finishStream(stream);
            throw e;
        }
    }

    /** A stream's HEADERS after the first: trailers, which end the request. */
    private void onTrailers(Http2StreamChannel s, Frame.Headers h, List<HeaderField> fields, HeaderListSizeException tooLarge)
            throws IOException {
        int id = s.id;
        stateLock.lock();
        try {
            if (s.remoteClosed && !s.reset) {
                throw Http2Exception.streamError(id, ErrorCode.STREAM_CLOSED, "HEADERS after END_STREAM");
            }
        } finally {
            stateLock.unlock();
        }
        if (tooLarge != null) throw tooLarge;
        if (!h.endStream()) {
            throw Http2Exception.streamError(id, ErrorCode.PROTOCOL_ERROR, "trailers without END_STREAM");
        }
        List<HeaderField> valid = Http2Headers.validateTrailers(id, fields);
        if (valid.isEmpty()) count(EMPTY_FRAME);
        HttpHeaders trailers = new HttpHeaders();
        for (HeaderField f : valid) trailers.add(f.name(), f.value());
        stateLock.lock();
        try {
            if (s.remoteClosed) {
                throw Http2Exception.streamError(id, ErrorCode.STREAM_CLOSED, "HEADERS after END_STREAM");
            }
            if (s.reset) return;
            Http2Headers.checkContentLength(id, s.declaredLength, s.received, true);
            s.trailers = trailers;
            s.remoteClosed = true;
            s.changed.signalAll();
        } finally {
            stateLock.unlock();
        }
    }

    private void onData(Frame.Data d) throws IOException {
        int id = d.streamId();
        int length = d.flowControlledLength();
        byte[] data = d.data();
        if (data.length == 0 && !d.endStream()) count(EMPTY_FRAME);
        int credit;
        boolean afterReset = false;
        stateLock.lock();
        try {
            if ((id & 1) == 0 || id > lastStreamId) throw idleStream("DATA", id);
            Http2StreamChannel s = streams.get(id);
            try {
                flow.onDataReceived(id, length);
            } catch (Http2Exception e) {
                // A stream's window was overrun: its data is dropped, the connection's credited back.
                if (!e.isConnectionError()) pendingConnectionCredit += length;
                throw e;
            }
            if (s == null || s.reset || s.remoteClosed) {
                pendingConnectionCredit += length;
                if (s != null && s.remoteClosed && !s.reset) {
                    throw Http2Exception.streamError(id, ErrorCode.STREAM_CLOSED, "DATA after END_STREAM");
                }
                if (s == null && !recentlyClosed.containsKey(id)) {
                    throw Http2Exception.connectionError(ErrorCode.STREAM_CLOSED, "DATA on closed stream " + id);
                }
                afterReset = answerAfterReset(id);
            } else {
                try {
                    Http2Headers.checkContentLength(id, s.declaredLength, s.received + data.length, d.endStream());
                } catch (Http2Exception e) {
                    // Malformed: the stream is reset and this frame dropped, its credit given back.
                    pendingConnectionCredit += length;
                    throw e;
                }
                // Padding is never read: it is credited back now.
                int padding = length - data.length;
                pendingConnectionCredit += padding;
                s.unacked += padding;
                s.received += data.length;
                if (data.length > 0) {
                    s.inbound.addLast(data);
                    s.buffered += data.length;
                }
                if (d.endStream()) s.remoteClosed = true;
                s.changed.signalAll();
            }
            credit = takeConnectionCredit();
        } finally {
            stateLock.unlock();
        }
        sendWindowUpdates(0, 0, credit);
        if (afterReset) writeReset(null, id, ErrorCode.STREAM_CLOSED);
    }

    /**
     * Whether a frame on stream {@code id} must be answered with RST_STREAM STREAM_CLOSED: the
     * client reset the stream and then sent more (RFC 9113 section 5.1). Answered once per stream;
     * frames on streams the proxy reset are ignored. Holds stateLock.
     */
    private boolean answerAfterReset(int id) {
        Integer how = recentlyClosed.get(id);
        if (how == null || how != RESET_BY_CLIENT) return false;
        recentlyClosed.put(id, ANSWERED);
        return true;
    }

    private void onSettings(Frame.Settings settings) throws IOException {
        count(SETTINGS);
        if (settings.ack()) {
            settingsSentNanos = 0;
            return;
        }
        applySettings(settings);
    }

    private void onPing(Frame.Ping ping) throws IOException {
        count(PING);
        answerPing(ping);
    }

    private void onWindowUpdate(Frame.WindowUpdate update) throws IOException {
        count(WINDOW_UPDATE);
        int id = update.streamId();
        stateLock.lock();
        try {
            if (id != 0 && ((id & 1) == 0 || id > lastStreamId)) throw idleStream("WINDOW_UPDATE", id);
            flow.onWindowUpdateReceived(id, update.increment());
            windowOpened.signalAll();
        } finally {
            stateLock.unlock();
        }
    }

    private void onRstStream(Frame.RstStream rst) throws IOException {
        count(RESET);
        int id = rst.streamId();
        Http2StreamChannel s;
        boolean early = false;
        ServerConnection serverConnection = null;
        stateLock.lock();
        try {
            if ((id & 1) == 0 || id > lastStreamId) throw idleStream("RST_STREAM", id);
            s = streams.get(id);
            recentlyClosed.putIfAbsent(id, s == null || !s.reset ? RESET_BY_CLIENT : CLOSED_HERE);
            if (s != null && !s.reset) {
                early = !s.responseEnded;
                s.markReset(new IOException("stream " + id + " reset by the client (" + rst.error() + ")"));
                s.rstWritten = true;
                serverConnection = s.cancelServer();
                windowOpened.signalAll();
            }
        } finally {
            stateLock.unlock();
        }
        if (s != null && early) {
            LOG.log(Level.DEBUG, s.logPrefix() + "client reset the stream (" + rst.error() + ")");
        }
        // The exchange stops waiting on its server, whose connection is in an unknown state.
        if (serverConnection != null) serverConnection.close();
        if (early) count(RAPID_RESET);
    }

    private void onGoAway(Frame.GoAway goAway) {
        LOG.log(Level.DEBUG, logPrefix + "client sent GOAWAY (" + goAway.error() + ")");
        boolean idle;
        stateLock.lock();
        try {
            peerGoingAway = true;
            idle = streams.isEmpty();
        } finally {
            stateLock.unlock();
        }
        if (idle) goAway(ErrorCode.NO_ERROR, "");
    }

    // ---------------------------------------------------------------------------------------
    // Streams
    // ---------------------------------------------------------------------------------------

    /**
     * The HTTP/1-style request the exchange logic handles for a stream's request head: origin-form
     * on an intercepted session, absolute-form ({@code :scheme} and {@code :authority}) for a
     * forward proxy, as an HTTP/1 client would send it.
     */
    private static HttpRequest toHttp1(int id, RequestHeaders head, boolean endStream, boolean forwardProxy)
            throws Http2Exception {
        HttpMethod method;
        try {
            method = HttpMethod.valueOf(head.method());
        } catch (IllegalArgumentException e) {
            throw Http2Exception.streamError(id, ErrorCode.PROTOCOL_ERROR, "invalid :method " + head.method());
        }
        HttpHeaders headers = new HttpHeaders();
        if (head.authority() != null && head.get("host") == null) {
            headers.add(HttpHeaderNames.HOST, head.authority());
        }
        for (HeaderField f : head.fields()) {
            headers.add(f.name(), f.value());
        }
        if (!endStream && head.contentLength() < 0) {
            // A body of unknown length: chunked towards an HTTP/1.1 server.
            headers.set(HttpHeaderNames.TRANSFER_ENCODING, "chunked");
        }
        String uri = head.isConnect() ? head.authority() : head.path();
        boolean httpScheme = "http".equalsIgnoreCase(head.scheme()) || "https".equalsIgnoreCase(head.scheme());
        if (forwardProxy && !head.isConnect() && httpScheme && head.authority() != null && head.path().startsWith("/")) {
            uri = head.scheme().toLowerCase(java.util.Locale.ROOT) + "://" + head.authority() + head.path();
        }
        return new DefaultHttpRequest(HttpVersion.HTTP_2_0, method, uri, headers);
    }

    /**
     * Whether a request names an authority other than the intercepted one. A client may reuse a
     * connection for any host its certificate covers (connection coalescing), but this session
     * reaches only the {@code CONNECT} target, so such requests get 421 and are retried on a
     * connection of their own (RFC 9110 section 15.5.20).
     */
    private boolean misdirected(String authority) {
        if (authority == null || target == null) return false;
        try {
            HostAndPort requested = HostAndPort.parse(authority, 443);
            return !requested.host().equalsIgnoreCase(target.host()) || requested.port() != target.port();
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    private void runStream(Http2StreamChannel s, boolean misdirected) {
        Throwable failure = null;
        try {
            if (misdirected) {
                LOG.log(Level.DEBUG, s.logPrefix() + "421 for " + s.request.headers().get(HttpHeaderNames.HOST)
                        + ": this connection reaches " + target);
                FullHttpResponse response = ProxyUtils.createFullHttpResponse(HttpVersion.HTTP_1_1,
                        HttpResponseStatus.valueOf(421), "Misdirected Request");
                s.writeComplete(response, !ProxyUtils.isHEAD(s.request));
            } else {
                client.handleStream(s, s.request);
            }
        } catch (IOException e) {
            failure = e;
            LOG.log(Level.DEBUG, s.logPrefix() + "stream failed: " + e);
        } catch (RuntimeException e) {
            failure = e;
            LOG.log(Level.WARNING, s.logPrefix() + "unexpected error on stream", e);
        } finally {
            boolean completed = s.responseEnded;
            finishStream(s);
            if (!completed) {
                // Trackers learn that this stream's exchange is over without a response.
                Throwable cause = failure != null ? failure : s.resetCause != null ? s.resetCause
                        : new IOException("stream " + s.id + " ended without a complete response");
                server.trackers.fire(t -> t.connectionExceptionCaught(s.flowContext(), cause));
            }
        }
    }

    /** The stream's thread is done: resets it if needed, forgets it and credits its unread data back. */
    private void finishStream(Http2StreamChannel s) {
        ErrorCode code = null;
        int credit;
        boolean lastOne;
        stateLock.lock();
        try {
            if (!s.reset) {
                if (!s.responseEnded) {
                    code = ErrorCode.INTERNAL_ERROR;
                } else if (!s.remoteClosed) {
                    // The response is complete; the client need not send the rest of its request.
                    code = ErrorCode.NO_ERROR;
                }
                if (code != null) s.markReset(new IOException("stream " + s.id + " ended"));
            }
            if (s.reset) recentlyClosed.putIfAbsent(s.id, CLOSED_HERE);
            if (streams.remove(s.id, s)) {
                flow.removeStream(s.id);
                pendingConnectionCredit += (int) s.buffered;
                s.buffered = 0;
                s.inbound.clear();
            }
            activeStreams = streams.size();
            lastStreamEndNanos = System.nanoTime();
            lastOne = streams.isEmpty() && (goAwaySent || peerGoingAway);
            credit = takeConnectionCredit();
            windowOpened.signalAll();
        } finally {
            stateLock.unlock();
        }
        if (code != null) writeReset(s, s.id, code);
        try {
            sendWindowUpdates(0, 0, credit);
        } catch (IOException e) {
            // the connection is failing; its reader sees it too
        }
        if (lastOne) goAway(ErrorCode.NO_ERROR, "");
    }

    /** The exchange logic closed a stream: reset it unless both sides already ended it. */
    void closeStream(Http2StreamChannel s) {
        ErrorCode code;
        stateLock.lock();
        try {
            if (s.reset) return;
            code = !s.responseEnded ? ErrorCode.CANCEL : !s.remoteClosed ? ErrorCode.NO_ERROR : null;
            if (code == null) return;
            s.markReset(new IOException("stream " + s.id + " closed"));
            recentlyClosed.putIfAbsent(s.id, CLOSED_HERE);
            windowOpened.signalAll();
        } finally {
            stateLock.unlock();
        }
        writeReset(s, s.id, code);
    }

    /** Resets stream {@code id} for a stream error (or refuses it), telling its exchange. */
    private void resetStream(int id, ErrorCode code, IOException cause) {
        Http2StreamChannel s;
        ServerConnection serverConnection = null;
        stateLock.lock();
        try {
            s = streams.get(id);
            recentlyClosed.putIfAbsent(id, CLOSED_HERE);
            if (s != null) {
                // Already reset (by either side): no second RST_STREAM.
                if (s.reset) return;
                s.markReset(cause != null ? cause : new IOException("stream " + id + " reset: " + code));
                serverConnection = s.cancelServer();
                windowOpened.signalAll();
            }
        } finally {
            stateLock.unlock();
        }
        if (cause != null && code != ErrorCode.REFUSED_STREAM) {
            LOG.log(Level.DEBUG, logPrefix + "resetting stream " + id + ": " + cause.getMessage());
        }
        writeReset(s, id, code);
        if (serverConnection != null) serverConnection.close();
    }

    // ---------------------------------------------------------------------------------------
    // Called by streams
    // ---------------------------------------------------------------------------------------

    /** A stream's exchange read {@code n} bytes of its body: credits the windows back as needed. */
    void consumed(Http2StreamChannel s, int n) throws IOException {
        int streamCredit = 0;
        int connectionCredit;
        stateLock.lock();
        try {
            s.unacked += n;
            pendingConnectionCredit += n;
            if (!s.remoteClosed && !s.reset && s.unacked >= options.initialWindowSize() / 2) {
                streamCredit = s.unacked;
                s.unacked = 0;
                flow.onWindowUpdateSent(s.id, streamCredit);
            }
            connectionCredit = takeConnectionCredit();
        } finally {
            stateLock.unlock();
        }
        sendWindowUpdates(s.id, streamCredit, connectionCredit);
    }

    /** Takes the connection credit owed, once it is worth a WINDOW_UPDATE. Holds stateLock. */
    private int takeConnectionCredit() {
        int credit = pendingConnectionCredit;
        if (credit < options.connectionWindowSize() / 2 && !(credit > 0 && activeStreams == 0)) return 0;
        pendingConnectionCredit = 0;
        try {
            flow.onWindowUpdateSent(0, credit);
        } catch (Http2Exception e) {
            return 0; // cannot happen: the window never exceeds what the proxy granted
        }
        return credit;
    }

    // ---------------------------------------------------------------------------------------
    // Ending
    // ---------------------------------------------------------------------------------------

    private boolean goingAway() {
        stateLock.lock();
        try {
            return goAwaySent;
        } finally {
            stateLock.unlock();
        }
    }

    /**
     * Sends GOAWAY (once) with the last stream processed; no new streams are accepted after it.
     * The connection closes once its streams are done and the client has closed (or after a grace
     * period).
     */
    private void goAway(ErrorCode code, String debug) {
        int last;
        stateLock.lock();
        try {
            if (goAwaySent) return;
            goAwaySent = true;
            last = lastStreamId;
        } finally {
            stateLock.unlock();
        }
        goAwayNanos = nanoTime();
        if (code != ErrorCode.NO_ERROR) {
            LOG.log(Level.DEBUG, logPrefix + "sending GOAWAY " + code + ": " + debug);
        }
        writeGoAway(last, code, debug);
    }

    /** Graceful stop: GOAWAY now, close once the open streams have finished. Does not block. */
    void stopGracefully() {
        if (closed) return;
        Thread.ofVirtual().name(server.name + "-h2-stop-" + connectionFlow.getConnectionId()).start(() -> {
            goAway(ErrorCode.NO_ERROR, "server stopping");
            if (activeStreams == 0) client.close();
        });
    }

    boolean isIdle() {
        return activeStreams == 0;
    }

    /**
     * The client connection is closing: every stream fails at its next wait or write, and their
     * server connections close with the client's.
     */
    void closed() {
        if (closed) return;
        closed = true;
        ScheduledFuture<?> w = watchdog;
        if (w != null) w.cancel(false);
        List<Http2StreamChannel> open;
        stateLock.lock();
        try {
            open = new ArrayList<>(streams.values());
            for (Http2StreamChannel s : open) {
                if (!s.reset) s.markReset(new IOException("HTTP/2 connection closed"));
            }
            windowOpened.signalAll();
        } finally {
            stateLock.unlock();
        }
        client.close();
    }

    /** After a connection error: reads what the client still sends for a moment, so closing does not reset the GOAWAY. */
    private void drainInput() {
        try {
            socket.setSoTimeout(1000);
            byte[] buf = new byte[4096];
            int total = 0;
            int n;
            while (total < 65_536 && (n = in.read(buf)) >= 0) {
                total += n;
            }
        } catch (IOException e) {
            // done
        }
    }

    // ---------------------------------------------------------------------------------------
    // Timers
    // ---------------------------------------------------------------------------------------

    private long tickMillis() {
        int idle = server.idleTimeoutMillis();
        long ack = options.settingsAckTimeout().toMillis();
        long shortest = idle > 0 ? Math.min(idle, ack) : ack;
        return Math.max(25, Math.min(1000, shortest / 4));
    }

    /** Runs on the shared timer: must not block, so anything that writes gets a thread of its own. */
    private void tick() {
        if (closed) return;
        long now = System.nanoTime();
        int idle = server.idleTimeoutMillis();
        long idleNanos = TimeUnit.MILLISECONDS.toNanos(idle);
        long writeStarted = writeStartedNanos;
        if (idle > 0 && writeStarted != 0 && now - writeStarted > idleNanos) {
            // The client stopped reading: nothing can be written to it, not even GOAWAY.
            LOG.log(Level.DEBUG, logPrefix + "closing: no write progress for " + idle + " ms");
            closeAsync();
            return;
        }
        long sent = settingsSentNanos;
        if (sent != 0 && now - sent > options.settingsAckTimeout().toNanos()) {
            settingsSentNanos = 0;
            Thread.ofVirtual().start(() -> {
                goAway(ErrorCode.SETTINGS_TIMEOUT, "SETTINGS not acknowledged in time");
                client.close();
            });
            return;
        }
        if (activeStreams > 0) return;
        long goAway = goAwayNanos;
        if (goAway != 0) {
            if (now - Math.max(goAway, lastStreamEndNanos) > CLOSE_GRACE_NANOS) closeAsync();
            return;
        }
        if (idle > 0 && now - Math.max(lastFrameNanos, lastStreamEndNanos) > idleNanos) {
            LOG.log(Level.DEBUG, logPrefix + "HTTP/2 connection idle for " + idle + " ms");
            goAwayNanos = nanoTime(); // no second idle check while GOAWAY is on its way
            Thread.ofVirtual().start(() -> {
                server.trackers.fire(t -> t.connectionTimedOut(connectionFlow));
                goAway(ErrorCode.NO_ERROR, "idle");
            });
        }
    }

    /** Closes the client connection on a thread of its own: closing runs trackers and pool code. */
    private void closeAsync() {
        Thread.ofVirtual().start(client::close);
    }

}
