package org.microproxy.impl;

import io.github.mahmoudimus.http3.Http3ErrorCode;
import io.github.mahmoudimus.http3.Http3Exception;
import io.github.mahmoudimus.http3.Http3Headers;
import io.github.mahmoudimus.http3.Http3StreamValidator;
import io.github.mahmoudimus.http3.RequestHeaders;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.connection.ConnectionError;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.microproxy.frames.FrameDirection;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/**
 * The server side of an HTTP/3 connection from a client (RFC 9114), on the reverse proxy's QUIC
 * listener ({@link Http3Listener}). Each request stream is an exchange of its own, run by the same
 * exchange logic as HTTP/1 and HTTP/2 requests ({@link ClientConnection#handleStream}) through an
 * {@link Http3StreamChannel}, on a virtual thread of its own; the connection's control and QPACK
 * streams are {@link Http3Endpoint}'s.
 *
 * <p>QUIC limits the request streams a client may open ({@link
 * org.microproxy.Http3Options#maxConcurrentStreams()}) and how much it may send ahead of the
 * proxy's reading; the proxy limits header sections (SETTINGS_MAX_FIELD_SECTION_SIZE, answered
 * {@code 431}), streams blocked on QPACK, unknown frames and streams, and requests cancelled before
 * their response (Rapid Reset), each a connection error H3_EXCESSIVE_LOAD past its limit.
 *
 * <p><b>Early data.</b> With {@link org.microproxy.Http3Options#zeroRtt() 0-RTT} on, a resuming
 * client's first requests may arrive as 0-RTT data, before its handshake completes, and may be
 * replays (RFC 8446 section 8). A request any part of which came early is marked ({@link
 * org.microproxy.FlowContext#isEarlyData()}), answered {@code 425 Too Early} unless it is safe to
 * repeat ({@code GET}, {@code HEAD} or {@code OPTIONS} without a body), and otherwise sent on with
 * {@code Early-Data: 1} (RFC 8470 section 5.1), whether or not the handshake has completed by
 * then: the proxy does not hold requests back to find out.
 *
 * <p>A graceful stop sends GOAWAY: streams the client opens after it are refused with
 * H3_REQUEST_REJECTED, which clients retry, and the connection closes once its streams are done
 * and the client has closed it (or after a grace period).
 */
final class Http3Connection extends Http3Endpoint {

    private static final System.Logger LOG = System.getLogger(Http3Connection.class.getName());

    /** How long a request head may wait for the stream's end before the request is taken to have a body. */
    private static final long END_GRACE_NANOS = TimeUnit.MILLISECONDS.toNanos(20);
    /** How long a connection that sent GOAWAY and has no streams waits for the client to close. */
    private static final long CLOSE_GRACE_NANOS = TimeUnit.SECONDS.toNanos(2);

    private final ClientConnection client;
    private final ClientFlowContext connectionFlow;
    private final Http3Frames.Origin origin;

    // Guarded by stateLock.
    private final Map<Long, Http3StreamChannel> streams = new HashMap<>();
    /** The highest request stream id the client has opened, or -1. */
    private long lastStreamId = -1;
    private boolean goAwaySent;

    private volatile int activeStreams;
    private final AtomicBoolean shutDown = new AtomicBoolean();

    Http3Connection(DefaultHttpProxyServer server, ClientConnection client, QuicConnection quic,
            ClientFlowContext connectionFlow, String logPrefix) {
        super(server, quic, logPrefix, Http3StreamValidator.Role.SERVER);
        this.client = client;
        this.connectionFlow = connectionFlow;
        this.origin = new Http3Frames.Origin(connectionFlow.getConnectionId(), connectionFlow.getClientAddress(), null);
    }

    @Override
    FrameDirection receivedDirection() {
        return FrameDirection.FROM_CLIENT;
    }

    @Override
    FrameDirection sentDirection() {
        return FrameDirection.TO_CLIENT;
    }

    @Override
    Http3Frames.Origin frameOrigin() {
        return origin;
    }

    /** Serves the connection on the calling thread until it ends. */
    void serve() {
        LOG.log(Level.DEBUG, logPrefix + "serving HTTP/3 to " + quic.remoteAddress());
        try {
            start();
            acceptStreams();
        } catch (IOException e) {
            if (!closed) LOG.log(Level.DEBUG, logPrefix + "HTTP/3 connection failed: " + e);
        } finally {
            closed();
        }
        ConnectionError reason = quic.closeReason();
        if (reason != null && reason.kind() == ConnectionError.Kind.TIMED_OUT) {
            server.trackers.fire(t -> t.connectionTimedOut(connectionFlow));
        }
    }

    // ---------------------------------------------------------------------------------------
    // Streams
    // ---------------------------------------------------------------------------------------

    @Override
    void onRequestStream(QuicStream s) throws IOException {
        long id = s.id();
        boolean refuse;
        stateLock.lock();
        try {
            refuse = goAwaySent || server.isStopping() || id > Integer.MAX_VALUE;
            if (!refuse) lastStreamId = Math.max(lastStreamId, id);
        } finally {
            stateLock.unlock();
        }
        if (refuse) {
            // Not processed: the client may retry it on another connection (RFC 9114 section 4.1.1).
            try {
                s.stopSending(Http3ErrorCode.H3_REQUEST_REJECTED.code());
                s.reset(Http3ErrorCode.H3_REQUEST_REJECTED.code());
            } catch (IOException e) {
                // gone already
            }
            if (server.isStopping()) stopGracefully();
            return;
        }
        ClientFlowContext flow = new ClientFlowContext(connectionFlow, (int) id, HttpVersion.HTTP_3_0);
        Http3StreamChannel[] channel = new Http3StreamChannel[1];
        Http3StreamReader reader = new Http3StreamReader(this, s, false,
                server.trackers.isEmpty() ? null : n -> server.trackers.fire(t -> t.bytesReceivedFromClient(connectionFlow, n)),
                () -> clientReset(channel[0]));
        Http3MessageWriter writer = new Http3MessageWriter(this, s, true,
                server.trackers.isEmpty() ? null : n -> server.trackers.fire(t -> t.bytesSentToClient(connectionFlow, n)));
        Http3StreamChannel stream = new Http3StreamChannel(this, reader, writer, flow);
        channel[0] = stream;
        stateLock.lock();
        try {
            streams.put(id, stream);
            activeStreams = streams.size();
        } finally {
            stateLock.unlock();
        }
        flow.startExchange();
        String name = server.name + "-h3-" + connectionFlow.getConnectionId() + "-" + id;
        try {
            reader.start(name + "-in");
            Thread.ofVirtual().name(name).start(() -> runStream(stream));
        } catch (RuntimeException | OutOfMemoryError e) {
            finishStream(stream);
            throw e;
        }
    }

    private void runStream(Http3StreamChannel s) {
        Throwable failure = null;
        try {
            HttpRequest request = readRequest(s);
            if (request != null) client.handleStream(s, request);
        } catch (IOException e) {
            failure = e;
            LOG.log(Level.DEBUG, s.logPrefix() + "stream failed: " + e);
        } catch (RuntimeException e) {
            failure = e;
            LOG.log(Level.WARNING, s.logPrefix() + "unexpected error on stream", e);
        } finally {
            boolean completed = s.responseEnded();
            finishStream(s);
            if (!completed) {
                // Trackers learn that this stream's exchange is over without a response.
                Throwable cause = failure != null ? failure : new IOException("stream " + s.id + " ended without a complete response");
                server.trackers.fire(t -> t.connectionExceptionCaught(s.flowContext(), cause));
            }
        }
    }

    /**
     * Reads the request head and makes it an HTTP/1-style request; answers itself (and returns
     * null) what goes no further: a head over the size limit ({@code 431}), a malformed one (a
     * stream error), {@code CONNECT} and extended {@code CONNECT} ({@code 501}).
     */
    private HttpRequest readRequest(Http3StreamChannel s) throws IOException {
        Http3StreamReader reader = s.reader;
        if (!reader.awaitHead(readTimeoutNanos())) throw new SocketTimeoutException("no request head on stream " + s.id);
        Http3StreamReader.Head head = reader.takeHead();
        if (head.tooLarge()) {
            LOG.log(Level.DEBUG, s.logPrefix() + "431: request field section over " + maxFieldSectionSize + " bytes");
            reader.abort(Http3ErrorCode.H3_NO_ERROR);
            answer(s, HttpResponseStatus.valueOf(431), "Request Header Fields Too Large");
            return null;
        }
        RequestHeaders request;
        try {
            request = Http3Headers.toRequest(s.id, head.fields(), true);
        } catch (Http3Exception e) {
            LOG.log(Level.DEBUG, s.logPrefix() + "malformed request: " + e.getMessage());
            s.resetStream(e.errorCode());
            return null;
        }
        if (request.isConnect()) {
            // Tunnels inside HTTP/3 (RFC 9114 section 4.4, RFC 9220) are not supported yet.
            reader.abort(Http3ErrorCode.H3_NO_ERROR);
            answer(s, HttpResponseStatus.valueOf(501), request.protocol() != null
                    ? "Not Implemented: extended CONNECT over HTTP/3" : "Not Implemented: CONNECT over HTTP/3");
            return null;
        }
        if (!reader.endsHere()) reader.awaitNext(END_GRACE_NANOS);
        HttpRequest http1;
        try {
            http1 = Http3Messages.toHttp1(request, !reader.endsHere());
        } catch (IllegalArgumentException e) {
            s.resetStream(Http3ErrorCode.H3_MESSAGE_ERROR);
            return null;
        }
        if (reader.stream.receivedEarlyData()) {
            s.flowContext().earlyData();
            if (!replaySafe(http1, reader.endsHere())) {
                // RFC 8470 section 5.2: the client sends it again once its handshake is complete
                LOG.log(Level.DEBUG, s.logPrefix() + "425: " + http1.method() + " in 0-RTT data");
                if (!reader.endsHere()) reader.abort(Http3ErrorCode.H3_NO_ERROR);
                answer(s, HttpResponseStatus.valueOf(425), "Too Early");
                return null;
            }
            http1.headers().set(EARLY_DATA, "1");
        }
        s.requestRead(http1);
        return http1;
    }

    /** The field that marks a request forwarded from early data (RFC 8470 section 5.1). */
    static final String EARLY_DATA = "Early-Data";

    /**
     * Whether a request may be replayed without harm, so that it may travel as early data: a
     * {@code GET}, {@code HEAD} or {@code OPTIONS} without a body (RFC 8470 section 2.1, RFC 9110
     * section 9.2.1).
     */
    static boolean replaySafe(HttpRequest request, boolean noBody) {
        String method = request.method().name();
        return noBody && (method.equals("GET") || method.equals("HEAD") || method.equals("OPTIONS"));
    }

    private static void answer(Http3StreamChannel s, HttpResponseStatus status, String text) throws IOException {
        FullHttpResponse response = ProxyUtils.createFullHttpResponse(HttpVersion.HTTP_1_1, status, text);
        s.writeComplete(response, true);
    }

    /** The client reset its request stream: the exchange stops waiting on its server. */
    private void clientReset(Http3StreamChannel s) {
        if (s == null) return;
        ServerConnection serverConnection = null;
        boolean early;
        stateLock.lock();
        try {
            early = !s.responseEnded() && streams.get(s.id) == s;
        } finally {
            stateLock.unlock();
        }
        if (early) {
            LOG.log(Level.DEBUG, s.logPrefix() + "client reset the stream");
            serverConnection = s.cancelServer();
        }
        if (serverConnection != null) serverConnection.close();
        if (early) {
            try {
                count(RAPID_RESET);
            } catch (Http3Exception e) {
                connectionError(e.errorCode(), e.getMessage());
            }
        }
    }

    /** The stream's thread is done: ends what is still open of the stream, and forgets it. */
    private void finishStream(Http3StreamChannel s) {
        ServerConnection dangling = s.cancelServer();
        if (dangling != null) dangling.close();
        if (!s.writer.ended()) {
            s.resetStream(Http3ErrorCode.H3_INTERNAL_ERROR);
        } else if (!s.reader.ended()) {
            // The response is complete; the client need not send the rest of its request.
            s.reader.abort(Http3ErrorCode.H3_NO_ERROR);
        }
        boolean lastOne;
        stateLock.lock();
        try {
            streams.remove(s.id, s);
            activeStreams = streams.size();
            lastOne = streams.isEmpty() && goAwaySent;
            stateChanged.signalAll();
        } finally {
            stateLock.unlock();
        }
        if (lastOne) closeWhenClientDone();
    }

    /** The exchange logic closed a stream: resets it unless its response is complete. */
    void closeStream(Http3StreamChannel s) {
        if (s.writer.ended() && !s.responseEnded()) return; // reset already
        if (!s.responseEnded()) {
            s.resetStream(Http3ErrorCode.H3_REQUEST_CANCELLED);
        } else if (!s.reader.ended()) {
            s.reader.abort(Http3ErrorCode.H3_NO_ERROR);
        }
    }

    @Override
    void onGoAway(long id) {
        // A client's GOAWAY names push ids, and the proxy never pushes: it stops using the connection.
        boolean idle;
        stateLock.lock();
        try {
            idle = streams.isEmpty();
        } finally {
            stateLock.unlock();
        }
        if (idle) stopGracefully();
    }

    // ---------------------------------------------------------------------------------------
    // Ending
    // ---------------------------------------------------------------------------------------

    /**
     * Graceful stop: GOAWAY now, naming the first stream the proxy will not process, and close once
     * the open streams have finished. Does not block.
     */
    void stopGracefully() {
        if (closed) return;
        long next;
        boolean idle;
        stateLock.lock();
        try {
            if (goAwaySent) return;
            goAwaySent = true;
            // The first client-initiated bidirectional stream id not processed (RFC 9114 section 5.2).
            next = lastStreamId < 0 ? 0 : lastStreamId + 4;
            idle = streams.isEmpty();
        } finally {
            stateLock.unlock();
        }
        Thread.ofVirtual().name(server.name + "-h3-stop-" + connectionFlow.getConnectionId()).start(() -> {
            try {
                sendGoAway(next);
            } catch (IOException e) {
                // the connection is failing
            }
            if (idle) closeWhenClientDone();
        });
    }

    /**
     * The connection has sent GOAWAY and has no streams left: waits briefly for the client to close
     * it (so the last responses are delivered), then closes it with H3_NO_ERROR.
     */
    private void closeWhenClientDone() {
        Thread.ofVirtual().name(server.name + "-h3-close-" + connectionFlow.getConnectionId()).start(() -> {
            try {
                quic.awaitClosed(java.time.Duration.ofNanos(CLOSE_GRACE_NANOS));
            } catch (IOException e) {
                Thread.currentThread().interrupt();
            }
            quic.close(Http3ErrorCode.H3_NO_ERROR.code(), "");
            client.close();
        });
    }

    boolean isIdle() {
        return activeStreams == 0;
    }

    /**
     * The client connection is closing: the QUIC connection closes, and every stream fails at its
     * next wait or write.
     */
    @Override
    void closed() {
        super.closed();
        if (!shutDown.compareAndSet(false, true)) return;
        List<Http3StreamChannel> open;
        stateLock.lock();
        try {
            open = new ArrayList<>(streams.values());
        } finally {
            stateLock.unlock();
        }
        IOException cause = new IOException("HTTP/3 connection closed");
        for (Http3StreamChannel s : open) s.reader.failWith(cause);
        if (quic.isOpen()) quic.close(Http3ErrorCode.H3_NO_ERROR.code(), "");
        client.close();
    }
}
