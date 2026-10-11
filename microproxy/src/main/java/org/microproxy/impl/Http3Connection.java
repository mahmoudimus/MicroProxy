package org.microproxy.impl;

import io.github.mahmoudimus.http3.Http3ErrorCode;
import io.github.mahmoudimus.http3.Http3Exception;
import io.github.mahmoudimus.http3.Http3Headers;
import io.github.mahmoudimus.http3.Http3Settings;
import io.github.mahmoudimus.http3.QuicVarInt;
import io.github.mahmoudimus.http3.Http3StreamValidator;
import io.github.mahmoudimus.http3.RequestHeaders;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.connection.ConnectionError;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.microproxy.frames.FrameDirection;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/**
 * The server side of an HTTP/3 connection from a client (RFC 9114): on the proxy's QUIC listener
 * ({@link Http3Listener}), as a reverse proxy's or a forward proxy's, or an intercepted connection
 * of the transparent QUIC listener. Each request stream is an exchange of its own, run by the same
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

    /** Who the client takes the proxy for. */
    enum Role {
        /** The server of a reverse proxy: requests are for its upstream. */
        REVERSE,
        /**
         * A forward proxy, on its TLS listener's UDP port: requests name their targets ({@code
         * :scheme} and {@code :authority}), {@code CONNECT} opens tunnels and CONNECT-UDP proxies UDP.
         */
        FORWARD,
        /** The server the client meant to reach, whose QUIC the proxy intercepted (transparent QUIC). */
        INTERCEPTED
    }

    private final ClientConnection client;
    private final ClientFlowContext connectionFlow;
    private final Http3Frames.Origin origin;
    final Role role;
    /**
     * The intercepted server ({@link Role#INTERCEPTED}): requests for another authority get 421,
     * except proxy requests ({@code :scheme http}) and plain {@code CONNECT}s, which the client
     * sends the server as to its proxy. Null for the proxy's own listener.
     */
    private final HostAndPort target;

    // Guarded by stateLock.
    private final Map<Long, Http3StreamChannel> streams = new HashMap<>();
    /** The highest request stream id the client has opened, or -1. */
    private long lastStreamId = -1;
    private boolean goAwaySent;

    private volatile int activeStreams;
    private final AtomicBoolean shutDown = new AtomicBoolean();
    /** The CONNECT-UDP flows of the connection, by their streams' ids; the size guarded by stateLock. */
    private final Map<Long, UdpFlow> udpFlows = new ConcurrentHashMap<>();
    /** The thread that receives QUIC DATAGRAM frames has started. */
    private final AtomicBoolean receivingDatagrams = new AtomicBoolean();

    /**
     * @param target the intercepted server, for {@link Role#INTERCEPTED}; else null
     */
    Http3Connection(DefaultHttpProxyServer server, ClientConnection client, QuicConnection quic,
            ClientFlowContext connectionFlow, String logPrefix, Role role, HostAndPort target) {
        super(server, quic, logPrefix, Http3StreamValidator.Role.SERVER);
        this.client = client;
        this.connectionFlow = connectionFlow;
        this.role = role;
        this.target = target;
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

    /**
     * Extended {@code CONNECT} (RFC 9220): WebSockets over HTTP/3, and on a forward proxy's
     * listener HTTP Datagrams (RFC 9297), for CONNECT-UDP; only that listener accepts QUIC DATAGRAM
     * frames.
     */
    @Override
    void extensionSettings(Http3Settings.Builder settings) {
        settings.enableConnectProtocol(true);
        if (role == Role.FORWARD) settings.h3Datagram(true);
    }

    // ---------------------------------------------------------------------------------------
    // HTTP Datagrams (RFC 9297), for CONNECT-UDP flows
    // ---------------------------------------------------------------------------------------

    /**
     * Routes the HTTP Datagrams of {@code streamId} to {@code flow}, starting the thread that
     * receives the connection's QUIC DATAGRAM frames; false if the connection has as many flows as
     * it may ({@link org.microproxy.Http3Options#connectUdpMaxFlowsPerConnection()}).
     */
    boolean addUdpFlow(long streamId, UdpFlow flow) {
        stateLock.lock();
        try {
            if (closed || udpFlows.size() >= options.connectUdpMaxFlowsPerConnection()) return false;
            udpFlows.put(streamId, flow);
        } finally {
            stateLock.unlock();
        }
        if (receivingDatagrams.compareAndSet(false, true)) {
            Thread.ofVirtual().name(server.name + "-h3-datagrams-" + connectionFlow.getConnectionId())
                    .start(this::receiveDatagrams);
        }
        return true;
    }

    /** The flow of {@code streamId} ended. */
    void removeUdpFlow(long streamId, UdpFlow flow) {
        stateLock.lock();
        try {
            udpFlows.remove(streamId, flow);
        } finally {
            stateLock.unlock();
        }
    }

    /**
     * Receives the client's QUIC DATAGRAM frames until the connection ends: each is an HTTP
     * Datagram, a quarter stream ID and then content for that stream's flow. Datagrams for a stream
     * with no flow (one that ended, or never was) are dropped (RFC 9297 section 2.1).
     */
    private void receiveDatagrams() {
        try {
            while (!closed) {
                byte[] d = quic.receiveDatagram();
                long quarter = QuicVarInt.read(d, 0, d.length);
                if (quarter < 0 || quarter > MAX_QUARTER_STREAM_ID) {
                    connectionError(Http3ErrorCode.H3_DATAGRAM_ERROR, "an HTTP/3 datagram without a valid quarter stream ID");
                    return;
                }
                UdpFlow flow = udpFlows.get(quarter * 4);
                if (flow != null) flow.fromClient(Arrays.copyOfRange(d, QuicVarInt.length(quarter), d.length));
            }
        } catch (IOException e) {
            // the connection ended
        }
    }

    /** The largest quarter stream ID (RFC 9297 section 2.1): a stream ID is below 2^62. */
    private static final long MAX_QUARTER_STREAM_ID = (1L << 60) - 1;

    /**
     * Sends an HTTP Datagram of {@code streamId} with {@code content} in a QUIC DATAGRAM frame, if
     * the client accepts HTTP Datagrams (its SETTINGS_H3_DATAGRAM) and it fits in one; false
     * otherwise, for the caller to send a DATAGRAM capsule instead.
     */
    boolean sendHttpDatagram(long streamId, byte[] content) throws IOException {
        // Not before the client's SETTINGS say it takes them (RFC 9297 section 2.1.1), which come
        // first on its control stream, but may be read after a request stream's datagram.
        Http3Settings settings = settingsReceived() ? peerSettings() : awaitPeerSettings(readTimeoutNanos());
        if (!settings.h3Datagram()) return false;
        byte[] quarter = QuicVarInt.encode(streamId / 4);
        if (quic.maxDatagramSize() < quarter.length + content.length) return false;
        byte[] d = new byte[quarter.length + content.length];
        System.arraycopy(quarter, 0, d, 0, quarter.length);
        System.arraycopy(content, 0, d, quarter.length, content.length);
        try {
            quic.sendDatagram(d);
            return true;
        } catch (IllegalStateException | IllegalArgumentException e) {
            return false;
        }
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
        if (server.drainClose()) {
            // Draining: this stream is served, and GOAWAY names the next one as the first refused.
            client.drain();
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
     * stream error), a request for another host on an intercepted connection ({@code 421}), and one
     * in 0-RTT data that is not safe to replay, a {@code CONNECT} included ({@code 425}).
     * {@code CONNECT} opens a tunnel; an extended {@code CONNECT} becomes the HTTP/1.1 upgrade an
     * HTTP/1.1 client would send ({@link Http3Messages#toHttp1Connect}).
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
        HttpRequest http1;
        // A request for http:// on an intercepted connection is a proxy request: the client takes
        // the intercepted server for its proxy, and the request goes there in absolute-form. So is
        // a plain CONNECT, whose authority names the tunnel's target.
        boolean proxyRequest;
        if (request.isConnect()) {
            if ("websocket".equals(request.protocol()) && (!("http".equals(request.scheme())
                    || "https".equals(request.scheme())) || !request.path().startsWith("/"))) {
                LOG.log(Level.DEBUG, s.logPrefix() + "malformed request: invalid WebSocket scheme or path");
                s.resetStream(Http3ErrorCode.H3_MESSAGE_ERROR);
                return null;
            }
            proxyRequest = request.protocol() == null;
            http1 = Http3Messages.toHttp1Connect(request, role == Role.FORWARD);
        } else {
            if (!reader.endsHere()) reader.awaitNext(END_GRACE_NANOS);
            proxyRequest = role == Role.INTERCEPTED && "http".equalsIgnoreCase(request.scheme());
            try {
                http1 = Http3Messages.toHttp1(request, !reader.endsHere(), role == Role.FORWARD || proxyRequest);
            } catch (IllegalArgumentException e) {
                s.resetStream(Http3ErrorCode.H3_MESSAGE_ERROR);
                return null;
            }
        }
        if (reader.stream.receivedEarlyData()) {
            s.flowContext().earlyData();
            // A CONNECT opens a tunnel (an extended one's upgrade too), which is never safe to replay
            if (request.isConnect() || !replaySafe(http1, reader.endsHere())) {
                // RFC 8470 section 5.2: the client sends it again once its handshake is complete
                LOG.log(Level.DEBUG, s.logPrefix() + "425: " + (request.isConnect() ? "CONNECT" : http1.method())
                        + " in 0-RTT data");
                if (!reader.endsHere()) reader.abort(Http3ErrorCode.H3_NO_ERROR);
                s.flowContext().setResponseCodeDetails("too_early");
                FullHttpResponse tooEarly = ProxyUtils.createFullHttpResponse(HttpVersion.HTTP_1_1,
                        HttpResponseStatus.valueOf(425), "Too Early");
                s.writeComplete(tooEarly, true);
                client.recordAnswered(s.flowContext(), org.microproxy.FlowRecord.Kind.HTTP3, http1, tooEarly);
                return null;
            }
            http1.headers().set(EARLY_DATA, "1");
        }
        if (request.isConnect()) {
            s.requestRead(http1, request.protocol(), request.scheme());
        } else {
            s.requestRead(http1);
        }
        if (!proxyRequest && misdirected(request.authority())) {
            LOG.log(Level.DEBUG, s.logPrefix() + "421 for " + request.authority() + ": this connection reaches " + target);
            FullHttpResponse response = ProxyUtils.createFullHttpResponse(HttpVersion.HTTP_1_1,
                    HttpResponseStatus.valueOf(421), "Misdirected Request");
            s.writeComplete(response, !ProxyUtils.isHEAD(http1));
            return null;
        }
        return http1;
    }

    /**
     * Whether a request on an intercepted connection names an authority other than the intercepted
     * server's. A client may reuse a connection for any host its certificate covers (connection
     * coalescing), but this one reaches only that server, so such requests get 421 and are retried
     * on a connection of their own (RFC 9110 section 15.5.20, RFC 9114 section 3.4). Only the host
     * counts: the port is the one the client sent its QUIC to before a firewall redirected it,
     * which the proxy cannot know (it reaches the SNI's host on the transparent TLS port). The
     * proxy's own listener serves every authority: a forward proxy's requests name their targets.
     */
    private boolean misdirected(String authority) {
        if (authority == null || target == null) return false;
        try {
            return !HostAndPort.parse(authority, 443).host().equalsIgnoreCase(target.host());
        } catch (IllegalArgumentException e) {
            return true;
        }
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
            LOG.log(Level.DEBUG, s.logPrefix() + (s.tunnelOpen ? "client ended the tunnel with a reset"
                    : "client reset the stream"));
            if (!s.tunnelOpen) {
                s.flowContext().addResponseFlag(org.microproxy.ResponseFlag.DOWNSTREAM_REMOTE_RESET);
                s.flowContext().defaultResponseCodeDetails("downstream_remote_reset");
            }
            serverConnection = s.cancelServer();
        }
        if (serverConnection != null) serverConnection.close();
        // A reset that ends an open tunnel is how tunnels end, not a request given up on.
        if (early && !s.tunnelOpen) {
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
