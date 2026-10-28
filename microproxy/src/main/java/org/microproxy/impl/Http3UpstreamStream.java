package org.microproxy.impl;

import io.github.mahmoudimus.http3.Http3ErrorCode;
import io.github.mahmoudimus.http3.Http3Exception;
import io.github.mahmoudimus.http3.Http3Headers;
import io.github.mahmoudimus.http3.ResponseHeaders;
import io.github.mahmoudimus.quic.QuicConnectionException;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.QuicStreamException;
import io.github.mahmoudimus.quic.connection.ConnectionError;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.microproxy.FullFlowContext;
import org.microproxy.http.FullHttpRequest;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.LastHttpContent;

/**
 * One exchange's request stream on an {@link Http3UpstreamConnection}, as the exchange logic sees
 * server connections, as {@link Http2UpstreamStream} is for HTTP/2: the request head becomes a
 * HEADERS frame (pseudo-headers from the request line and {@code Host}, without HTTP/1's
 * connection-specific fields), its body DATA frames, its trailers a final HEADERS frame, and its
 * end the stream's FIN; the response arrives as HTTP/1-style messages. It is never pooled or kept:
 * {@link #close()} ends the stream (resetting what is still open of it) and leaves the connection
 * to other exchanges.
 *
 * <p>QUIC's failures become the exchange logic's: the idle timeout a {@link SocketTimeoutException}
 * (a {@code 504}), a request the server never processed ({@code GOAWAY}, {@code
 * H3_REQUEST_REJECTED}) {@link Http3UpstreamConnection.Unprocessed}, which is sent again, and
 * other resets and connection errors {@link IOException}s (a {@code 502}, or a reset client stream
 * once the response has started).
 *
 * <p>A WebSocket upgrade goes to a server that sent SETTINGS_ENABLE_CONNECT_PROTOCOL as an extended
 * {@code CONNECT} with {@code :protocol websocket} (RFC 9220); its 2xx is shown to the exchange
 * logic as the {@code 101} an HTTP/1.1 server would send, and the stream's DATA then carry the
 * WebSocket's frames ({@link #tunnelInput}, {@link #tunnelOutput}).
 *
 * <p>A request the proxy chose to send as 0-RTT data that the server answers with {@code 425 Too
 * Early} is {@link Http3UpstreamConnection.Unprocessed} too, and goes again once the handshake has
 * completed; but one that arrived as early data itself, marked {@code Early-Data: 1}, has its
 * {@code 425} relayed to its client (RFC 8470 section 5.2).
 */
final class Http3UpstreamStream extends ServerConnection {

    private final Http3UpstreamConnection connection;
    final long id;
    private final QuicStream stream;
    private final Http3StreamReader reader;
    private final Http3MessageWriter writer;
    private final boolean headRequest;
    private final String logPrefix;
    private final AtomicBoolean done = new AtomicBoolean();
    /** The QUIC connection was made for this stream's exchange: it reports the connection to filters and trackers. */
    volatile boolean newConnection;
    /** The request is a WebSocket upgrade, sent as an extended CONNECT. */
    private boolean webSocket;
    private String webSocketKey;
    /** The server's actual status for an accepted WebSocket, shown to the exchange as a 101; else 0. */
    private int tunnelStatus;
    /** The request went out as 0-RTT data, which the proxy chose to send early. */
    private boolean sentEarly;

    Http3UpstreamStream(Http3UpstreamConnection connection, QuicStream stream, FullFlowContext flowContext, String logPrefix,
            boolean headRequest) {
        super(connection.hostAndPort, null, null, connection.remote, flowContext, connection.server.trackers);
        this.connection = connection;
        this.cluster = connection.cluster;
        this.stream = stream;
        this.id = stream.id();
        this.headRequest = headRequest;
        this.logPrefix = logPrefix;
        Trackers trackers = connection.server.trackers;
        this.reader = new Http3StreamReader(connection, stream, true,
                trackers.isEmpty() ? null : n -> {
                    if (this.flowContext.getClientContext() instanceof ClientFlowContext flow) flow.addUpstreamReceived(n);
                    trackers.fire(t -> t.bytesReceivedFromServer(this.flowContext, n));
                }, null);
        this.writer = new Http3MessageWriter(connection, stream, false,
                trackers.isEmpty() ? null : n -> {
                    if (this.flowContext.getClientContext() instanceof ClientFlowContext flow) flow.addUpstreamSent(n);
                    trackers.fire(t -> t.bytesSentToServer(this.flowContext, n));
                });
        reader.headRequest = headRequest;
        reader.flow = flowContext;
        writer.flow = flowContext;
        // A stream is a reused connection as far as retries go: one the server never processed
        // (GOAWAY, H3_REQUEST_REJECTED) can be sent again.
        this.used = true;
    }

    void startReading(String name) {
        reader.start(name);
    }

    @Override
    boolean multiplexed() {
        return true;
    }

    /** Whether the server allows extended CONNECT, as its SETTINGS (waited for briefly) say. */
    @Override
    boolean supportsWebSockets() {
        try {
            return connection.awaitPeerSettings(connection.options.upstreamHandshakeTimeout().toNanos())
                    .enableConnectProtocol();
        } catch (java.io.InterruptedIOException e) {
            return false;
        }
    }

    // ---------------------------------------------------------------------------------------
    // The request
    // ---------------------------------------------------------------------------------------

    @Override
    void writeRequestHead(HttpRequest request, boolean bodyFollows, boolean trailersAccepted) throws IOException {
        if (ProxyUtils.isCONNECT(request)) throw new IOException("CONNECT is not sent to servers over HTTP/3");
        sentEarly = connection.quic.isZeroRtt() && !request.headers().contains(Http3Connection.EARLY_DATA);
        var fields = Http3Messages.requestFields(request, hostAndPort, trailersAccepted);
        io.github.mahmoudimus.http3.Http3ClientProfile profile = connection.profile;
        if (profile != null) {
            fields = new java.util.ArrayList<>(profile.order(fields));
            String priority = request.headers().get("priority");
            if (priority != null && profile.priorityUpdates()) connection.sendPriorityUpdate(id, priority);
        }
        webSocket = ProxyUtils.isSwitchingToWebSocketProtocol(request);
        if (webSocket) {
            if (!supportsWebSockets()) throw new IOException("the server has not enabled extended CONNECT");
            webSocketKey = request.headers().get("Sec-WebSocket-Key");
            fields.set(0, new io.github.mahmoudimus.http3.HeaderField(":method", "CONNECT"));
            fields.add(1, new io.github.mahmoudimus.http3.HeaderField(":protocol", "websocket"));
            fields.removeIf(f -> f.name().equals("sec-websocket-key") || f.name().equals("sec-websocket-accept")
                    || f.name().equals("content-length"));
            try {
                writer.headers(fields, false);
                writer.flush();
            } catch (IOException e) {
                throw translate(e);
            }
            return;
        }
        try {
            if (request instanceof FullHttpRequest full) {
                byte[] content = full.content();
                HttpHeaders trailers = full.trailingHeaders();
                writer.headers(fields, content.length == 0 && trailers.isEmpty());
                if (content.length > 0) writer.data(content, 0, content.length, trailers.isEmpty());
                if (!trailers.isEmpty()) writer.headers(Http3Messages.trailerFields(trailers), true);
                return;
            }
            writer.headers(fields, !bodyFollows);
        } catch (IOException e) {
            throw translate(e);
        }
    }

    @Override
    void writeContent(HttpContent content) throws IOException {
        byte[] data = content.content();
        try {
            if (content instanceof LastHttpContent last) {
                HttpHeaders trailers = last.trailingHeaders();
                if (trailers.isEmpty()) {
                    writer.data(data, 0, data.length, true);
                    return;
                }
                if (data.length > 0) writer.data(data, 0, data.length, false);
                writer.headers(Http3Messages.trailerFields(trailers), true);
            } else if (data.length > 0) {
                writer.data(data, 0, data.length, false);
            }
        } catch (IOException e) {
            throw translate(e);
        }
    }

    @Override
    void writeData(byte[] data, int off, int len) throws IOException {
        try {
            if (len > 0) writer.data(data, off, len, false);
        } catch (IOException e) {
            throw translate(e);
        }
    }

    @Override
    void flush() throws IOException {
        writer.flush();
    }

    @Override
    void writeEnd(HttpHeaders trailers) throws IOException {
        try {
            if (trailers != null && !trailers.isEmpty()) {
                writer.headers(Http3Messages.trailerFields(trailers), true);
            } else {
                writer.end();
            }
        } catch (IOException e) {
            throw translate(e);
        }
    }

    // ---------------------------------------------------------------------------------------
    // The response
    // ---------------------------------------------------------------------------------------

    @Override
    boolean awaitResponse(int millis) throws IOException {
        try {
            return reader.awaitHead(TimeUnit.MILLISECONDS.toNanos(millis));
        } catch (IOException e) {
            throw translate(e);
        }
    }

    @Override
    boolean awaitResponseHead() throws IOException {
        try {
            if (!reader.awaitHead(connection.readTimeoutNanos())) {
                throw connection.timedOut("response from the server");
            }
            return true;
        } catch (IOException e) {
            throw translate(e);
        }
    }

    @Override
    HttpResponse readResponse(HttpCodec.Limits limits) throws IOException {
        Http3StreamReader.Head head = reader.takeHead();
        if (head == null) throw new IOException("no response head on stream " + id);
        ResponseHeaders response;
        try {
            response = Http3Headers.toResponse(id, head.fields());
            if (response.status() == 101) throw Http3Exception.streamError(id, Http3ErrorCode.H3_MESSAGE_ERROR, "101 in HTTP/3");
        } catch (Http3Exception e) {
            writer.reset(e.errorCode());
            reader.abort(e.errorCode());
            throw e;
        }
        if (response.status() == 425 && sentEarly) {
            // The server wants it after the handshake, which is complete once its answer is read
            writer.reset(Http3ErrorCode.H3_REQUEST_CANCELLED);
            reader.abort(Http3ErrorCode.H3_REQUEST_CANCELLED);
            throw new Http3UpstreamConnection.Unprocessed("425 Too Early from " + hostAndPort + " for 0-RTT data");
        }
        boolean bodyless = headRequest || response.status() == 204 || response.status() == 304;
        if (webSocket && response.status() / 100 == 2) {
            // The server accepted the WebSocket: the exchange logic sees an HTTP/1.1 server's 101.
            tunnelStatus = response.status();
            HttpResponse switching = Http3Messages.toHttp1(response, false, true);
            switching.setStatus(HttpResponseStatus.valueOf(101));
            switching.headers().remove(HttpHeaderNames.TRANSFER_ENCODING);
            switching.headers().remove(HttpHeaderNames.CONTENT_LENGTH);
            switching.headers().set(HttpHeaderNames.CONNECTION, "Upgrade");
            switching.headers().set(HttpHeaderNames.UPGRADE, "websocket");
            if (webSocketKey != null) switching.headers().set("Sec-WebSocket-Accept", WebSocketHandshake.accept(webSocketKey));
            return switching;
        }
        return Http3Messages.toHttp1(response, reader.endsHere(), bodyless);
    }

    @Override
    int responseStatus(HttpResponse response) {
        return tunnelStatus != 0 ? tunnelStatus : super.responseStatus(response);
    }

    @Override
    MessageBody responseBody(Framing framing, HttpCodec.Limits limits) {
        MessageBody body = reader.body();
        return new MessageBody() {
            @Override
            public boolean hasBody() {
                return body.hasBody();
            }

            @Override
            public long declaredLength() {
                return body.declaredLength();
            }

            @Override
            public boolean isDone() {
                return body.isDone();
            }

            @Override
            public HttpContent next() throws IOException {
                try {
                    return body.next();
                } catch (IOException e) {
                    throw translate(e);
                }
            }

            @Override
            public int read(byte[] dst, int off, int len) throws IOException {
                try {
                    return body.read(dst, off, len);
                } catch (IOException e) {
                    throw translate(e);
                }
            }

            @Override
            public HttpHeaders trailers() {
                return body.trailers();
            }

            @Override
            public boolean hasBufferedInput() {
                return body.hasBufferedInput();
            }
        };
    }

    @Override
    void exchangeDone() {
        // Nothing buffered for the next exchange: the stream carries only this one.
    }

    /** An accepted WebSocket's bytes from the server: the stream's DATA. */
    @Override
    InputStream tunnelInput() {
        InputStream in = reader.body().asInputStream();
        return new InputStream() {
            @Override
            public int read() throws IOException {
                try {
                    return in.read();
                } catch (IOException e) {
                    throw translate(e);
                }
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                try {
                    return in.read(b, off, len);
                } catch (IOException e) {
                    throw translate(e);
                }
            }

            @Override
            public int available() throws IOException {
                return in.available();
            }
        };
    }

    /** An accepted WebSocket's bytes to the server, as DATA frames. */
    @Override
    OutputStream tunnelOutput() {
        return new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                write(new byte[] {(byte) b}, 0, 1);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                if (len == 0) return;
                if (writer.ended()) throw new java.net.SocketException("the stream's output has ended");
                writeData(b, off, len);
            }

            @Override
            public void flush() throws IOException {
                writer.flush();
            }

            @Override
            public void close() throws IOException {
                endTunnelOutput();
            }
        };
    }

    /** Ends an accepted WebSocket's output: the stream's FIN. */
    @Override
    void endTunnelOutput() throws IOException {
        try {
            writer.end();
        } catch (IOException e) {
            throw translate(e);
        }
    }

    /** QUIC's failures as the exchange logic understands them. */
    private IOException translate(IOException e) {
        if (e instanceof QuicStreamException q && q.errorCode() == Http3ErrorCode.H3_REQUEST_REJECTED.code()) {
            return new Http3UpstreamConnection.Unprocessed("stream " + id + " rejected by " + hostAndPort);
        }
        if (e instanceof QuicConnectionException q && q.error().kind() == ConnectionError.Kind.TIMED_OUT) {
            return new SocketTimeoutException("the HTTP/3 connection to " + hostAndPort + " timed out");
        }
        return e;
    }

    @Override
    boolean retryable(IOException e) {
        return e instanceof Http3UpstreamConnection.Unprocessed;
    }

    @Override
    boolean isOpen() {
        return !done.get() && !connection.closed;
    }

    // ---------------------------------------------------------------------------------------
    // Ending
    // ---------------------------------------------------------------------------------------

    /** Ends the stream, resetting what is still open of it; the connection stays. */
    @Override
    void close() {
        if (!done.compareAndSet(false, true)) return;
        if (!writer.ended()) writer.reset(Http3ErrorCode.H3_REQUEST_CANCELLED);
        if (!reader.ended()) reader.abort(Http3ErrorCode.H3_REQUEST_CANCELLED);
        connection.streamDone(this);
    }

    /** The server's GOAWAY left this stream unprocessed: the exchange may send its request again. */
    void unprocessed(String why) {
        reader.failWith(new Http3UpstreamConnection.Unprocessed(why));
        writer.reset(Http3ErrorCode.H3_REQUEST_CANCELLED);
    }

    /** The connection ended under the stream. */
    void connectionClosed(IOException cause) {
        reader.failWith(cause);
    }

    /** Abandons a stream that carried nothing yet. */
    void abandon() {
        done.set(true);
        writer.reset(Http3ErrorCode.H3_REQUEST_CANCELLED);
        try {
            stream.stopSending(Http3ErrorCode.H3_REQUEST_CANCELLED.code());
        } catch (IOException | RuntimeException e) {
            // gone already
        }
    }

    @Override
    public String toString() {
        return "Http3UpstreamStream[" + hostAndPort + " stream " + id + "]";
    }

    /** The log prefix of the exchange the stream carries. */
    String logPrefix() {
        return logPrefix;
    }
}
