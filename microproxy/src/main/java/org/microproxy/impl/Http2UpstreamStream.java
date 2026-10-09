package org.microproxy.impl;

import io.github.mahmoudimus.http2.HeaderField;
import io.github.mahmoudimus.http2.Http2Headers;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.microproxy.FullFlowContext;
import org.microproxy.http.FullHttpRequest;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.LastHttpContent;

/**
 * One exchange's stream on an {@link Http2UpstreamConnection}, as the exchange logic sees server
 * connections: the request head becomes a HEADERS frame (pseudo-headers from the request line and
 * {@code Host}, without HTTP/1's connection-specific fields), its body DATA frames and its
 * trailers a final HEADERS frame; responses arrive as HTTP/1-style messages ({@link
 * Http2UpstreamConnection}). It is never pooled or kept: {@link #close()} ends the stream (with
 * {@code RST_STREAM CANCEL} if it is still open) and leaves the connection to other streams.
 */
final class Http2UpstreamStream extends ServerConnection {

    private final Http2UpstreamConnection connection;
    private final Http2UpstreamConnection.StreamState state;
    private final String logPrefix;
    private String webSocketKey;
    private boolean webSocket;
    private int tunnelStatus;

    Http2UpstreamStream(Http2UpstreamConnection connection, Http2UpstreamConnection.StreamState state,
            FullFlowContext flowContext, Trackers trackers) {
        super(connection.carrier.hostAndPort, connection.carrier.chainedProxy, connection.carrier.socket,
                connection.carrier.remoteAddress, flowContext, trackers);
        this.connection = connection;
        this.state = state;
        this.logPrefix = state.logPrefix;
        // A stream is a reused connection as far as retries go: one the server never processed
        // (GOAWAY, REFUSED_STREAM) can be sent again.
        this.used = true;
    }

    @Override
    boolean multiplexed() {
        return true;
    }

    @Override
    boolean supportsWebSockets() {
        connection.stateLock.lock();
        try {
            return connection.peerSettings.enableConnectProtocol();
        } finally {
            connection.stateLock.unlock();
        }
    }

    @Override
    void writeRequestHead(HttpRequest request, boolean bodyFollows, boolean trailersAccepted) throws IOException {
        List<HeaderField> fields = requestFields(request, hostAndPort, trailersAccepted);
        webSocket = ProxyUtils.isSwitchingToWebSocketProtocol(request);
        if (webSocket) {
            if (!supportsWebSockets()) throw new IOException("origin has not enabled extended CONNECT");
            webSocketKey = request.headers().get("Sec-WebSocket-Key");
            fields.set(0, new HeaderField(":method", "CONNECT"));
            fields.add(1, new HeaderField(":protocol", "websocket"));
            fields.removeIf(f -> f.name().equals("sec-websocket-key") || f.name().equals("sec-websocket-accept")
                    || f.name().equals("content-length"));
            connection.open(state, fields, false);
            return;
        }
        if (request instanceof FullHttpRequest full) {
            byte[] content = full.content();
            HttpHeaders trailers = full.trailingHeaders();
            connection.open(state, fields, content.length == 0 && trailers.isEmpty());
            if (content.length > 0) connection.send(state, content, 0, content.length, trailers.isEmpty(), true);
            if (!trailers.isEmpty()) connection.sendTrailers(state, trailerFields(trailers));
            return;
        }
        connection.open(state, fields, !bodyFollows);
    }

    @Override
    void writeContent(HttpContent content) throws IOException {
        byte[] data = content.content();
        if (content instanceof LastHttpContent last) {
            HttpHeaders trailers = last.trailingHeaders();
            if (trailers.isEmpty()) {
                connection.send(state, data, 0, data.length, true, true);
                return;
            }
            if (data.length > 0) connection.send(state, data, 0, data.length, false, false);
            connection.sendTrailers(state, trailerFields(trailers));
        } else if (data.length > 0) {
            connection.send(state, data, 0, data.length, false, true);
        }
    }

    @Override
    void writeData(byte[] data, int off, int len) throws IOException {
        if (len > 0) connection.send(state, data, off, len, false, false);
    }

    @Override
    void flush() throws IOException {
        connection.flush();
    }

    @Override
    void writeEnd(HttpHeaders trailers) throws IOException {
        if (trailers != null && !trailers.isEmpty()) {
            connection.sendTrailers(state, trailerFields(trailers));
        } else {
            connection.send(state, Http2Endpoint.EMPTY, 0, 0, true, true);
        }
    }

    @Override
    boolean awaitResponse(int millis) throws IOException {
        return connection.awaitHead(state, TimeUnit.MILLISECONDS.toNanos(millis));
    }

    @Override
    boolean awaitResponseHead() throws IOException {
        int idle = connection.server.idleTimeoutMillis();
        long nanos = idle > 0 ? TimeUnit.MILLISECONDS.toNanos(idle) : Long.MAX_VALUE;
        if (!connection.awaitHead(state, nanos)) {
            throw new SocketTimeoutException("no response from the server for " + idle + " ms");
        }
        return true;
    }

    @Override
    HttpResponse readResponse(HttpCodec.Limits limits) throws IOException {
        HttpResponse response = connection.takeHead(state);
        if (webSocket && response.status().code() / 100 == 2) {
            tunnelStatus = response.status().code();
            response.setStatus(HttpResponseStatus.valueOf(101));
            response.headers().remove(HttpHeaderNames.TRANSFER_ENCODING);
            response.headers().remove(HttpHeaderNames.CONTENT_LENGTH);
            response.headers().set(HttpHeaderNames.CONNECTION, "Upgrade");
            response.headers().set(HttpHeaderNames.UPGRADE, "websocket");
            if (webSocketKey != null) response.headers().set("Sec-WebSocket-Accept", WebSocketHandshake.accept(webSocketKey));
        }
        return response;
    }

    @Override
    int responseStatus(HttpResponse response) {
        return tunnelStatus != 0 ? tunnelStatus : super.responseStatus(response);
    }

    @Override
    MessageBody responseBody(Framing framing, HttpCodec.Limits limits) {
        return connection.body(state);
    }

    @Override
    void exchangeDone() {
        // Nothing buffered for the next exchange: the stream carries only this one.
    }

    @Override
    InputStream tunnelInput() {
        return connection.body(state).asInputStream();
    }

    @Override
    OutputStream tunnelOutput() {
        return new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                write(new byte[] {(byte) b}, 0, 1);
            }

            @Override
            public void write(byte[] bytes, int off, int len) throws IOException {
                writeData(bytes, off, len);
            }

            @Override
            public void flush() throws IOException {
                Http2UpstreamStream.this.flush();
            }
        };
    }

    @Override
    void endTunnelOutput() throws IOException {
        writeEnd(new HttpHeaders());
    }

    @Override
    boolean retryable(IOException e) {
        return e instanceof Http2UpstreamConnection.Unprocessed;
    }

    @Override
    boolean isOpen() {
        return !connection.isClosed() && !state.rstWritten;
    }

    /** Ends the stream, resetting it if it is still open either way; the connection stays. */
    @Override
    void close() {
        connection.cancel(state);
    }

    @Override
    public String toString() {
        return "Http2UpstreamStream[" + hostAndPort + " stream " + state.id + "]";
    }

    /** The log prefix of the exchange the stream carries. */
    String logPrefix() {
        return logPrefix;
    }

    // ---------------------------------------------------------------------------------------
    // Requests as HTTP/2 fields
    // ---------------------------------------------------------------------------------------

    /**
     * The header list for {@code request}: pseudo-headers ({@code :authority} from {@code Host},
     * else the target), then the fields with lower-case names, without connection-specific ones
     * or {@code host}, with {@code cookie} split into crumbs and {@code te} only as {@code
     * trailers} (added when the client accepts trailers: the proxy relays them). Fields HTTP/2
     * cannot carry are dropped.
     */
    static List<HeaderField> requestFields(HttpRequest request, String hostAndPort, boolean trailersAccepted) {
        String uri = request.uri();
        String path = ProxyUtils.isAbsoluteUri(uri) ? ProxyUtils.stripHost(uri) : uri;
        if (path.isEmpty()) path = "/";
        String authority = request.headers().get(HttpHeaderNames.HOST);
        if (authority == null || authority.isBlank()) authority = defaultPortless(hostAndPort);
        authority = authority.strip();
        String method = request.method().name();
        List<Map.Entry<String, String>> entries = request.headers().entries();
        List<HeaderField> fields;
        try {
            fields = Http2Headers.fromHttp1Request(method, "https", authority, path, entries);
        } catch (IllegalArgumentException e) {
            List<Map.Entry<String, String>> valid = new ArrayList<>(entries.size());
            for (Map.Entry<String, String> entry : entries) {
                try {
                    Http2Headers.fromHttp1Request(method, "https", authority, path, List.of(entry));
                    valid.add(entry);
                } catch (IllegalArgumentException invalid) {
                    // dropped
                }
            }
            fields = Http2Headers.fromHttp1Request(method, "https", authority, path, valid);
        }
        if (trailersAccepted && fields.stream().noneMatch(f -> f.name().equals("te"))) {
            fields.add(new HeaderField("te", "trailers"));
        }
        return fields;
    }

    private static String defaultPortless(String hostAndPort) {
        return hostAndPort.endsWith(":443") ? hostAndPort.substring(0, hostAndPort.length() - 4) : hostAndPort;
    }

    private static List<HeaderField> trailerFields(HttpHeaders trailers) {
        List<HeaderField> fields = Http2StreamChannel.responseFields(200, trailers);
        return fields.subList(1, fields.size());
    }
}
