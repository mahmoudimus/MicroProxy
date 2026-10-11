package org.microproxy.impl;

import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3ErrorCode;
import java.io.EOFException;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.microproxy.http.FullHttpMessage;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpUtil;
import org.microproxy.http.HttpVersion;
import org.microproxy.http.LastHttpContent;

/**
 * One HTTP/3 request stream as a {@link ClientChannel}: the client side of one exchange, run on the
 * stream's own thread while the connection's other streams run on theirs, as {@link
 * Http2StreamChannel} is for HTTP/2.
 *
 * <p>The request body is the stream's DATA frames, which its {@link Http3StreamReader} reads
 * ahead of the exchange by at most a small buffer, so QUIC's flow control holds the client back.
 * The response head becomes a HEADERS frame without HTTP/1's connection-specific fields, its body
 * DATA frames, its trailers a final HEADERS frame, and its end the end of the stream.
 *
 * <p>What has no meaning in HTTP/3: there is no connection to keep alive or close ({@link
 * #clientKeepAlive} is always true, {@link #setKeepAlive} does nothing, and {@link #close} resets
 * the stream), framing is the protocol's ({@link #adaptFraming} only drops {@code
 * Transfer-Encoding}). {@code CONNECT} and extended {@code CONNECT} are answered {@code 501}
 * before an exchange starts ({@link Http3Connection}), so the channel carries no tunnels. A {@code
 * 100 Continue} is sent only to a client that asked for it; other interim responses are forwarded
 * as interim HEADERS.
 */
final class Http3StreamChannel implements ClientChannel {

    private static final Object CANCELLED = new Object();

    final Http3Connection connection;
    final long id;
    final Http3StreamReader reader;
    final Http3MessageWriter writer;
    private final ClientFlowContext flow;
    private final String logPrefix;
    /** The request as the client sent it; set once its head has been read. */
    volatile HttpRequest request;
    private boolean expectsContinue;
    private final AtomicReference<Object> server = new AtomicReference<>();

    // The stream thread's own.
    private boolean headersSent;
    private boolean continueSent;
    private boolean bodyAllowed = true;

    Http3StreamChannel(Http3Connection connection, Http3StreamReader reader, Http3MessageWriter writer,
            ClientFlowContext flow) {
        this.connection = connection;
        this.reader = reader;
        this.writer = writer;
        this.id = reader.id;
        this.flow = flow;
        this.logPrefix = connection.logPrefix.substring(0, connection.logPrefix.length() - 2) + " stream " + id + "] ";
        reader.flow = flow;
        writer.flow = flow;
    }

    void requestRead(HttpRequest request) {
        this.request = request;
        this.expectsContinue = HttpUtil.is100ContinueExpected(request);
    }

    /** Whether the whole response has been sent. */
    boolean responseEnded() {
        return writer.ended();
    }

    /** The client cancelled the stream: the server connection in use, to close, or null. */
    ServerConnection cancelServer() {
        Object previous = server.getAndSet(CANCELLED);
        return previous instanceof ServerConnection c ? c : null;
    }

    private IOException failure() {
        return new ClientConnection.ClientFailure(new EOFException("stream " + id + " reset"));
    }

    // ---------------------------------------------------------------------------------------
    // ClientChannel
    // ---------------------------------------------------------------------------------------

    @Override
    public ClientFlowContext flowContext() {
        return flow;
    }

    @Override
    public String logPrefix() {
        return logPrefix;
    }

    @Override
    public boolean multiplexed() {
        return true;
    }

    @Override
    public boolean supportsTunnels() {
        return false;
    }

    @Override
    public void serverConnectionInUse(ServerConnection conn) throws IOException {
        while (true) {
            Object current = server.get();
            if (current == CANCELLED) throw failure();
            if (server.compareAndSet(current, conn)) return;
        }
    }

    @Override
    public boolean serverConnectionDone(ServerConnection conn) {
        return server.compareAndSet(conn, null) || server.get() != CANCELLED;
    }

    @Override
    public MessageBody requestBody(HttpRequest request) {
        return reader.body();
    }

    @Override
    public boolean clientKeepAlive(HttpRequest request) {
        return true;
    }

    @Override
    public void awaitUnlessClientLeaves(long deadline) throws IOException {
        IOException failed = reader.awaitFailure(deadline);
        if (failed != null) throw new ClientConnection.ClientFailure(failed);
    }

    @Override
    public void writeContinue() throws IOException {
        if (!expectsContinue || continueSent || headersSent) return;
        continueSent = true;
        writer.headers(List.of(new HeaderField(":status", "100")), false);
    }

    @Override
    public void writeInformational(HttpResponse response) throws IOException {
        int code = response.status().code();
        if (code == 100) {
            writeContinue();
        } else if (code > 101 && code < 200 && !headersSent) {
            // 102, 103 (Early Hints): interim HEADERS before the final response (RFC 9114 section 4.1).
            writer.headers(Http3Messages.responseFields(code, response.headers()), false);
        }
    }

    @Override
    public boolean adaptFraming(HttpResponse response, boolean streamed) {
        // DATA frames delimit the body, and the stream's end ends it.
        response.headers().remove(HttpHeaderNames.TRANSFER_ENCODING);
        return false;
    }

    @Override
    public void setKeepAlive(HttpResponse response, boolean keepAlive) {
        // No connection-specific fields in HTTP/3; the connection outlives every stream.
    }

    @Override
    public void setUpgrade(HttpResponse response, String upgrade) {
        // HTTP/3 has no protocol switch, and its channel carries no tunnels.
    }

    @Override
    public void writeHead(HttpResponse response, boolean bodyAllowed) throws IOException {
        if (response instanceof FullHttpMessage full) {
            writeFull(response, full, bodyAllowed);
            return;
        }
        // A declared empty body ends the stream with the head.
        this.bodyAllowed = bodyAllowed && !"0".equals(response.headers().get(HttpHeaderNames.CONTENT_LENGTH));
        sendHead(response, !this.bodyAllowed);
    }

    @Override
    public void writeComplete(HttpResponse response, boolean bodyAllowed) throws IOException {
        if (response instanceof FullHttpMessage full) {
            writeFull(response, full, bodyAllowed);
            return;
        }
        if (bodyAllowed && !response.headers().contains(HttpHeaderNames.CONTENT_LENGTH)) {
            HttpUtil.setContentLength(response, 0);
        }
        this.bodyAllowed = false;
        sendHead(response, true);
    }

    private void writeFull(HttpResponse response, FullHttpMessage full, boolean bodyAllowed) throws IOException {
        byte[] content = full.content();
        HttpHeaders trailing = full.trailingHeaders();
        if (bodyAllowed) {
            response.headers().remove(HttpHeaderNames.TRANSFER_ENCODING);
            HttpUtil.setContentLength(response, content.length);
        }
        this.bodyAllowed = false;
        if (!bodyAllowed || (content.length == 0 && trailing.isEmpty())) {
            sendHead(response, true);
            return;
        }
        sendHead(response, false);
        writer.data(content, 0, content.length, trailing.isEmpty());
        if (!trailing.isEmpty()) writer.headers(Http3Messages.trailerFields(trailing), true);
    }

    @Override
    public void writeContent(HttpContent content) throws IOException {
        if (!bodyAllowed || writer.ended()) return;
        byte[] data = content.content();
        boolean last = content instanceof LastHttpContent;
        HttpHeaders trailing = last ? ((LastHttpContent) content).trailingHeaders() : null;
        boolean endWithData = last && trailing.isEmpty();
        if (data.length > 0 || endWithData) writer.data(data, 0, data.length, endWithData);
        if (last && !trailing.isEmpty()) writer.headers(Http3Messages.trailerFields(trailing), true);
    }

    @Override
    public void writeData(byte[] data, int off, int len) throws IOException {
        if (!bodyAllowed || writer.ended() || len == 0) return;
        writer.data(data, off, len, false);
    }

    @Override
    public void flush() throws IOException {
        writer.flush();
    }

    @Override
    public void writeEnd(HttpHeaders trailing) throws IOException {
        if (!bodyAllowed || writer.ended()) return;
        if (trailing != null && !trailing.isEmpty()) {
            writer.headers(Http3Messages.trailerFields(trailing), true);
        } else {
            writer.end();
        }
    }

    @Override
    public void relay(ServerConnection conn, WebSocketRelay webSocket, TcpSession tcp, String name) {
        // Never reached: the channel supports no tunnels, so no exchange opens one on it.
        conn.close();
        close();
    }

    @Override
    public void reject(HttpResponseStatus status) {
        FullHttpResponse response = ProxyUtils.createFullHttpResponse(HttpVersion.HTTP_1_1, status, status.reasonPhrase());
        try {
            writeComplete(response, true);
        } catch (IOException ignored) {
            // the stream is reset below
        }
        close();
    }

    @Override
    public void close() {
        connection.closeStream(this);
    }

    private void sendHead(HttpResponse response, boolean end) throws IOException {
        int code = response.status().code();
        if (code == 101) throw new IOException("101 Switching Protocols is invalid in HTTP/3");
        headersSent = true;
        writer.headers(Http3Messages.responseFields(code, response.headers()), end);
    }

    /** Resets the stream both ways with {@code code}, as a stream error or a cancelled exchange does. */
    void resetStream(Http3ErrorCode code) {
        writer.reset(code);
        reader.abort(code);
    }
}
