package org.microproxy.impl;

import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3ErrorCode;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketException;
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
 * Transfer-Encoding}). A {@code 100 Continue} is sent only to a client that asked for it; other
 * interim responses are forwarded as interim HEADERS.
 *
 * <p>Tunnels (RFC 9114 section 4.4, RFC 9220): a {@code CONNECT}'s 2xx, or the {@code 101} that
 * accepts an extended {@code CONNECT} (a WebSocket), goes out as HEADERS {@code 200} and leaves the
 * stream open; from then on its DATA carry the tunnel's bytes both ways, through the shared {@link
 * Tunnel} relay, and the stream's FIN half-closes one direction. {@link #tunnelSocket} shows the
 * stream as a socket, for an intercepted {@code CONNECT}'s TLS. A reset ends the tunnel; the proxy
 * resets the stream with H3_CONNECT_ERROR when its connection to the server fails.
 */
final class Http3StreamChannel implements ClientChannel, StreamSocket.Stream, UdpFlow.Client {

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
    /** An extended {@code CONNECT}'s {@code :protocol} ({@code websocket}), or null. */
    private volatile String protocol;
    /** The {@code :scheme} of an extended {@code CONNECT}. */
    private volatile String scheme;
    /**
     * The response that opens a tunnel has been sent: a reset from now on is how a client ends
     * the tunnel, not a request it gave up on.
     */
    volatile boolean tunnelOpen;

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
        requestRead(request, null, null);
    }

    /** The request's head has been read; {@code protocol} and {@code scheme} are an extended {@code CONNECT}'s. */
    void requestRead(HttpRequest request, String protocol, String scheme) {
        this.request = request;
        this.protocol = protocol;
        this.scheme = scheme;
        this.expectsContinue = HttpUtil.is100ContinueExpected(request);
    }

    /** Whether the whole response has been sent (not reset). */
    boolean responseEnded() {
        return writer.finished();
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
        return true;
    }

    @Override
    public String tunnelProtocol() {
        return protocol;
    }

    @Override
    public boolean secureWebSocket() {
        return "websocket".equals(protocol) && "https".equalsIgnoreCase(scheme);
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
        // HTTP/3 has no protocol switch: writeHead turns the 101 of an extended CONNECT into a 200.
        // Until then, filters see the 101 as an HTTP/1.1 client's upgrade would show it.
        if (protocol != null) {
            if (upgrade != null) response.headers().set(HttpHeaderNames.UPGRADE, upgrade);
            response.headers().set(HttpHeaderNames.CONNECTION, "Upgrade");
        }
    }

    @Override
    public void writeHead(HttpResponse response, boolean bodyAllowed) throws IOException {
        int code = response.status().code();
        HttpRequest req = request;
        if (protocol != null ? code == 101 : code / 100 == 2 && req != null && ProxyUtils.isCONNECT(req)) {
            // The response opens a tunnel: HEADERS :status 200, and the stream stays open. DATA are
            // tunnel bytes, not a message body. The 101 itself stays as filters and trackers saw it.
            HttpHeaders headers = response.headers().copy();
            headers.remove("Sec-WebSocket-Accept");
            headers.remove(HttpHeaderNames.CONTENT_LENGTH);
            headers.remove(HttpHeaderNames.TRANSFER_ENCODING);
            this.bodyAllowed = true;
            headersSent = true;
            // Before the HEADERS go out: the client may reset the stream as soon as it reads them.
            tunnelOpen = true;
            writer.headers(Http3Messages.responseFields(code == 101 ? 200 : code, headers), false);
            writer.flush();
            return;
        }
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
    public void relay(ServerConnection conn, WebSocketRelay webSocket, TcpSession tcp, ClientFlowContext counted,
            String name) {
        Tunnel.relay(reader.body().asInputStream(), new TunnelOutput(), this::endTunnelOutput,
                conn.tunnelInput(), conn.tunnelOutput(), conn::endTunnelOutput,
                () -> { closeTunnelStream(); conn.close(); }, connection.server.getIdleConnectionTimeout(), name,
                logPrefix, webSocket, tcp, connection.server.ioBuffers, counted);
    }

    /**
     * The tunnel ended: a stream whose both directions finished is complete; otherwise the server
     * side failed (or the client reset it), and what is left of the stream is reset: with
     * H3_CONNECT_ERROR for a {@code CONNECT} (RFC 9114 section 4.4), with H3_REQUEST_CANCELLED for
     * a WebSocket (RFC 9220 section 3, as RFC 8441's CANCEL).
     */
    private void closeTunnelStream() {
        if (writer.finished() && reader.ended()) return;
        resetStream(protocol == null ? Http3ErrorCode.H3_CONNECT_ERROR : Http3ErrorCode.H3_REQUEST_CANCELLED);
    }

    /**
     * The stream as a connected socket, for a TLS session layered over it (an intercepted {@code
     * CONNECT}): its streams are the tunnel's bytes, {@code shutdownOutput} sends the FIN, and
     * {@code close} ends the output and fails reads, as closing a TCP socket does. Null until the
     * tunnel is open.
     */
    @Override
    public StreamSocket tunnelSocket() {
        if (!tunnelOpen) return null;
        return new StreamSocket(this, reader.body().asInputStream(), new TunnelOutput(), flow.getClientAddress(),
                connection.quic.localAddress());
    }

    @Override
    public void setReadTimeout(int millis) {
        reader.setReadTimeout(millis);
    }

    @Override
    public int readTimeout() {
        return reader.readTimeout();
    }

    @Override
    public void endTunnelOutput() throws IOException {
        writer.end();
    }

    /**
     * Closes the stream as a socket is closed: reads fail from now on, and the output ends with
     * the FIN, or, if a write is in progress on another thread, the stream is reset.
     */
    @Override
    public void closeTunnel() {
        reader.closeInput();
        writer.endOrReset(Http3ErrorCode.H3_CONNECT_ERROR);
        // The client need not send what nobody reads.
        if (!reader.ended()) reader.abort(Http3ErrorCode.H3_NO_ERROR);
    }

    // ---------------------------------------------------------------------------------------
    // CONNECT-UDP (RFC 9298): the stream's capsules, and the connection's HTTP Datagrams
    // ---------------------------------------------------------------------------------------

    /** The stream as a CONNECT-UDP flow's client: on a forward proxy's listener, for {@code :protocol connect-udp}. */
    @Override
    public UdpFlow.Client udpClient() {
        return "connect-udp".equals(protocol) && connection.role == Http3Connection.Role.FORWARD ? this : null;
    }

    @Override
    public boolean attach(UdpFlow flow) {
        return connection.addUdpFlow(id, flow);
    }

    @Override
    public void detach(UdpFlow flow) {
        connection.removeUdpFlow(id, flow);
    }

    @Override
    public void releaseEnded() {
        connection.releaseEndedFlows();
    }

    @Override
    public InputStream capsules() {
        return reader.body().asInputStream();
    }

    @Override
    public boolean sendDatagram(byte[] content) throws IOException {
        if (connection.sendHttpDatagram(id, content)) return false;
        // No QUIC datagrams to this client (or too large for one): a DATAGRAM capsule on the stream.
        byte[] capsule = UdpFlow.datagramCapsule(content);
        if (writer.ended()) throw new SocketException("the stream's output has ended");
        writer.data(capsule, 0, capsule.length, false);
        writer.flush();
        return true;
    }

    @Override
    public void endFlow(boolean clean) {
        if (clean) {
            writer.endOrReset(Http3ErrorCode.H3_CONNECT_ERROR);
            if (!reader.ended()) reader.abort(Http3ErrorCode.H3_NO_ERROR);
        } else {
            resetStream(Http3ErrorCode.H3_CONNECT_ERROR);
        }
    }

    /** The tunnel's bytes to the client, in DATA frames that wait for QUIC's flow control. */
    private final class TunnelOutput extends OutputStream {
        @Override
        public void write(int b) throws IOException {
            write(new byte[] {(byte) b}, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (len == 0) return;
            if (writer.ended()) throw new SocketException("the stream's output has ended");
            writer.data(b, off, len, false);
        }

        @Override
        public void flush() throws IOException {
            writer.flush();
        }

        @Override
        public void close() throws IOException {
            endTunnelOutput();
        }
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
