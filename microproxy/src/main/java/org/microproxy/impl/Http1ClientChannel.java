package org.microproxy.impl;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.microproxy.http.DefaultHttpResponse;
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
 * The client side of an HTTP/1.x connection: a {@link ClientChannel} for each of the exchanges
 * the connection carries, one after another, over {@link ByteReader}, {@link HttpCodec} and
 * {@link PooledOutputStream}.
 *
 * <p>Besides the channel operations, it reads request heads ({@link #awaitRequest}, {@link
 * #readRequest}), which is how pipelining works: unread pipelined requests simply wait in the
 * buffer. It also turns the connection into TLS ({@link #startTls}), for the TLS listener and for
 * intercepted {@code CONNECT}s. The connection loop in {@link ClientConnection} drives those.
 */
final class Http1ClientChannel implements ClientChannel {

    private final DefaultHttpProxyServer server;
    private final ClientFlowContext flowContext;
    private final String logPrefix;
    /** Closes the whole client connection (and gives up its server connections). */
    private final Runnable closeConnection;

    /** The socket requests arrive on: the accepted one, or the TLS socket layered over it. */
    private volatile Socket socket;
    private ByteReader in;
    private OutputStream out;
    private HttpCodec.HttpWriter writer;
    /**
     * The version of the request being served: HTTP/1.0 clients get no interim responses and no
     * chunked bodies.
     */
    private HttpVersion requestVersion = HttpVersion.HTTP_1_1;

    Http1ClientChannel(DefaultHttpProxyServer server, Socket socket, ClientFlowContext flowContext, String logPrefix,
            Runnable closeConnection) {
        this.server = server;
        this.socket = socket;
        this.flowContext = flowContext;
        this.logPrefix = logPrefix;
        this.closeConnection = closeConnection;
    }

    // ---------------------------------------------------------------------------------------
    // The connection
    // ---------------------------------------------------------------------------------------

    /** Reads and writes through {@code s} from now on (the accepted socket, or TLS over it). */
    void attach(Socket s) throws IOException {
        socket = s;
        InputStream is = s.getInputStream();
        OutputStream os = s.getOutputStream();
        if (!server.trackers.isEmpty()) {
            is = CountingStreams.counting(is, n -> server.trackers.fire(t -> t.bytesReceivedFromClient(flowContext, n)));
            os = CountingStreams.counting(os, n -> server.trackers.fire(t -> t.bytesSentToClient(flowContext, n)));
        }
        in = new ByteReader(is, server.ioBuffers).strictLineEndings();
        out = new PooledOutputStream(os, server.ioBuffers);
        writer = new HttpCodec.HttpWriter(out);
    }

    /** Reads the PROXY protocol header that starts the connection. */
    ProxyProtocol.Header readProxyHeader() throws IOException {
        return ProxyProtocol.read(in);
    }

    /**
     * Runs a TLS handshake as the server on the current socket, bytes the client already sent
     * included, and reads and writes through TLS from then on.
     */
    SSLSocket startTls(SSLContext context, boolean needClientAuth, Consumer<SSLSocket> configurer, TlsLog.Peer peer)
            throws IOException {
        SSLSocket tls = Tls.serverHandshake(context, socket, in.drainBuffered(), needClientAuth, server.tlsProtocols,
                configurer, server.tlsHandshakeTimeout, peer);
        attach(tls);
        return tls;
    }

    /**
     * Waits for the next request without holding a buffer, so idle connections are cheap.
     *
     * @return whether bytes arrived (false at end of stream)
     */
    boolean awaitRequest() throws IOException {
        in.awaitNext();
        return in.buffered() > 0;
    }

    /**
     * Whether the connection starts with the HTTP/2 connection preface (prior knowledge, {@code
     * h2c}); nothing is consumed, and an HTTP/1 request is told apart by its first bytes.
     */
    boolean startsWithHttp2Preface() throws IOException {
        return in.startsWith(HTTP2_PREFACE);
    }

    /** The bytes received and not yet read: what an HTTP/2 connection taking over starts with. */
    byte[] drainBuffered() {
        return in.drainBuffered();
    }

    /** The HTTP/2 client connection preface (RFC 9113 section 3.4). */
    private static final byte[] HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.US_ASCII);

    /**
     * Reads a request head.
     *
     * @return the request, or {@code null} if the client closed the connection cleanly instead
     */
    HttpRequest readRequest() throws IOException {
        return HttpCodec.readRequest(in, server.limits);
    }

    /** Closes the socket; {@link #close()} closes the whole client connection. */
    void closeSocket() {
        Tls.closeQuietly(socket);
    }

    // ---------------------------------------------------------------------------------------
    // ClientChannel
    // ---------------------------------------------------------------------------------------

    @Override
    public ClientFlowContext flowContext() {
        return flowContext;
    }

    @Override
    public String logPrefix() {
        return logPrefix;
    }

    @Override
    public boolean multiplexed() {
        return false;
    }

    @Override
    public boolean supportsTunnels() {
        return true;
    }

    @Override
    public void serverConnectionInUse(ServerConnection server) {
        // A client that goes away is seen when the response is written to it.
    }

    @Override
    public boolean serverConnectionDone(ServerConnection server) {
        return true;
    }

    @Override
    public MessageBody requestBody(HttpRequest request) throws HttpParseException {
        requestVersion = request.protocolVersion();
        return new HttpCodec.BodyReader(in, Framing.forRequest(request), server.limits);
    }

    @Override
    public boolean clientKeepAlive(HttpRequest request) {
        return ProxyUtils.isClientKeepAlive(request);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Bytes the client sends meanwhile (a request body, a pipelined request) stay buffered for
     * later; once some have arrived, the close can no longer be seen and the rest of the wait is a
     * plain sleep.
     */
    @Override
    public void awaitUnlessClientLeaves(long deadline) throws IOException {
        Socket client = socket;
        int original = client.getSoTimeout();
        try {
            while (true) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) return;
                if (in.buffered() > 0) {
                    Thread.sleep(Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining)));
                    return;
                }
                client.setSoTimeout((int) Math.max(1, Math.min(Integer.MAX_VALUE,
                        TimeUnit.NANOSECONDS.toMillis(remaining + 999_999))));
                if (in.awaitData() && in.buffered() == 0) {
                    throw new ClientConnection.ClientFailure(new EOFException("client disconnected while waiting to retry"));
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted while waiting to retry");
        } catch (ClientConnection.ClientFailure e) {
            throw e;
        } catch (IOException e) {
            throw new ClientConnection.ClientFailure(e);
        } finally {
            if (!client.isClosed()) {
                try {
                    client.setSoTimeout(original);
                } catch (IOException ignored) {
                    // the connection is failing anyway
                }
            }
        }
    }

    @Override
    public void writeContinue() throws IOException {
        writer.writeHead(new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.CONTINUE), false);
    }

    @Override
    public void writeInformational(HttpResponse response) throws IOException {
        if (requestVersion.isKeepAliveDefault()) {
            writer.writeHead(response, false);
        }
    }

    @Override
    public boolean adaptFraming(HttpResponse response, boolean streamed) {
        boolean close = false;
        if (streamed) {
            boolean clientSupportsChunked = requestVersion.isKeepAliveDefault();
            if (!ProxyUtils.isResponseSelfTerminating(response)) {
                // The server ends the body by closing. Re-chunk so the client connection survives.
                if (clientSupportsChunked) {
                    HttpUtil.setTransferEncodingChunked(response, true);
                } else {
                    close = true;
                }
            } else if (!clientSupportsChunked && HttpUtil.isTransferEncodingChunked(response)) {
                // HTTP/1.0 clients cannot parse chunked bodies: de-chunk and delimit by closing.
                HttpUtil.setTransferEncodingChunked(response, false);
                close = true;
            }
        }
        if (HttpUtil.isTransferEncodingChunked(response) && !response.protocolVersion().isKeepAliveDefault()) {
            response.setProtocolVersion(HttpVersion.HTTP_1_1);
        }
        return close;
    }

    @Override
    public void setKeepAlive(HttpResponse response, boolean keepAlive) {
        HttpUtil.setKeepAlive(response, keepAlive);
    }

    @Override
    public void setUpgrade(HttpResponse response, String upgrade) {
        if (upgrade != null) response.headers().set(HttpHeaderNames.UPGRADE, upgrade);
        response.headers().set(HttpHeaderNames.CONNECTION, "Upgrade");
    }

    @Override
    public void writeHead(HttpResponse response, boolean bodyAllowed) throws IOException {
        hop(response);
        writer.writeHead(response, bodyAllowed);
    }

    /** A response from an HTTP/2 server goes to an HTTP/1 client with this hop's version, 1.1. */
    private static void hop(HttpResponse response) {
        if (response.protocolVersion().majorVersion() >= 2) response.setProtocolVersion(HttpVersion.HTTP_1_1);
    }

    @Override
    public void writeComplete(HttpResponse response, boolean bodyAllowed) throws IOException {
        hop(response);
        boolean bare = !(response instanceof FullHttpMessage);
        if (bare && bodyAllowed && !ProxyUtils.isResponseSelfTerminating(response)) {
            HttpUtil.setContentLength(response, 0);
        }
        writer.writeHead(response, bodyAllowed);
        if (bare && bodyAllowed && HttpUtil.isTransferEncodingChunked(response)) {
            writer.writeContent(LastHttpContent.empty());
        }
    }

    @Override
    public void writeContent(HttpContent content) throws IOException {
        writer.writeContent(content);
    }

    @Override
    public void writeData(byte[] data, int off, int len) throws IOException {
        writer.writeData(data, off, len);
    }

    @Override
    public void flush() throws IOException {
        writer.flush();
    }

    @Override
    public void writeEnd(HttpHeaders trailers) throws IOException {
        writer.writeEnd(trailers);
    }

    @Override
    public void relay(ServerConnection conn, Tunnel.FrameHandler frames, String name) {
        Tunnel.relay(in.asInputStream(), out, () -> Tunnel.halfClose(socket),
                conn.tunnelInput(), conn.tunnelOutput(), conn::endTunnelOutput,
                () -> { close(); conn.close(); },
                server.getIdleConnectionTimeout(), name, logPrefix, frames, server.maxWebSocketFrameBufferSize,
                server.ioBuffers);
    }

    @Override
    public void reject(HttpResponseStatus status) {
        FullHttpResponse response = ProxyUtils.createFullHttpResponse(HttpVersion.HTTP_1_1, status, status.reasonPhrase());
        HttpUtil.setKeepAlive(response, false);
        try {
            writer.writeHead(response, true);
        } catch (IOException ignored) {
            // closing anyway
        }
        close();
    }

    @Override
    public void close() {
        closeConnection.run();
    }
}
