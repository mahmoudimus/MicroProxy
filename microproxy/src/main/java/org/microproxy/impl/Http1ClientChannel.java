package org.microproxy.impl;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.ProtocolException;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
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
 * intercepted {@code CONNECT}s. The connection loop in {@link ClientConnection} drives those. After
 * an HTTP/1.1 CONNECT-UDP upgrade the connection carries the flow's capsules ({@link #udpClient}).
 */
final class Http1ClientChannel implements ClientChannel {

    /** How long a CONNECT-UDP flow's clean end waits for a capsule being written, before closing. */
    private static final long FLOW_END_WAIT_MILLIS = 250;

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
    /**
     * A request arrived with both {@code Transfer-Encoding} and {@code Content-Length} ({@link
     * DefaultHttpProxyServer#allowChunkedLength}): the connection closes after its response.
     */
    private boolean closeAfterResponse;
    /** What counts the bytes read from and written to the client, or null when nothing does. */
    private java.util.function.IntConsumer rxBytes;
    private java.util.function.IntConsumer txBytes;

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

    /**
     * Counts the bytes read from and written to the client in {@code rx} and {@code tx}, from the
     * next {@link #attach} on (decrypted bytes, once TLS is layered over the connection).
     */
    void countBytes(org.microproxy.stats.Counter rx, org.microproxy.stats.Counter tx) {
        rxBytes = rx::add;
        txBytes = tx::add;
    }

    /** Reads and writes through {@code s} from now on (the accepted socket, or TLS over it). */
    void attach(Socket s) throws IOException {
        socket = s;
        InputStream is = s.getInputStream();
        OutputStream os = s.getOutputStream();
        if (rxBytes != null) {
            is = CountingStreams.counting(is, rxBytes);
            os = CountingStreams.counting(os, txBytes);
        }
        if (!server.trackers.isEmpty()) {
            is = CountingStreams.counting(is, n -> server.trackers.fire(t -> t.bytesReceivedFromClient(flowContext, n)));
            os = CountingStreams.counting(os, n -> server.trackers.fire(t -> t.bytesSentToClient(flowContext, n)));
        }
        in = new ByteReader(is, server.ioBuffers).strictLineEndings().idleWaitsOn(s);
        out = new PooledOutputStream(os, server.ioBuffers);
        writer = new HttpCodec.HttpWriter(out);
    }

    /**
     * Reads the PROXY protocol header that starts the connection, if it starts with one. The
     * first byte may take the idle timeout, as a request's would; the rest of the signature and
     * the header must have come by {@code timeoutMillis} after it, or the read fails with a {@link
     * SocketTimeoutException}. Nothing is consumed unless a header is read.
     *
     * @param optional whether the connection may start without a header (it is then served as it
     *     came); otherwise one without fails with a {@link ProtocolException}
     * @param trusted whether the peer's headers are honored: a header from another peer fails
     *     with a {@link ProtocolException}, and so does any connection from it when not {@code
     *     optional} (once its first bytes are read, so that closing it does not reset it)
     * @return the header, or null for a connection that does not start with one ({@code
     *     optional}), or that ended before its first byte
     */
    ProxyProtocol.Header readProxyHeader(boolean optional, boolean trusted, int timeoutMillis,
            ProxyStats.ProxyProtocolStats stats) throws IOException {
        in.awaitNext();
        if (in.buffered() == 0) {
            if (optional) return null;
            throw new ProtocolException("missing PROXY protocol header");
        }
        if (!trusted && !optional) {
            // A header is required, and this peer's would not count.
            stats.untrustedSource.inc();
            throw new ProtocolException("PROXY protocol header required, and the peer is not a trusted source");
        }
        Socket client = socket;
        int original = client.getSoTimeout();
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        ProxyProtocol.Start start = ProxyProtocol.Start.OTHER;
        try {
            // Enough bytes to tell a signature apart: the first that matches none decides.
            boolean ended = false;
            while ((start = ProxyProtocol.start(in.peekBuffered(PROXY_SIGNATURE_LENGTH))) == ProxyProtocol.Start.PARTIAL) {
                if (!bufferAtLeast(client, in.buffered() + 1, deadline, original)) {
                    ended = true;
                    break;
                }
            }
            if (start == ProxyProtocol.Start.OTHER || ended) {
                if (optional) {
                    stats.notFoundAllowed.inc();
                    return null;
                }
                stats.notFoundDisallowed.inc();
                throw new ProtocolException("missing PROXY protocol header");
            }
            if (!trusted) {
                stats.untrustedSource.inc();
                throw new ProtocolException("PROXY protocol header from a peer that is not a trusted source");
            }
            int length;
            while ((length = ProxyProtocol.headerLength(start, in.peekBuffered(ProxyProtocol.V1_MAX_LENGTH))) < 0) {
                if (!bufferAtLeast(client, in.buffered() + 1, deadline, original)) {
                    throw new EOFException("connection closed in the PROXY protocol header");
                }
            }
            if (!bufferAtLeast(client, length, deadline, original)) {
                throw new EOFException("connection closed in the PROXY protocol header");
            }
            // The whole header is buffered: parsing it reads nothing more.
            ProxyProtocol.Header header = ProxyProtocol.read(in);
            (start == ProxyProtocol.Start.V1 ? stats.v1Found : stats.v2Found).inc();
            return header;
        } catch (IOException e) {
            if (start == ProxyProtocol.Start.V1 || start == ProxyProtocol.Start.V2) {
                if (trusted) (start == ProxyProtocol.Start.V1 ? stats.v1Error : stats.v2Error).inc();
            } else if (e instanceof SocketTimeoutException) {
                // A signature begun and not finished in time.
                stats.notFoundDisallowed.inc();
            }
            throw e;
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

    /** The longest PROXY protocol signature: v2's 12 bytes. */
    private static final int PROXY_SIGNATURE_LENGTH = 12;

    /**
     * Reads until at least {@code n} bytes are buffered, each read waiting at most until {@code
     * deadline} (and the idle timeout, {@code idleMillis}, when shorter), however slowly the
     * bytes come.
     *
     * @return whether they are (false if the stream ended first)
     */
    private boolean bufferAtLeast(Socket client, int n, long deadline, int idleMillis) throws IOException {
        while (in.buffered() < n) {
            long remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
            if (remaining <= 0) throw new SocketTimeoutException("PROXY protocol header not complete in time");
            client.setSoTimeout((int) Math.max(1, idleMillis > 0 ? Math.min(idleMillis, remaining)
                    : Math.min(Integer.MAX_VALUE, remaining)));
            if (!in.ensureBuffered(in.buffered() + 1)) return false;
        }
        return true;
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

    /**
     * Whether the connection's first byte, received and not consumed, could start a TLS record
     * (a handshake record, {@code 0x16}).
     */
    boolean startsLikeTls() throws IOException {
        return in.peek() == 0x16;
    }

    /** The reader requests arrive through, for looking at bytes before deciding how to serve them. */
    ByteReader input() {
        return in;
    }

    /** The socket requests arrive on: the accepted one, or the TLS socket layered over it. */
    Socket socket() {
        return socket;
    }

    /** Writes {@code bytes} to the client as they are, such as a TLS alert. */
    void writeRaw(byte[] bytes) throws IOException {
        out.write(bytes);
        out.flush();
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
        HttpHeaders headers = request.headers();
        boolean chunkedLength = server.allowChunkedLength && headers.contains(HttpHeaderNames.TRANSFER_ENCODING)
                && headers.contains(HttpHeaderNames.CONTENT_LENGTH);
        Framing framing = Framing.forRequest(request, server.allowChunkedLength);
        if (chunkedLength) {
            // Accepted as RFC 9112 section 6.1 allows, its Content-Length gone: the connection
            // closes after the response, whatever the client asked, so that bytes another hop may
            // have framed differently are never read as a request.
            closeAfterResponse = true;
            flowContext.chunkedWithContentLength();
            server.stats.http.rqChunkedLength.inc();
        }
        return new HttpCodec.BodyReader(in, framing, server.limits);
    }

    @Override
    public boolean clientKeepAlive(HttpRequest request) {
        return !closeAfterResponse && ProxyUtils.isClientKeepAlive(request);
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

    @Override
    public void writeHead(HttpResponse response, boolean bodyAllowed, boolean bodyFollows) throws IOException {
        hop(response);
        writer.writeHead(response, bodyAllowed, !bodyFollows);
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
    public void relay(ServerConnection conn, WebSocketRelay webSocket, TcpSession tcp, ClientFlowContext counted,
            String name) {
        Tunnel.relay(in.asInputStream(), out, () -> Tunnel.halfClose(socket),
                conn.tunnelInput(), conn.tunnelOutput(), conn::endTunnelOutput,
                () -> { close(); conn.close(); },
                server.getIdleConnectionTimeout(), name, logPrefix, webSocket, tcp, server.ioBuffers, counted);
    }

    /**
     * The connection as the client of a CONNECT-UDP flow, for an exchange that the proxy took for
     * an HTTP/1.1 CONNECT-UDP request (RFC 9298 section 3.2): once its {@code 101} is written, the
     * connection carries capsules both ways, and the connection closes when the flow ends.
     */
    @Override
    public UdpFlow.Client udpClient() {
        return new UdpClient();
    }

    /** The connection's bytes after the {@code 101}, as a CONNECT-UDP flow's capsules. */
    private final class UdpClient implements UdpFlow.Client {
        /** Serializes writing a capsule with ending the output from another thread. */
        private final ReentrantLock output = new ReentrantLock();

        @Override
        public InputStream capsules() {
            return in.asInputStream();
        }

        @Override
        public void setReadTimeout(int millis) {
            try {
                socket.setSoTimeout(millis);
            } catch (SocketException e) {
                // the connection is failing: the next read says so
            }
        }

        /** Always a DATAGRAM capsule, written as TCP takes it. */
        @Override
        public boolean sendDatagram(byte[] content) throws IOException {
            byte[] capsule = UdpFlow.datagramCapsule(content);
            output.lock();
            try {
                out.write(capsule);
                out.flush();
            } finally {
                output.unlock();
            }
            return true;
        }

        /**
         * Ends the connection's output when {@code clean} (the client reads its end), once a capsule
         * being written on the flow's sender thread is out, unless TCP holds it up for longer than
         * {@link #FLOW_END_WAIT_MILLIS}; otherwise closes the connection.
         */
        @Override
        public void endFlow(boolean clean) {
            try {
                if (clean && output.tryLock(FLOW_END_WAIT_MILLIS, TimeUnit.MILLISECONDS)) {
                    try {
                        Tunnel.halfClose(socket);
                        return;
                    } finally {
                        output.unlock();
                    }
                }
            } catch (IOException e) {
                // closed below
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            closeSocket();
        }

        /** One flow on the connection, which the per-connection bound always allows. */
        @Override
        public boolean attach(UdpFlow flow) {
            return true;
        }

        @Override
        public void detach(UdpFlow flow) {
            // the connection closes with the flow
        }
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
