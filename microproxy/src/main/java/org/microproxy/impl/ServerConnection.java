package org.microproxy.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;
import org.microproxy.ChainedProxy;
import org.microproxy.ChainedProxyType;
import org.microproxy.FullFlowContext;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;

/**
 * A connection from the proxy to a server or chained proxy. It is used by one client connection
 * at a time; with the shared pool enabled it may be handed from one client to another.
 *
 * <p>The exchange logic writes requests and reads responses through the methods under "The
 * exchange's I/O", which this class implements for HTTP/1.1. A subclass stands for one stream of
 * a multiplexed connection instead ({@link #multiplexed()}).
 */
class ServerConnection {

    /** Key in the owning client's connection map. */
    volatile String key;
    final String hostAndPort;
    final ChainedProxy chainedProxy;
    final boolean tlsToOrigin;
    // Not final: a connection made before its client's ClientHello was read gets TLS layered over
    // it afterwards (layerTls), before anything else uses it.
    Socket socket;
    ByteReader in;
    OutputStream out;
    HttpCodec.HttpWriter writer;
    final InetSocketAddress remoteAddress;

    /** The flow this connection currently serves; replaced when another client borrows it. */
    volatile FullFlowContext flowContext;
    /** Removes the connection from its current owner when it closes. */
    volatile Runnable onDetach;
    /** The pool counting this connection, if any. */
    volatile SharedConnectionPool pool;
    /** Pool key: mode, target and route. */
    volatile String poolKey;
    /** Limit key for per-host accounting. */
    volatile String hostKey;
    /** Returned to the pool after each exchange (rather than held for a client's session). */
    volatile boolean perRequestLease;
    /** Mid request/response: the connection's state is unknown if the exchange is abandoned. */
    volatile boolean inExchange;
    /** Whether this connection has carried a request before (so it may have gone stale). */
    volatile boolean used;
    /**
     * The TLS handshake with the server negotiated {@code h2} (ALPN): the connection is for an
     * {@link Http2UpstreamConnection} to take over, never for HTTP/1.1 exchanges.
     */
    volatile boolean http2;
    /**
     * Made for interception, but its TLS handshake waits for the client's ClientHello, whose ALPN
     * protocols and server name it mirrors: until {@link #layerTls}, the socket is the plain
     * connection (or tunnel) to the server.
     */
    volatile boolean tlsPending;

    private final AtomicBoolean closed = new AtomicBoolean();
    private final Trackers trackers;

    ServerConnection(
            String key,
            String hostAndPort,
            ChainedProxy chainedProxy,
            boolean tlsToOrigin,
            Socket socket,
            ByteReader in,
            OutputStream out,
            InetSocketAddress remoteAddress,
            FullFlowContext flowContext,
            Trackers trackers) {
        this.key = key;
        this.hostAndPort = hostAndPort;
        this.chainedProxy = chainedProxy;
        this.tlsToOrigin = tlsToOrigin;
        this.socket = socket;
        this.in = in;
        this.out = out;
        this.writer = new HttpCodec.HttpWriter(out);
        this.remoteAddress = remoteAddress;
        this.flowContext = flowContext;
        this.trackers = trackers;
    }

    /** For a stream of a multiplexed connection, which has no reader and writer of its own. */
    ServerConnection(String hostAndPort, ChainedProxy chainedProxy, Socket socket, InetSocketAddress remoteAddress,
            FullFlowContext flowContext, Trackers trackers) {
        this.key = null;
        this.hostAndPort = hostAndPort;
        this.chainedProxy = chainedProxy;
        this.tlsToOrigin = true;
        this.socket = socket;
        this.in = null;
        this.out = null;
        this.writer = null;
        this.remoteAddress = remoteAddress;
        this.flowContext = flowContext;
        this.trackers = trackers;
    }

    /** Switches to {@code tls}, a TLS socket over this connection's socket, and its streams. */
    void layerTls(Socket tls, ByteReader tlsIn, OutputStream tlsOut) {
        this.socket = tls;
        this.in = tlsIn;
        this.out = tlsOut;
        this.writer = new HttpCodec.HttpWriter(tlsOut);
        this.tlsPending = false;
    }

    // ---------------------------------------------------------------------------------------
    // The exchange's I/O
    // ---------------------------------------------------------------------------------------

    /**
     * Whether this is one stream of a multiplexed connection, which carries one exchange and is
     * never pooled or kept by a client: {@link #close()} ends the stream, not the connection.
     */
    boolean multiplexed() {
        return false;
    }

    boolean supportsWebSockets() {
        return true;
    }

    int responseStatus(HttpResponse response) {
        return response.status().code();
    }

    /**
     * Writes the request head; a {@link org.microproxy.http.FullHttpRequest} is written whole.
     *
     * @param bodyFollows the body is streamed after the head ({@link #writeData} or {@link
     *     #writeContent}, then {@link #writeEnd})
     * @param trailersAccepted the client sent {@code TE: trailers}
     */
    void writeRequestHead(HttpRequest request, boolean bodyFollows, boolean trailersAccepted) throws IOException {
        writer.writeHead(request, true);
    }

    /** Writes a piece of the request body; a {@link org.microproxy.http.LastHttpContent} ends it. */
    void writeContent(HttpContent content) throws IOException {
        writer.writeContent(content);
    }

    /** Writes request body bytes. */
    void writeData(byte[] data, int off, int len) throws IOException {
        writer.writeData(data, off, len);
    }

    void flush() throws IOException {
        writer.flush();
    }

    /** Ends the request body, with its trailers. */
    void writeEnd(HttpHeaders trailers) throws IOException {
        writer.writeEnd(trailers);
    }

    /** Waits up to {@code millis} for the server to send something; false on timeout. */
    boolean awaitResponse(int millis) throws IOException {
        int original = socket.getSoTimeout();
        socket.setSoTimeout(original > 0 ? Math.min(original, millis) : millis);
        try {
            return in.awaitData();
        } finally {
            socket.setSoTimeout(original);
        }
    }

    /**
     * Waits (up to the read timeout) for the next response head to begin; returns whether any of
     * it has arrived, false at the end of the connection.
     */
    boolean awaitResponseHead() throws IOException {
        in.awaitNext();
        return in.buffered() > 0;
    }

    /** Reads the next response head (interim or final); null if the server closed the connection. */
    HttpResponse readResponse(HttpCodec.Limits limits) throws IOException {
        return HttpCodec.readResponse(in, limits);
    }

    /** The body of the response just read, delimited by {@code framing}. */
    MessageBody responseBody(Framing framing, HttpCodec.Limits limits) {
        return new HttpCodec.BodyReader(in, framing, limits);
    }

    /** The exchange is over and the connection reusable: gives back the buffers it held. */
    void exchangeDone() {
        in.release();
    }

    InputStream tunnelInput() {
        return in.asInputStream();
    }

    OutputStream tunnelOutput() {
        return out;
    }

    void endTunnelOutput() throws IOException {
        out.flush();
        Tunnel.halfClose(socket);
    }

    /**
     * Whether a request that failed with {@code e} on a reused connection may be sent again: for
     * HTTP/1.1, any failure before the response can mean the server had closed the idle connection.
     */
    boolean retryable(IOException e) {
        return true;
    }

    /**
     * Whether requests on this connection go to the origin server (origin-form URIs), rather than
     * to an HTTP proxy (absolute-form URIs). SOCKS proxies and CONNECT tunnels are transparent.
     */
    boolean nextHopIsOrigin() {
        return chainedProxy == null || tlsToOrigin || chainedProxy.getChainedProxyType() != ChainedProxyType.HTTP;
    }

    boolean isOpen() {
        return !closed.get() && !socket.isClosed();
    }

    void close() {
        if (closed.compareAndSet(false, true)) {
            Tls.closeQuietly(socket);
            Runnable detach = onDetach;
            if (detach != null) {
                detach.run();
            }
            SharedConnectionPool p = pool;
            if (p != null) {
                p.discarded(this);
            }
            if (chainedProxy != null) {
                chainedProxy.disconnected();
            }
            FullFlowContext ctx = flowContext;
            trackers.fire(t -> t.serverDisconnected(ctx, remoteAddress));
        }
    }

    @Override
    public String toString() {
        return "ServerConnection[" + hostAndPort + (chainedProxy != null ? " via " + chainedProxy.getChainedProxyAddress() : "") + "]";
    }
}
