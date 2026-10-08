package org.microproxy.impl;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;
import org.microproxy.ChainedProxy;
import org.microproxy.ChainedProxyType;
import org.microproxy.FullFlowContext;

/**
 * A connection from the proxy to a server or chained proxy. It is used by one client connection
 * at a time; with the shared pool enabled it may be handed from one client to another.
 */
final class ServerConnection {

    /** Key in the owning client's connection map. */
    volatile String key;
    final String hostAndPort;
    final ChainedProxy chainedProxy;
    final boolean tlsToOrigin;
    final Socket socket;
    final ByteReader in;
    final OutputStream out;
    final HttpCodec.HttpWriter writer;
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
