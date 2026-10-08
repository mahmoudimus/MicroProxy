package org.microproxy.impl;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;
import org.microproxy.ChainedProxy;
import org.microproxy.ChainedProxyType;
import org.microproxy.FullFlowContext;

/** A connection from the proxy to a server or chained proxy, owned by one client connection. */
final class ServerConnection {

    volatile String key;
    final String hostAndPort;
    final ChainedProxy chainedProxy;
    final boolean tlsToOrigin;
    final Socket socket;
    final ByteReader in;
    final OutputStream out;
    final HttpCodec.HttpWriter writer;
    final InetSocketAddress remoteAddress;
    final FullFlowContext flowContext;
    /** Whether this connection has carried a request before (so it may have gone stale). */
    boolean used;

    private final AtomicBoolean closed = new AtomicBoolean();
    private final Runnable onClose;

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
            Runnable onClose) {
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
        this.onClose = onClose;
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
            onClose.run();
        }
    }

    @Override
    public String toString() {
        return "ServerConnection[" + hostAndPort + (chainedProxy != null ? " via " + chainedProxy.getChainedProxyAddress() : "") + "]";
    }
}
