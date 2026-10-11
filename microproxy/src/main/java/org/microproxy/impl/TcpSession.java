// Ported from mitmproxy (MIT License, see META-INF/LICENSE-mitmproxy.txt):
// mitmproxy/proxy/layers/tcp.py, TCPLayer: the tcp_start, tcp_message, tcp_end and tcp_error
// hooks around a relay, messages as the chunks read, and injected messages.
// Changes: injected bytes are written as they are instead of passing through tcp_message again;
// a half-close is reported (tcpHalfClose) before it is passed on; the relay is the blocking
// Tunnel's, one thread per direction.
package org.microproxy.impl;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import org.microproxy.FlowContext;
import org.microproxy.tcp.TcpContext;
import org.microproxy.tcp.TcpInterceptor;
import org.microproxy.tcp.TcpMessage;

/**
 * A raw tunnel's side of the {@link TcpInterceptor}: the context its hooks get, and what {@link
 * Tunnel} calls as bytes arrive in each direction. Made only when an interceptor is configured;
 * without one the tunnel copies bytes as before.
 */
final class TcpSession implements TcpContext {

    private static final System.Logger LOG = System.getLogger(TcpSession.class.getName());

    /** Where bytes go in one direction, as the session writes them. */
    interface Sink {
        void write(byte[] data) throws IOException;

        /** Passes the end of the stream on (a half-close). */
        void end() throws IOException;
    }

    /** One direction's output, written by its relay thread and by {@link #send} from any thread. */
    private static final class Output {
        final boolean fromClient;
        final ReentrantLock lock = new ReentrantLock();
        Sink sink;
        /** Set under {@link #lock}: the end was passed on, or the tunnel failed. */
        boolean ended;
        /** The direction finished without failing. */
        volatile boolean finished;
        /** The thread running a {@code tcpMessage} hook of this direction, whose sends wait for its result. */
        volatile Thread hookThread;
        /** Bytes that {@link #hookThread} sent during the hook, written after its result. */
        List<byte[]> pending;

        Output(boolean fromClient) {
            this.fromClient = fromClient;
        }
    }

    private final TcpInterceptor interceptor;
    private final long connectionId;
    private final InetSocketAddress clientAddress;
    private final String host;
    private final int port;
    private final boolean tlsIntercepted;
    private final String sni;
    private final String alpn;
    private final FlowContext flowContext;
    private final String logPrefix;
    private final Output toServer = new Output(true);
    private final Output toClient = new Output(false);
    private final AtomicReference<Throwable> error = new AtomicReference<>();
    private final AtomicBoolean finished = new AtomicBoolean();
    private volatile Runnable closeAll = () -> {};

    TcpSession(TcpInterceptor interceptor, FlowContext flowContext, HostAndPort target, boolean tlsIntercepted,
            String sni, String alpn, String logPrefix) {
        this.interceptor = interceptor;
        this.flowContext = flowContext;
        this.connectionId = flowContext.getConnectionId();
        this.clientAddress = flowContext.getClientAddress();
        this.host = target.host();
        this.port = target.port();
        this.tlsIntercepted = tlsIntercepted;
        this.sni = sni;
        this.alpn = alpn == null || alpn.isEmpty() ? null : alpn;
        this.logPrefix = logPrefix;
    }

    // ---------------------------------------------------------------------------------------
    // TcpContext
    // ---------------------------------------------------------------------------------------

    @Override
    public long connectionId() {
        return connectionId;
    }

    @Override
    public InetSocketAddress clientAddress() {
        return clientAddress;
    }

    @Override
    public String host() {
        return host;
    }

    @Override
    public int port() {
        return port;
    }

    @Override
    public boolean tlsIntercepted() {
        return tlsIntercepted;
    }

    @Override
    public String sni() {
        return sni;
    }

    @Override
    public String alpn() {
        return alpn;
    }

    @Override
    public FlowContext flowContext() {
        return flowContext;
    }

    @Override
    public void send(boolean fromClient, byte[] data) {
        Objects.requireNonNull(data, "data");
        Output out = fromClient ? toServer : toClient;
        if (out.hookThread == Thread.currentThread()) {
            if (out.pending == null) out.pending = new ArrayList<>();
            out.pending.add(data.clone());
            return;
        }
        out.lock.lock();
        try {
            if (out.ended || out.sink == null) {
                throw new IllegalStateException((fromClient ? "the client's" : "the server's") + " side has ended");
            }
            if (data.length > 0) out.sink.write(data);
        } catch (IOException e) {
            fail(out, e);
        } finally {
            out.lock.unlock();
        }
    }

    @Override
    public String toString() {
        return "tcp " + connectionId + " to " + new HostAndPort(host, port);
    }

    // ---------------------------------------------------------------------------------------
    // Called by Tunnel
    // ---------------------------------------------------------------------------------------

    /** The tunnel is ready: {@code tcpStart}. */
    void start(Sink server, Sink client, Runnable closeAll) {
        toServer.sink = server;
        toClient.sink = client;
        this.closeAll = closeAll;
        try {
            interceptor.tcpStart(this);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, logPrefix + "TCP interceptor's tcpStart threw", e);
        }
    }

    /** Bytes read in one direction: through {@code tcpMessage}, then to the other side. */
    void message(boolean fromClient, byte[] data) throws IOException {
        Output out = fromClient ? toServer : toClient;
        TcpMessage message = new TcpMessage(data, fromClient, Instant.now());
        byte[] result;
        out.hookThread = Thread.currentThread();
        try {
            result = interceptor.tcpMessage(message, this);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, logPrefix + "TCP interceptor's tcpMessage threw; passing the bytes on", e);
            result = data;
        } finally {
            out.hookThread = null;
        }
        List<byte[]> added = out.pending;
        out.pending = null;
        out.lock.lock();
        try {
            if (out.ended) return;
            if (result != null && result.length > 0) out.sink.write(result);
            if (added != null) {
                for (byte[] bytes : added) {
                    if (bytes.length > 0) out.sink.write(bytes);
                }
            }
        } finally {
            out.lock.unlock();
        }
    }

    /** One direction reached end of stream: {@code tcpHalfClose}, then the end is passed on. */
    void endOfStream(boolean fromClient) throws IOException {
        Output out = fromClient ? toServer : toClient;
        try {
            interceptor.tcpHalfClose(this, fromClient);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, logPrefix + "TCP interceptor's tcpHalfClose threw", e);
        }
        out.lock.lock();
        try {
            if (out.ended) return;
            out.ended = true;
            // Finished before the end is passed on: closing a TLS socket whole fails the other
            // direction's read at once, which is how that connection ends, not an error.
            out.finished = true;
            out.sink.end();
        } finally {
            out.lock.unlock();
        }
    }

    /**
     * One direction failed. After the other direction finished, that is how a connection that
     * cannot half-close ends (a TLS socket closes whole), not an error.
     */
    void failed(boolean fromClient, IOException e) {
        Output out = fromClient ? toServer : toClient;
        Output other = fromClient ? toClient : toServer;
        if (!other.finished) error.compareAndSet(null, e);
        markEnded(out);
    }

    /** Both directions are done and the connection closed: {@code tcpEnd} or {@code tcpError}. */
    void finish() {
        if (!finished.compareAndSet(false, true)) return;
        markEnded(toServer);
        markEnded(toClient);
        Throwable failure = error.get();
        try {
            if (failure == null) {
                interceptor.tcpEnd(this);
            } else {
                interceptor.tcpError(this, failure);
            }
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, logPrefix + "TCP interceptor's " + (failure == null ? "tcpEnd" : "tcpError")
                    + " threw", e);
        }
    }

    /** A write of {@link #send} failed: the tunnel ends with that error. */
    private void fail(Output out, IOException e) {
        error.compareAndSet(null, e);
        out.ended = true;
        closeAll.run();
    }

    private static void markEnded(Output out) {
        out.lock.lock();
        try {
            out.ended = true;
        } finally {
            out.lock.unlock();
        }
    }
}
