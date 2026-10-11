package org.microproxy.impl;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import org.microproxy.FullFlowContext;

/**
 * The proxy's HTTP/2 connections to origin servers ({@link Http2UpstreamConnection}), by key, and
 * the streams on them that exchanges take ({@link #stream}).
 *
 * <p>A key names everything that must match for two exchanges to share a connection: the target,
 * the route (direct, or which chained proxy), the MITM manager that set up its TLS, and, unless
 * the connection may serve every client (the shared pool is on, and nothing about the connection
 * is particular to one client), the client connection it belongs to. So connections that carry a
 * PROXY protocol header, or whose TLS a MITM manager set up for one client, are never shared.
 *
 * <p>Exchanges for a key share its connections, each up to the server's
 * SETTINGS_MAX_CONCURRENT_STREAMS; when all are full (or there are none), the exchange makes a new
 * connection, which offers {@code h2} with ALPN. While one connection is being made for a key,
 * other exchanges for it wait for that one (once) instead of making their own, so a burst of
 * streams shares one connection from the start. Servers that answer the handshake without {@code
 * h2} are remembered, so their exchanges do not wait for each other again.
 *
 * <p>A connection made for an intercepted {@code CONNECT} waits for its client's ClientHello
 * before its TLS handshake ({@link #awaitingClientHello}). Others wait for such a connection only
 * for {@link #CLIENT_HELLO_GRACE_NANOS} from when that wait began: a client that is slow to send
 * its ClientHello, or never sends one, does not hold up other clients for longer.
 *
 * <p>All state is guarded by {@link #lock}, which may be held while taking a connection's state
 * lock, never the other way round.
 */
final class Http2Origins {

    /** Keys remembered as reaching servers that chose HTTP/1.1. */
    private static final int MAX_HTTP1_KEYS = 4096;

    /**
     * How long others wait for a connection whose making waits for its client's ClientHello:
     * enough for a client that sends it right after the {@code CONNECT}'s answer.
     */
    static final long CLIENT_HELLO_GRACE_NANOS = TimeUnit.MILLISECONDS.toNanos(200);

    private final DefaultHttpProxyServer server;
    private final ReentrantLock lock = new ReentrantLock();
    /** Signalled when a connection is made, or making one ended. */
    private final Condition changed = lock.newCondition();
    private final Map<String, List<Http2UpstreamConnection>> open = new HashMap<>();
    /** Keys a connection is being made for, and by which thread. */
    private final Map<String, Thread> connecting = new HashMap<>();
    /**
     * Keys whose connection is made but waits for its client's ClientHello before its TLS
     * handshake, and since when ({@link System#nanoTime()}).
     */
    private final Map<String, Long> awaitingClient = new HashMap<>();
    private final Map<String, Boolean> http1Only = new LinkedHashMap<>(64, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
            return size() > MAX_HTTP1_KEYS;
        }
    };
    private boolean closed;

    Http2Origins(DefaultHttpProxyServer server) {
        this.server = server;
    }

    /**
     * A stream for an exchange on an open connection for {@code key} with room for it, or on the
     * connection another exchange is making for it, waited for up to {@code waitMillis} (once).
     *
     * @return the stream, or null: the caller connects itself, then reports with {@link #adopt},
     *     {@link #negotiatedHttp1} or {@link #connectFailed}
     */
    ServerConnection stream(String key, ClientFlowContext flow, String hostAndPort, String log, boolean headRequest,
            long waitMillis) throws IOException {
        return find(key, waitMillis, list -> reserve(list, flow, hostAndPort, log, headRequest));
    }

    /**
     * The TLS session of an open connection for {@code key}, waiting (once) for one being made: an
     * intercepted {@code CONNECT} needs no connection of its own when its requests will take
     * streams on that one.
     *
     * @return the session, or null: the caller connects itself, then reports as for {@link #stream}
     */
    SSLSession session(String key, long waitMillis) throws IOException {
        return find(key, waitMillis, list -> list.isEmpty() || !(list.getFirst().carrier.socket instanceof SSLSocket tls)
                ? null : tls.getSession());
    }

    /**
     * What {@code take} finds among {@code key}'s usable connections, waiting (once) for a
     * connection another thread is making; null when there is nothing to wait for, after claiming
     * the making of the connection for the calling thread unless another thread has.
     */
    private <T> T find(String key, long waitMillis, Function<List<Http2UpstreamConnection>, T> take) throws IOException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(Math.max(0, waitMillis));
        Thread waitedFor = null;
        lock.lock();
        try {
            while (true) {
                if (closed) throw new IOException("the proxy is stopping");
                T found = take.apply(usable(key));
                if (found != null) return found;
                if (http1Only.containsKey(key)) return null;
                Thread maker = connecting.get(key);
                if (maker == null || !maker.isAlive()) {
                    connecting.put(key, Thread.currentThread());
                    return null;
                }
                if (maker == waitedFor || maker == Thread.currentThread()) return null;
                // Another exchange is making a connection for this key: wait for it, once, but not
                // for long while that connection waits for its client's ClientHello.
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) return null;
                while (connecting.get(key) == maker && remaining > 0 && !closed) {
                    long limit = remaining;
                    Long since = awaitingClient.get(key);
                    if (since != null) limit = Math.min(limit, since + CLIENT_HELLO_GRACE_NANOS - System.nanoTime());
                    if (limit <= 0) break;
                    changed.awaitNanos(limit);
                    remaining = deadline - System.nanoTime();
                }
                waitedFor = maker;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted waiting for an HTTP/2 connection");
        } finally {
            lock.unlock();
        }
    }

    /** {@code key}'s connections that take new streams, forgetting the others. Holds lock. */
    private List<Http2UpstreamConnection> usable(String key) {
        List<Http2UpstreamConnection> list = open.get(key);
        if (list == null) return List.of();
        list.removeIf(c -> !c.usable());
        if (list.isEmpty()) open.remove(key);
        return list;
    }

    /** A stream on one of {@code list}'s connections with room for it; null if none. Holds lock. */
    private ServerConnection reserve(List<Http2UpstreamConnection> list, ClientFlowContext flow, String hostAndPort,
            String log, boolean headRequest) {
        for (Http2UpstreamConnection c : list) {
            ServerConnection stream = streamOn(c, flow, hostAndPort, log, headRequest);
            if (stream != null) return stream;
        }
        return null;
    }

    private ServerConnection streamOn(Http2UpstreamConnection c, ClientFlowContext flow, String hostAndPort, String log,
            boolean headRequest) {
        FullFlowContext context = new FullFlowContext(flow, hostAndPort, c.carrier.chainedProxy, c.carrier.remoteAddress);
        Http2UpstreamConnection.StreamState state = c.reserve(headRequest, log, context);
        return state == null ? null : new Http2UpstreamStream(c, state, context, server.trackers);
    }

    /**
     * Takes over {@code carrier}, a connection whose TLS handshake negotiated {@code h2}: starts
     * HTTP/2 on it and keeps it under {@code key} for other exchanges.
     *
     * @param lookupKey the key the connection was made for (by {@link #stream}), which may name
     *     another route than the one it took
     * @param owner the client connection a private connection belongs to, null if it is shared
     * @param flow the exchange to give the connection's first stream, or null for none
     * @return that stream, or null without {@code flow}
     * @throws IOException if HTTP/2 could not be started (the carrier is closed)
     */
    ServerConnection adopt(ServerConnection carrier, String lookupKey, String key, Object owner, ClientFlowContext flow,
            String hostAndPort, String log, boolean headRequest) throws IOException {
        Http2UpstreamConnection c = new Http2UpstreamConnection(server, this, carrier, key, owner);
        // The carrier now belongs to the HTTP/2 connection, not to a client or the pool's idle list.
        carrier.onDetach = null;
        carrier.perRequestLease = false;
        try {
            c.start();
        } catch (IOException | RuntimeException e) {
            connectFailed(lookupKey);
            throw e;
        }
        ServerConnection first = null;
        boolean late;
        lock.lock();
        try {
            if (flow != null) first = streamOn(c, flow, hostAndPort, log, headRequest);
            late = closed;
            if (!late) {
                open.computeIfAbsent(key, k -> new ArrayList<>()).add(c);
                http1Only.remove(key);
                http1Only.remove(lookupKey);
            }
            release(lookupKey);
        } finally {
            lock.unlock();
        }
        if (late) c.shutdown("the proxy is stopping");
        if (flow != null && first == null) {
            throw new IOException("the server allows no HTTP/2 streams (SETTINGS_MAX_CONCURRENT_STREAMS 0)");
        }
        return first;
    }

    /** The connection made for {@code lookupKey} chose HTTP/1.1: its exchanges stop waiting for each other. */
    void negotiatedHttp1(String lookupKey) {
        lock.lock();
        try {
            http1Only.put(lookupKey, Boolean.TRUE);
            release(lookupKey);
        } finally {
            lock.unlock();
        }
    }

    /**
     * The connection the calling thread is making for {@code key} waits for its client's
     * ClientHello before its TLS handshake: others wait for it only briefly.
     */
    void awaitingClientHello(String key) {
        lock.lock();
        try {
            if (connecting.get(key) == Thread.currentThread()) awaitingClient.put(key, System.nanoTime());
        } finally {
            lock.unlock();
        }
    }

    /** The ClientHello for {@link #awaitingClientHello} has come: others may wait for the handshake. */
    void clientHelloArrived(String key) {
        lock.lock();
        try {
            if (connecting.get(key) == Thread.currentThread() && awaitingClient.remove(key) != null) {
                changed.signalAll();
            }
        } finally {
            lock.unlock();
        }
    }

    /** Making a connection for {@code lookupKey} failed (or was given up); others may try. */
    void connectFailed(String lookupKey) {
        lock.lock();
        try {
            release(lookupKey);
        } finally {
            lock.unlock();
        }
    }

    /** Ends the calling thread's claim to make {@code key}'s connection. Holds lock. */
    private void release(String key) {
        if (connecting.get(key) == Thread.currentThread()) {
            connecting.remove(key);
            awaitingClient.remove(key);
        }
        changed.signalAll();
    }

    /** Forgets a connection that takes no new streams (GOAWAY, closed, idle). */
    void remove(Http2UpstreamConnection c) {
        lock.lock();
        try {
            List<Http2UpstreamConnection> list = open.get(c.key);
            if (list != null && list.remove(c) && list.isEmpty()) open.remove(c.key);
        } finally {
            lock.unlock();
        }
    }

    /** Closes the connections private to {@code owner}, a client connection that is closing. */
    void closeOwnedBy(Object owner) {
        List<Http2UpstreamConnection> owned = new ArrayList<>();
        lock.lock();
        try {
            for (List<Http2UpstreamConnection> list : open.values()) {
                for (Http2UpstreamConnection c : list) {
                    if (c.owner == owner) owned.add(c);
                }
            }
        } finally {
            lock.unlock();
        }
        owned.forEach(c -> c.shutdown("client connection closed"));
    }

    /** The proxy is stopping: every connection is sent GOAWAY and closed. */
    void closeAll() {
        List<Http2UpstreamConnection> all = new ArrayList<>();
        lock.lock();
        try {
            closed = true;
            open.values().forEach(all::addAll);
            open.clear();
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        all.forEach(c -> c.shutdown("the proxy is stopping"));
    }

    /** The open connections for every key (for tests). */
    List<Http2UpstreamConnection> connections() {
        lock.lock();
        try {
            List<Http2UpstreamConnection> all = new ArrayList<>();
            open.values().forEach(all::addAll);
            return all;
        } finally {
            lock.unlock();
        }
    }
}
