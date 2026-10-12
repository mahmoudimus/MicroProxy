package org.microproxy.impl;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
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
 * <p>A {@link Key} names everything that must match for two exchanges to share a connection: the
 * target's authority, and its isolation: the route (direct, or which chained proxy), the MITM
 * manager that set up its TLS, and, unless the connection may serve every client (the shared pool
 * is on, and nothing about the connection is particular to one client), the client connection it
 * belongs to. So connections that carry a PROXY protocol header, or whose TLS a MITM manager set up
 * for one client, are never shared.
 *
 * <p>Connections are indexed by isolation, then by the authorities they serve: the one each was
 * made for and, with connection coalescing on ({@link
 * org.microproxy.Http2Options#coalesceConnections()}), the others found to share it ({@link
 * Http2Coalescing}). An exchange with an {@link Http2Coalescing.Request} that finds no connection
 * with room for its authority looks at the other connections of its isolation, never beyond: each
 * one that may serve the authority (by its certificate, TLS context, and address or ORIGIN frame)
 * is indexed under it from then on, so later exchanges find it at once. An exchange without one
 * takes only connections made for its own authority: a dedicated connection, such as the one a
 * request answered {@code 421} on a coalesced connection is sent again on.
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
 * <p>The proxy keeps a second instance for its HTTP/2 connections to chained proxies ({@link
 * #forChainedProxies}), which carry its {@code CONNECT} tunnels and plain-HTTP proxy requests to
 * any server: there a key's authority is the chained proxy's, its isolation the proxy itself (its
 * TLS, credentials and local address), and connections are never coalesced.
 *
 * <p>All state is guarded by {@link #lock}, which may be held while taking a connection's state
 * lock (or its {@link Http2Coalescing.Peer}'s), never the other way round.
 */
final class Http2Origins {

    /** Keys remembered as reaching servers that chose HTTP/1.1. */
    private static final int MAX_HTTP1_KEYS = 4096;

    /**
     * How long others wait for a connection whose making waits for its client's ClientHello:
     * enough for a client that sends it right after the {@code CONNECT}'s answer.
     */
    static final long CLIENT_HELLO_GRACE_NANOS = TimeUnit.MILLISECONDS.toNanos(200);

    /**
     * What an exchange's HTTP/2 connection must match: the server's {@code authority} and its
     * {@code isolation}, everything else that keeps connections apart (mode, route or hop, MITM
     * manager, owning client connection). Connections are coalesced only within one isolation.
     *
     * @param isolation what besides the authority two exchanges must have in common to share a
     *     connection
     * @param authority the server's {@code host:port}, kept as {@link Http2Coalescing#authority}
     *     normalizes it (the host in lower case)
     */
    record Key(String isolation, String authority) {

        Key {
            String normalized = Http2Coalescing.authority(authority);
            authority = normalized != null ? normalized : authority.toLowerCase(Locale.ROOT);
        }

        @Override
        public String toString() {
            return isolation + "|" + authority;
        }
    }

    private final DefaultHttpProxyServer server;
    /** Whether the connections go to chained proxies ({@link #forChainedProxies}), not to origin servers. */
    final boolean chainedProxies;
    private final ReentrantLock lock = new ReentrantLock();
    /** Signalled when a connection is made, or making one ended. */
    private final Condition changed = lock.newCondition();
    /**
     * Open connections by isolation, then by the authorities they serve: each under the one it
     * was made for, and under those coalesced onto it.
     */
    private final Map<String, Map<String, List<Http2UpstreamConnection>>> open = new HashMap<>();
    /** Keys a connection is being made for, and by which thread. */
    private final Map<Key, Thread> connecting = new HashMap<>();
    /**
     * Keys whose connection is made but waits for its client's ClientHello before its TLS
     * handshake, and since when ({@link System#nanoTime()}).
     */
    private final Map<Key, Long> awaitingClient = new HashMap<>();
    private final Map<Key, Boolean> http1Only = new LinkedHashMap<>(64, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Key, Boolean> eldest) {
            return size() > MAX_HTTP1_KEYS;
        }
    };
    private boolean closed;

    Http2Origins(DefaultHttpProxyServer server) {
        this(server, false);
    }

    private Http2Origins(DefaultHttpProxyServer server, boolean chainedProxies) {
        this.server = server;
        this.chainedProxies = chainedProxies;
    }

    /**
     * The HTTP/2 connections to chained proxies ({@link org.microproxy.ChainedProxy#http2()}),
     * whose streams are the {@code CONNECT} tunnels and proxy requests of exchanges with any
     * server; never coalesced.
     */
    static Http2Origins forChainedProxies(DefaultHttpProxyServer server) {
        return new Http2Origins(server, true);
    }

    /**
     * A stream for an exchange on an open connection for {@code key} with room for it, or on the
     * connection another exchange is making for it, waited for up to {@code waitMillis} (once).
     * With {@code coalescing}, before waiting, one on a connection of the same isolation made for
     * another authority that may serve this one; without, only one on a connection made for
     * {@code key}.
     *
     * @param coalescing what lets the exchange take a connection made for another authority, or
     *     null to take only one made for its own
     * @return the stream, or null: the caller connects itself, then reports with {@link #adopt},
     *     {@link #negotiatedHttp1} or {@link #connectFailed}
     */
    ServerConnection stream(Key key, Http2Coalescing.Request coalescing, ClientFlowContext flow, String hostAndPort,
            String log, boolean headRequest, long waitMillis) throws IOException {
        Function<List<Http2UpstreamConnection>, ServerConnection> take =
                list -> reserve(list, key, flow, hostAndPort, log, headRequest);
        if (coalescing != null) {
            ServerConnection coalesced = coalesce(key, coalescing, take);
            if (coalesced != null) return coalesced;
        }
        return find(key, coalescing == null, waitMillis, take);
    }

    /**
     * The TLS session of an open connection for {@code key} (or, with {@code coalescing}, of one
     * that may serve it), waiting (once) for one being made: an intercepted {@code CONNECT} needs
     * no connection of its own when its requests will take streams on that one.
     *
     * @return the session, or null: the caller connects itself, then reports as for {@link #stream}
     */
    SSLSession session(Key key, Http2Coalescing.Request coalescing, long waitMillis) throws IOException {
        Function<List<Http2UpstreamConnection>, SSLSession> take = list -> list.isEmpty()
                || !(list.getFirst().carrier.socket instanceof SSLSocket tls) ? null : tls.getSession();
        if (coalescing != null) {
            SSLSession coalesced = coalesce(key, coalescing, take);
            if (coalesced != null) return coalesced;
        }
        return find(key, coalescing == null, waitMillis, take);
    }

    /**
     * What {@code take} finds among the connections that serve {@code key}'s authority, then among
     * the other connections of its isolation that may serve it by {@code request}'s checks (each
     * indexed under the authority from then on); null if none does. The TLS context and the
     * address are looked up outside the lock, once, and only when a connection needs them.
     */
    private <T> T coalesce(Key key, Http2Coalescing.Request request, Function<List<Http2UpstreamConnection>, T> take)
            throws IOException {
        List<Http2UpstreamConnection> toCheck = new ArrayList<>();
        boolean needsAddress = false;
        lock.lock();
        try {
            if (closed) throw new IOException("the proxy is stopping");
            T found = take.apply(served(key, false));
            if (found != null) return found;
            for (Http2UpstreamConnection c : members(key.isolation())) {
                if (c.coalescing == null || c.coalescing.serves(key.authority())) continue;
                switch (c.coalescing.verdict(request)) {
                    case CHECK_TLS -> toCheck.add(c);
                    case CHECK_ADDRESS -> {
                        if (request.resolver() != null) {
                            toCheck.add(c);
                            needsAddress = true;
                        }
                    }
                    case SERVES, REFUSED -> {
                        // listed already (and tried above), or not to be
                    }
                }
            }
        } finally {
            lock.unlock();
        }
        if (toCheck.isEmpty()) return null;
        Http2Coalescing.Lookup lookup = Http2Coalescing.Lookup.of(request, needsAddress);
        lock.lock();
        try {
            if (closed) throw new IOException("the proxy is stopping");
            List<Http2UpstreamConnection> admitted = new ArrayList<>();
            for (Http2UpstreamConnection c : toCheck) {
                if (c.usable() && c.coalescing.admit(request, lookup.context(), lookup.address())) {
                    index(c, key.authority());
                    admitted.add(c);
                }
            }
            return admitted.isEmpty() ? null : take.apply(admitted);
        } finally {
            lock.unlock();
        }
    }

    /**
     * What {@code take} finds among {@code key}'s usable connections (only those made for it when
     * {@code dedicated}), waiting (once) for a connection another thread is making; null when there
     * is nothing to wait for, after claiming the making of the connection for the calling thread
     * unless another thread has.
     */
    private <T> T find(Key key, boolean dedicated, long waitMillis, Function<List<Http2UpstreamConnection>, T> take)
            throws IOException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(Math.max(0, waitMillis));
        Thread waitedFor = null;
        lock.lock();
        try {
            while (true) {
                if (closed) throw new IOException("the proxy is stopping");
                T found = take.apply(served(key, dedicated));
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

    /** A stream on one of {@code list}'s connections with room for it; null if none. Holds lock. */
    private ServerConnection reserve(List<Http2UpstreamConnection> list, Key key, ClientFlowContext flow,
            String hostAndPort, String log, boolean headRequest) {
        for (Http2UpstreamConnection c : list) {
            boolean coalesced = !c.key.authority().equals(key.authority());
            ServerConnection stream = streamOn(c, coalesced, flow, hostAndPort, log, headRequest);
            if (stream != null) return stream;
        }
        return null;
    }

    /**
     * A stream on {@code c} for an exchange with {@code hostAndPort}, if it has room; {@code
     * coalesced} when {@code c} was made for another authority. Holds lock.
     */
    private ServerConnection streamOn(Http2UpstreamConnection c, boolean coalesced, ClientFlowContext flow,
            String hostAndPort, String log, boolean headRequest) {
        FullFlowContext context = new FullFlowContext(flow, hostAndPort, c.carrier.chainedProxy, c.carrier.remoteAddress);
        Http2UpstreamConnection.StreamState state = c.reserve(headRequest, log, context);
        if (state == null) return null;
        if (coalesced) server.stats.http2Upstream.coalescedStreams.inc();
        return new Http2UpstreamStream(c, state, context, server.trackers, hostAndPort, coalesced);
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
    ServerConnection adopt(ServerConnection carrier, Key lookupKey, Key key, Object owner, ClientFlowContext flow,
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
            if (flow != null) first = streamOn(c, false, flow, hostAndPort, log, headRequest);
            late = closed;
            if (!late) {
                index(c, key.authority());
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
    void negotiatedHttp1(Key lookupKey) {
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
    void awaitingClientHello(Key key) {
        lock.lock();
        try {
            if (connecting.get(key) == Thread.currentThread()) awaitingClient.put(key, System.nanoTime());
        } finally {
            lock.unlock();
        }
    }

    /** The ClientHello for {@link #awaitingClientHello} has come: others may wait for the handshake. */
    void clientHelloArrived(Key key) {
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
    void connectFailed(Key lookupKey) {
        lock.lock();
        try {
            release(lookupKey);
        } finally {
            lock.unlock();
        }
    }

    /** Ends the calling thread's claim to make {@code key}'s connection. Holds lock. */
    private void release(Key key) {
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
            forget(c);
        } finally {
            lock.unlock();
        }
    }

    /**
     * The server answered {@code 421 Misdirected Request} on {@code c}, a connection made for
     * another authority, to a request for {@code hostAndPort}: that authority is not coalesced
     * onto {@code c} again.
     */
    void misdirected(Http2UpstreamConnection c, String hostAndPort) {
        if (c.coalescing == null) return;
        lock.lock();
        try {
            c.coalescing.misdirected(hostAndPort);
            String authority = Http2Coalescing.authority(hostAndPort);
            if (authority != null && !authority.equals(c.key.authority())) unindex(c, authority);
        } finally {
            lock.unlock();
        }
    }

    /**
     * The server sent {@code c} an ORIGIN frame naming {@code origins}: from now on its origin set
     * says which authorities it serves ({@link Http2Coalescing.Peer#origins}).
     */
    void origins(Http2UpstreamConnection c, List<String> origins) {
        if (c.coalescing == null) return;
        lock.lock();
        try {
            c.coalescing.origins(origins);
            Map<String, List<Http2UpstreamConnection>> group = open.get(c.key.isolation());
            if (group == null) return;
            for (String authority : List.copyOf(group.keySet())) {
                if (!c.coalescing.serves(authority)) unindex(c, authority);
            }
        } finally {
            lock.unlock();
        }
    }

    /** Closes the connections private to {@code owner}, a client connection that is closing. */
    void closeOwnedBy(Object owner) {
        List<Http2UpstreamConnection> owned = new ArrayList<>();
        lock.lock();
        try {
            for (Http2UpstreamConnection c : all()) {
                if (c.owner == owner) owned.add(c);
            }
        } finally {
            lock.unlock();
        }
        owned.forEach(c -> c.shutdown("client connection closed"));
    }

    /** The proxy is stopping: every connection is sent GOAWAY and closed. */
    void closeAll() {
        List<Http2UpstreamConnection> all;
        lock.lock();
        try {
            closed = true;
            all = all();
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
            return all();
        } finally {
            lock.unlock();
        }
    }

    // ---------------------------------------------------------------------------------------
    // The index; every method holds lock
    // ---------------------------------------------------------------------------------------

    /**
     * The connections that take new streams and serve {@code key}'s authority (only those made
     * for it when {@code dedicated}), forgetting any that take no new streams.
     */
    private List<Http2UpstreamConnection> served(Key key, boolean dedicated) {
        Map<String, List<Http2UpstreamConnection>> group = open.get(key.isolation());
        List<Http2UpstreamConnection> list = group == null ? null : group.get(key.authority());
        if (list == null) return List.of();
        for (Http2UpstreamConnection c : List.copyOf(list)) {
            if (!c.usable()) forget(c);
        }
        List<Http2UpstreamConnection> served = new ArrayList<>(list.size());
        for (Http2UpstreamConnection c : list) {
            if (!dedicated || c.key.equals(key)) served.add(c);
        }
        return served;
    }

    /** The usable connections of {@code isolation}, each once. */
    private List<Http2UpstreamConnection> members(String isolation) {
        List<Http2UpstreamConnection> members = new ArrayList<>();
        Map<String, List<Http2UpstreamConnection>> group = open.get(isolation);
        if (group != null) addOwn(group, members);
        members.removeIf(c -> !c.usable());
        return members;
    }

    /** Every connection, once. */
    private List<Http2UpstreamConnection> all() {
        List<Http2UpstreamConnection> all = new ArrayList<>();
        for (Map<String, List<Http2UpstreamConnection>> group : open.values()) addOwn(group, all);
        return all;
    }

    /** Adds the connections of {@code group} to {@code out}, each from the list of its own authority. */
    private static void addOwn(Map<String, List<Http2UpstreamConnection>> group, List<Http2UpstreamConnection> out) {
        for (Map.Entry<String, List<Http2UpstreamConnection>> e : group.entrySet()) {
            for (Http2UpstreamConnection c : e.getValue()) {
                if (c.key.authority().equals(e.getKey())) out.add(c);
            }
        }
    }

    /** Lists {@code c} under {@code authority}, in its isolation. */
    private void index(Http2UpstreamConnection c, String authority) {
        List<Http2UpstreamConnection> list = open.computeIfAbsent(c.key.isolation(), k -> new HashMap<>())
                .computeIfAbsent(authority, k -> new ArrayList<>());
        if (!list.contains(c)) list.add(c);
    }

    /** Stops listing {@code c} under {@code authority}. */
    private void unindex(Http2UpstreamConnection c, String authority) {
        Map<String, List<Http2UpstreamConnection>> group = open.get(c.key.isolation());
        List<Http2UpstreamConnection> list = group == null ? null : group.get(authority);
        if (list == null || !list.remove(c) || !list.isEmpty()) return;
        group.remove(authority);
        if (group.isEmpty()) open.remove(c.key.isolation());
    }

    /** Stops listing {@code c} anywhere. */
    private void forget(Http2UpstreamConnection c) {
        Map<String, List<Http2UpstreamConnection>> group = open.get(c.key.isolation());
        if (group == null) return;
        group.values().removeIf(list -> list.remove(c) && list.isEmpty());
        if (group.isEmpty()) open.remove(c.key.isolation());
    }
}
