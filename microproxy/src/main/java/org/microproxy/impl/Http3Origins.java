package org.microproxy.impl;

import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.connection.SessionCache;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.System.Logger.Level;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;
import javax.net.ssl.X509TrustManager;
import org.microproxy.Http3Options;
import org.microproxy.http.HttpHeaders;
import org.microproxy.tls.SslContexts;

/**
 * The proxy's HTTP/3 connections to origin servers ({@link Http3UpstreamConnection}), by key, the
 * streams on them that exchanges take ({@link #stream}), and what the proxy knows about which
 * servers speak HTTP/3, as {@link Http2Origins} is for HTTP/2.
 *
 * <p>A server is reached over HTTP/3 once it is known to speak it: one of its responses over TLS
 * advertised {@code h3} on its own host in {@code Alt-Svc} ({@link #learn}; remembered for the
 * advertisement's {@code ma}, forgotten on {@code Alt-Svc: clear}), or its {@code host:port}
 * matches a configured pattern. The key names everything that must match for two exchanges to
 * share a connection: the server and the trust its certificate is checked with. Unlike TCP
 * connections, nothing about a QUIC connection is particular to one client (no PROXY header goes
 * over it, and it never runs through a chained proxy), so every client shares it.
 *
 * <p>Making a connection is happy eyeballs, lite: the exchange that needs one makes it, and others
 * for the same key wait for it (once) rather than make their own. A QUIC handshake that fails, or
 * takes longer than {@link Http3Options#upstreamHandshakeTimeout()}, sends the waiting exchanges
 * over TCP, and keeps the server on TCP for {@link Http3Options#upstreamFailureTimeout()}.
 *
 * <p>Session tickets and NEW_TOKEN tokens the servers send are kept in one {@link SessionCache}
 * for all of them, so a new connection to a server resumes the last session (and skips its Retry).
 * With {@link Http3Options#upstreamZeroRtt()}, an exchange that makes a connection for a request
 * that is safe to replay sends it as 0-RTT data when the ticket allows; other exchanges wait on the
 * connection's handshake before using it ({@link Http3UpstreamConnection#open}).
 *
 * <p>All state is guarded by {@link #lock}; nothing blocks while holding it except waiting on
 * {@link #changed}.
 */
final class Http3Origins {

    private static final System.Logger LOG = System.getLogger(Http3Origins.class.getName());

    /** Servers remembered, as speaking HTTP/3 or as failing to, at most. */
    private static final int MAX_ENTRIES = 4096;

    /** An HTTP/3 alternative learned for an origin: its UDP port, until when ({@link #clock}). */
    private record Alternative(int port, long expiresNanos) {}

    /** How to make a connection's address: resolving the server's name, as filters see it. */
    @FunctionalInterface
    interface Resolver {
        InetSocketAddress resolve() throws IOException;
    }

    private final DefaultHttpProxyServer server;
    private final Http3Options options;
    private final List<Pattern> forced;
    private final ReentrantLock lock = new ReentrantLock();
    /** Signalled when a connection is made, or making one ended. */
    private final Condition changed = lock.newCondition();
    private final Map<String, Http3UpstreamConnection> open = new HashMap<>();
    /** Keys a connection is being made for, and by which thread. */
    private final Map<String, Thread> connecting = new HashMap<>();
    /** Keys whose QUIC handshake failed, until when they stay on TCP. */
    private final Map<String, Long> brokenUntil = lru();
    /** Origins ({@code host:port}) that advertised HTTP/3. */
    private final Map<String, Alternative> alternatives = lru();
    /** A QUIC client endpoint per trust and address family. */
    private final Map<String, QuicClient> clients = new HashMap<>();
    /** The servers' session tickets and tokens, for every client endpoint. */
    final SessionCache sessions = SessionCache.memory();
    private boolean closed;

    /** The clock for expiry; replaceable by tests. */
    volatile LongSupplier clock = System::nanoTime;

    Http3Origins(DefaultHttpProxyServer server, List<String> forcedHosts) {
        this.server = server;
        this.options = server.http3Options;
        this.forced = HostRules.compile(forcedHosts);
    }

    private static <V> Map<String, V> lru() {
        return new LinkedHashMap<>(64, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, V> eldest) {
                return size() > MAX_ENTRIES;
            }
        };
    }

    private static String origin(String hostAndPort) {
        return hostAndPort.toLowerCase(Locale.ROOT);
    }

    // ---------------------------------------------------------------------------------------
    // What servers speak
    // ---------------------------------------------------------------------------------------

    /**
     * Learns from a response that {@code hostAndPort} sent over TLS: an {@code h3} alternative on
     * its own host, until its {@code ma}; {@code clear} or {@code ma=0} forgets it. Called before
     * the advertisement is removed for the client.
     */
    void learn(String hostAndPort, HttpHeaders headers) {
        if (!headers.contains(AltSvc.NAME)) return;
        HostAndPort target;
        try {
            target = HostAndPort.parse(hostAndPort, 443);
        } catch (IllegalArgumentException e) {
            return;
        }
        AltSvc.Http3Alternative h3 = AltSvc.http3(headers, target.host());
        if (h3 == null) return;
        String key = origin(hostAndPort);
        lock.lock();
        try {
            if (h3 == AltSvc.CLEAR || h3.maxAgeSeconds() == 0) {
                alternatives.remove(key);
            } else {
                long ttl = TimeUnit.SECONDS.toNanos(Math.min(h3.maxAgeSeconds(), TimeUnit.DAYS.toSeconds(365)));
                Alternative previous = alternatives.put(key, new Alternative(h3.port(), clock.getAsLong() + ttl));
                if (previous == null) LOG.log(Level.DEBUG, hostAndPort + " advertises HTTP/3 on UDP port " + h3.port());
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Learns that a client just spoke HTTP/3 to {@code hostAndPort}, on its own port: the
     * transparent QUIC listener intercepted the client's QUIC to it. Remembered for a day unless
     * the server's own advertisement says otherwise; a server whose QUIC handshake fails still
     * goes over TCP, as for any advertisement.
     */
    void spoke(String hostAndPort) {
        int port;
        try {
            port = HostAndPort.parse(hostAndPort, 443).port();
        } catch (IllegalArgumentException e) {
            return;
        }
        String key = origin(hostAndPort);
        lock.lock();
        try {
            Alternative known = alternatives.get(key);
            if (known == null || known.expiresNanos() - clock.getAsLong() <= 0) {
                alternatives.put(key, new Alternative(port, clock.getAsLong() + TimeUnit.DAYS.toNanos(1)));
                LOG.log(Level.DEBUG, "a client spoke HTTP/3 to " + hostAndPort);
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * The UDP port to reach {@code hostAndPort} at over HTTP/3, or -1 when it is not known to speak
     * HTTP/3 (or its advertisement has expired).
     */
    int http3Port(String hostAndPort) {
        String key = origin(hostAndPort);
        lock.lock();
        try {
            Alternative a = alternatives.get(key);
            if (a != null) {
                if (a.expiresNanos() - clock.getAsLong() > 0) return a.port();
                alternatives.remove(key);
            }
        } finally {
            lock.unlock();
        }
        for (Pattern p : forced) {
            if (p.matcher(hostAndPort).find()) {
                try {
                    return HostAndPort.parse(hostAndPort, 443).port();
                } catch (IllegalArgumentException e) {
                    return -1;
                }
            }
        }
        return -1;
    }

    /** Whether the QUIC handshake with {@code key}'s server failed recently. Holds lock. */
    private boolean broken(String key) {
        Long until = brokenUntil.get(key);
        if (until == null) return false;
        if (until - clock.getAsLong() > 0) return true;
        brokenUntil.remove(key);
        return false;
    }

    // ---------------------------------------------------------------------------------------
    // Streams
    // ---------------------------------------------------------------------------------------

    /**
     * A stream for an exchange on the HTTP/3 connection to {@code hostAndPort}, making the
     * connection if there is none; null when the server is not known to speak HTTP/3, its QUIC
     * handshake failed (now or recently), or it takes no new streams: the exchange goes over TCP.
     *
     * @param key what must match for exchanges to share a connection, beyond the server
     * @param trust how the server's certificate is checked; null for the JDK's default trust store
     * @param replaySafe whether the request may go as 0-RTT data: safe to repeat, without a body
     * @param resolve the server's address (its port is replaced by the HTTP/3 one)
     * @throws IOException if the proxy is stopping
     */
    Http3UpstreamStream stream(String key, String hostAndPort, X509TrustManager trust, ClientFlowContext flow, String log,
            boolean headRequest, boolean replaySafe, Resolver resolve) throws IOException {
        int port = http3Port(hostAndPort);
        if (port < 0) return null;
        String connectionKey = key + "|" + port;
        Http3UpstreamConnection c = find(connectionKey);
        boolean made = false;
        if (c == null) {
            if (!claimed(connectionKey)) return null;
            c = connect(connectionKey, hostAndPort, port, trust, resolve, log, replaySafe);
            if (c == null) return null;
            made = true;
        }
        try {
            Http3UpstreamStream stream = c.open(flow, log, headRequest, replaySafe);
            stream.newConnection = made;
            return stream;
        } catch (Http3UpstreamConnection.Unprocessed e) {
            LOG.log(Level.DEBUG, log + e.getMessage() + "; going over TCP");
            return null;
        } catch (IOException e) {
            LOG.log(Level.DEBUG, log + "no HTTP/3 stream to " + hostAndPort + ": " + e.getMessage() + "; going over TCP");
            return null;
        }
    }

    /**
     * The usable connection for {@code key}, waiting (once, up to the handshake timeout) for one
     * another exchange is making; null when there is none, after claiming the making of one for
     * the calling thread unless the key is broken or another thread kept the claim.
     */
    private Http3UpstreamConnection find(String key) throws IOException {
        long deadline = System.nanoTime() + options.upstreamHandshakeTimeout().toNanos() + TimeUnit.MILLISECONDS.toNanos(100);
        Thread waitedFor = null;
        lock.lock();
        try {
            while (true) {
                if (closed) throw new IOException("the proxy is stopping");
                Http3UpstreamConnection c = open.get(key);
                if (c != null && c.usable()) return c;
                if (c != null) open.remove(key);
                if (broken(key)) return null;
                Thread maker = connecting.get(key);
                if (maker == null || !maker.isAlive()) {
                    connecting.put(key, Thread.currentThread());
                    return null;
                }
                if (maker == waitedFor || maker == Thread.currentThread()) return null;
                long remaining;
                while (connecting.get(key) == maker && (remaining = deadline - System.nanoTime()) > 0 && !closed) {
                    changed.awaitNanos(remaining);
                }
                waitedFor = maker;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted waiting for an HTTP/3 connection");
        } finally {
            lock.unlock();
        }
    }

    /** Whether the calling thread holds the claim to make {@code key}'s connection. */
    private boolean claimed(String key) {
        lock.lock();
        try {
            return connecting.get(key) == Thread.currentThread();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Makes the connection for {@code key}, which the calling thread claimed; null if it failed.
     * For a request safe to replay, it returns as soon as the connection can send 0-RTT data, when
     * the server's ticket allows that.
     */
    private Http3UpstreamConnection connect(String key, String hostAndPort, int port, X509TrustManager trust, Resolver resolve,
            String log, boolean replaySafe) {
        Http3UpstreamConnection c = null;
        try {
            InetSocketAddress tcp = resolve.resolve();
            InetSocketAddress remote = new InetSocketAddress(tcp.getAddress(), port);
            String host = HostAndPort.parse(hostAndPort, 443).host();
            QuicClient client = client(trust, remote.getAddress() instanceof Inet6Address);
            QuicConnection quic = replaySafe && options.upstreamZeroRtt()
                    ? client.connectEarly(remote, host, options.upstreamHandshakeTimeout(), sessions)
                    : client.connect(remote, host, options.upstreamHandshakeTimeout(), sessions);
            c = new Http3UpstreamConnection(server, this, quic, key, hostAndPort);
            c.begin();
            LOG.log(Level.DEBUG, log + "HTTP/3 to " + hostAndPort + " (" + remote + ")"
                    + (quic.isZeroRtt() ? ", sending 0-RTT data" : quic.isResumed() ? ", resumed" : ""));
            return c;
        } catch (IOException | RuntimeException e) {
            LOG.log(Level.DEBUG, log + "HTTP/3 to " + hostAndPort + " failed (" + e.getMessage() + "); TCP for "
                    + options.upstreamFailureTimeout().toSeconds() + " s");
            if (c != null) c.shutdown("starting HTTP/3 failed");
            c = null;
            lock.lock();
            try {
                brokenUntil.put(key, clock.getAsLong() + options.upstreamFailureTimeout().toNanos());
            } finally {
                lock.unlock();
            }
            return null;
        } finally {
            boolean late;
            lock.lock();
            try {
                late = closed;
                if (c != null && !late) open.put(key, c);
                if (connecting.get(key) == Thread.currentThread()) connecting.remove(key);
                changed.signalAll();
            } finally {
                lock.unlock();
            }
            if (late && c != null) c.shutdown("the proxy is stopping");
        }
    }

    /** The QUIC client endpoint for {@code trust} and an address family, made on first use. */
    private QuicClient client(X509TrustManager trust, boolean ipv6) throws IOException {
        String key = (trust == null ? "default" : Integer.toHexString(System.identityHashCode(trust))) + (ipv6 ? "|6" : "|4");
        lock.lock();
        try {
            if (closed) throw new IOException("the proxy is stopping");
            QuicClient existing = clients.get(key);
            if (existing != null) return existing;
            TlsConfig.Builder tls = TlsConfig.builder().alpnProtocols("h3").earlyData(options.upstreamZeroRtt());
            if (trust != null && SslContexts.trustsAll(trust)) {
                tls.trustAllCertificates(true);
            } else if (trust != null) {
                tls.trustManager(trust);
            }
            int idle = server.idleTimeoutMillis();
            TransportConfig transport = TransportConfig.builder()
                    .maxIdleTimeout(idle > 0 ? Duration.ofMillis(idle) : Duration.ZERO)
                    // A server opens no request streams; its unidirectional streams are a few.
                    .maxConcurrentBidiStreams(0)
                    .maxConcurrentUniStreams(16)
                    .streamReceiveWindow(options.streamReceiveWindow())
                    .receiveWindow(options.connectionReceiveWindow())
                    .congestionControl(Http3Listener.congestionControl(options))
                    .build();
            ClientConfig config = ClientConfig.builder(tls.build()).transport(transport).build();
            InetSocketAddress local = server.localAddress;
            InetSocketAddress bind = local != null && (local.getAddress() instanceof Inet6Address) == ipv6
                    ? new InetSocketAddress(local.getAddress(), 0)
                    : new InetSocketAddress(InetAddress.getByName(ipv6 ? "::" : "0.0.0.0"), 0);
            QuicClient client = QuicClient.create(config, bind, EndpointConfig.defaults());
            clients.put(key, client);
            return client;
        } finally {
            lock.unlock();
        }
    }

    /** Forgets a connection that takes no new streams (GOAWAY, closed). */
    void remove(Http3UpstreamConnection c) {
        lock.lock();
        try {
            open.remove(c.key, c);
        } finally {
            lock.unlock();
        }
    }

    /** The proxy is stopping: every connection and client endpoint is closed. */
    void closeAll() {
        List<Http3UpstreamConnection> all;
        List<QuicClient> endpoints;
        lock.lock();
        try {
            closed = true;
            all = new ArrayList<>(open.values());
            open.clear();
            endpoints = new ArrayList<>(clients.values());
            clients.clear();
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        all.forEach(c -> c.shutdown("the proxy is stopping"));
        endpoints.forEach(QuicClient::close);
    }

    /** The open connections (for tests). */
    List<Http3UpstreamConnection> connections() {
        lock.lock();
        try {
            return new ArrayList<>(open.values());
        } finally {
            lock.unlock();
        }
    }
}
