package org.microproxy.impl;

import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.QuicServer;
import io.github.mahmoudimus.quic.connection.ConnectionError;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.function.ToLongFunction;
import org.microproxy.stats.Counter;
import org.microproxy.stats.Gauge;
import org.microproxy.stats.Histogram;
import org.microproxy.stats.StatsRegistry;

/**
 * {@code quic.<scope>.*}: the QUIC connections of one scope ({@code downstream}: the HTTP/3
 * listener's; {@code transparent}: the transparent listener's intercepted ones; {@code
 * masque}: those inside CONNECT-UDP flows; {@code upstream}: the proxy's to servers). Observes
 * the scope's endpoints ({@link #observe}): a connection's counts are added when it closes.
 *
 * <p>Nothing is counted per packet: a connection keeps its counts as plain fields of its own
 * ({@link QuicConnection#stats()}), and this observer adds them to the registry once, when the
 * connection closes. Only code that runs QUIC loads this class, so the proxy runs without the
 * optional {@code quic} module; {@link ProxyStats} keeps the scopes as plain objects ({@link #of}).
 * It also closes the connections' qlog files ({@link QlogWriter}) as they end, so it observes the
 * endpoints with qlog on even without metrics.
 */
final class QuicStats implements QuicConnection.Observer {

    /** The scopes: the connections of the HTTP/3 listener, the transparent listener, CONNECT-UDP flows, and to servers. */
    static final String DOWNSTREAM = "downstream";
    static final String TRANSPARENT = "transparent";
    static final String MASQUE = "masque";
    static final String UPSTREAM = "upstream";

    /** Kinds of handshake failure, the tags of {@code handshake_failures}. */
    private static final String[] ERRORS = {"timed_out", "crypto_error", "connection_refused", "protocol_violation",
        "transport_error", "peer_closed", "application_closed", "local_close", "stateless_reset", "version_mismatch"};

    private final StatsRegistry registry;
    private final String prefix;
    final boolean enabled;
    final Gauge connectionsActive;
    final Counter connectionsTotal;
    private final AtomicReferenceArray<Counter> handshakeFailures = new AtomicReferenceArray<>(ERRORS.length);
    final Histogram handshakeMs;
    final Histogram rttMs;
    final Counter packetsSent;
    final Counter packetsReceived;
    final Counter packetsLost;
    final Counter bytesSent;
    final Counter bytesReceived;
    final Counter bytesLost;
    final Counter probeTimeouts;
    final Counter congestionEvents;
    final Counter keyUpdates;
    final Counter zeroRttAccepted;
    final Counter zeroRttRejected;
    final Counter migrations;
    final Counter natRebindings;
    final Counter pathValidations;
    final Counter pathValidationFailures;
    final Counter strayDatagrams;
    final Counter statelessResetReceived;
    final Counter droppedDatagrams;
    private final ConcurrentHashMap<String, Counter> controllers = new ConcurrentHashMap<>();
    private final List<QuicServer> servers = new CopyOnWriteArrayList<>();
    /** Closes the qlog files of the scope's connections as they end; null without qlog. */
    private final QlogWriter qlog;
    /** {@code server} or {@code client}: the proxy's side of the scope's connections, as qlog names it. */
    private final String vantage;

    /**
     * @param qlog the writer of the scope's connections' qlog files, or null for none
     */
    QuicStats(StatsRegistry registry, String scope, QlogWriter qlog) {
        this.registry = registry;
        this.qlog = qlog;
        this.vantage = scope.equals(UPSTREAM) ? "client" : "server";
        this.enabled = registry.enabled();
        this.prefix = "quic." + scope + ".";
        String p = prefix;
        connectionsActive = registry.gauge(p + "connections_active", "QUIC connections open");
        connectionsTotal = registry.counter(p + "connections_total", "QUIC connections started");
        handshakeMs = registry.histogram(p + "handshake_ms", "Milliseconds from a connection's start to its handshake's end");
        rttMs = registry.histogram(p + "rtt_ms", "Smoothed round-trip time of connections, in milliseconds, when they closed");
        packetsSent = registry.counter(p + "packets_sent_total", "Packets sent, counted when connections close");
        packetsReceived = registry.counter(p + "packets_received_total", "Packets received, counted when connections close");
        packetsLost = registry.counter(p + "packets_lost_total", "Packets deemed lost, counted when connections close");
        bytesSent = registry.counter(p + "bytes_sent_total", "UDP payload bytes sent, counted when connections close");
        bytesReceived = registry.counter(p + "bytes_received_total",
                "UDP payload bytes received, counted when connections close");
        bytesLost = registry.counter(p + "bytes_lost_total", "Bytes of packets deemed lost, counted when connections close");
        probeTimeouts = registry.counter(p + "pto_total", "Probe timeouts that fired, counted when connections close");
        congestionEvents = registry.counter(p + "congestion_events_total", "Congestion events, counted when connections close");
        keyUpdates = registry.counter(p + "key_updates_total", "Key updates, counted when connections close");
        zeroRttAccepted = registry.counter(p + "zero_rtt_accepted", "Connections whose 0-RTT data was accepted");
        zeroRttRejected = registry.counter(p + "zero_rtt_rejected", "Connections whose 0-RTT data was rejected");
        migrations = registry.counter(p + "migrations",
                "Moves to a new path: a client followed to its new address, or the proxy's own switches");
        natRebindings = registry.counter(p + "nat_rebindings", "Migrations to a new port of the client's address");
        pathValidations = registry.counter(p + "path_validations", "PATH_CHALLENGE frames from peers, each answered");
        pathValidationFailures = registry.counter(p + "path_validation_failures",
                "Validations of a new path that got no PATH_RESPONSE in time");
        strayDatagrams = registry.counter(p + "stray_datagrams",
                "Datagrams from an address a connection takes no packets from, dropped");
        statelessResetReceived = registry.counter(p + "stateless_reset_received", "Connections ended by a peer's stateless reset");
        droppedDatagrams = registry.counter(p + "dropped_datagrams",
                "Datagrams dropped because a connection fell behind, counted when connections close");
        if (enabled) {
            registry.counter(p + "version_negotiation_sent", "Version Negotiation packets sent",
                    () -> sum(s -> s.endpointStats().versionNegotiationsSent()));
            registry.counter(p + "retry_sent", "Retry packets sent", () -> sum(s -> s.endpointStats().retriesSent()));
            registry.counter(p + "stateless_reset_sent", "Stateless resets sent",
                    () -> sum(s -> s.endpointStats().statelessResetsSent()));
            registry.counter(p + "connections_refused", "Connections refused before they started (busy, invalid token)",
                    () -> sum(s -> s.endpointStats().connectionsRefused()));
        }
    }

    /** The stats of {@code scope}, made the first time. */
    static QuicStats of(DefaultHttpProxyServer server, String scope) {
        ProxyStats stats = server.stats;
        return (QuicStats) stats.quicScope(scope, () -> new QuicStats(stats.registry, scope, QlogWriter.of(server)));
    }

    private long sum(ToLongFunction<QuicServer> f) {
        long total = 0;
        for (QuicServer s : servers) total += f.applyAsLong(s);
        return total;
    }

    /** Counts {@code server}'s connections here, and its endpoint's own answers. */
    void observe(QuicServer server) {
        if (!enabled && qlog == null) return;
        if (enabled) servers.add(server);
        server.observe(this);
    }

    /** Counts {@code client}'s connections here. */
    void observe(QuicClient client) {
        if (enabled || qlog != null) client.observe(this);
    }

    @Override
    public void opened(QuicConnection connection) {
        connectionsTotal.inc();
        connectionsActive.inc();
    }

    @Override
    public void handshakeCompleted(QuicConnection connection, Duration elapsed) {
        handshakeMs.recordNanos(elapsed.toNanos());
    }

    @Override
    public void closed(QuicConnection connection, QuicConnection.Stats s, ConnectionError reason,
            boolean handshakeCompleted) {
        if (!handshakeCompleted) handshakeFailure(reason).inc();
        if (reason != null && reason.kind() == ConnectionError.Kind.RESET) statelessResetReceived.inc();
        if (handshakeCompleted) rttMs.recordNanos(s.rtt().toNanos());
        packetsSent.add(s.sentPackets());
        packetsReceived.add(s.receivedPackets());
        packetsLost.add(s.lostPackets());
        bytesSent.add(s.sentBytes());
        bytesReceived.add(s.receivedBytes());
        bytesLost.add(s.lostBytes());
        probeTimeouts.add(s.probeTimeouts());
        congestionEvents.add(s.congestionEvents());
        keyUpdates.add(s.keyUpdates());
        migrations.add(s.migrations());
        natRebindings.add(s.natRebindings());
        pathValidations.add(s.pathValidations());
        pathValidationFailures.add(s.pathValidationFailures());
        strayDatagrams.add(s.strayDatagrams());
        droppedDatagrams.add(s.droppedDatagrams());
        if (s.zeroRttAccepted()) zeroRttAccepted.inc();
        if (s.zeroRttRejected()) zeroRttRejected.inc();
        controller(s.congestionController()).inc();
        if (qlog != null) qlog.closed(vantage, connection.initialDestinationId().toString());
        // Last: a connection no longer active has been counted in full.
        connectionsActive.dec();
    }

    /** {@code congestion_controller.<name>}: connections by congestion controller, a bounded set of names. */
    private Counter controller(String name) {
        Counter c = controllers.get(name);
        if (c == null) {
            c = controllers.computeIfAbsent(name, n -> registry.counter(prefix + "congestion_controller." + n,
                    "Connections closed, by congestion controller"));
        }
        return c;
    }

    /** {@code handshake_failures.<error>} for a connection that ended before its handshake did. */
    Counter handshakeFailure(ConnectionError reason) {
        int i = errorIndex(reason);
        Counter c = handshakeFailures.get(i);
        if (c == null) {
            c = registry.counter(prefix + "handshake_failures." + ERRORS[i], "Connections that ended before their handshake, by error");
            if (!handshakeFailures.compareAndSet(i, null, c)) c = handshakeFailures.get(i);
        }
        return c;
    }

    private static int errorIndex(ConnectionError reason) {
        if (reason == null) return 7;
        return switch (reason.kind()) {
            case TIMED_OUT -> 0;
            case TRANSPORT_ERROR, CONNECTION_CLOSED -> {
                long code = reason.code();
                if (code >= QuicException.CRYPTO_ERROR && code < QuicException.CRYPTO_ERROR + 0x100) yield 1;
                if (code == QuicException.CONNECTION_REFUSED) yield 2;
                if (code == QuicException.PROTOCOL_VIOLATION) yield 3;
                yield reason.kind() == ConnectionError.Kind.TRANSPORT_ERROR ? 4 : 5;
            }
            case APPLICATION_CLOSED -> 6;
            case LOCALLY_CLOSED -> 7;
            case RESET -> 8;
            case VERSION_MISMATCH -> 9;
        };
    }
}
