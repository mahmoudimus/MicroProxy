package org.microproxy.impl;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.function.Supplier;
import javax.net.ssl.SSLSession;
import org.microproxy.ClientDetails;
import org.microproxy.ClientHello;
import org.microproxy.FlowContext;
import org.microproxy.FlowTimings;

/**
 * The context of one client connection, which also records the exchange in progress (exchanges on
 * an HTTP/1 connection run one at a time), or of one HTTP/2 stream, which records that stream's
 * exchange (streams run concurrently, so each has its own). {@link org.microproxy.FullFlowContext}s
 * made from it read the same record. Recording costs a few stores into fields allocated once per
 * connection (or stream).
 */
final class ClientFlowContext extends FlowContext {

    // Marks for FlowTimings: System.nanoTime() values, 0 for "not yet".
    static final int DNS_START = 0;
    static final int DNS_END = 1;
    static final int CONNECT_START = 2;
    static final int CONNECT_END = 3;
    static final int TLS_START = 4;
    static final int TLS_END = 5;
    static final int REQUEST_SENT = 6;
    static final int FIRST_RESPONSE_BYTE = 7;
    static final int RESPONSE_COMPLETE = 8;
    private static final int EXCHANGE_MARKS = 9;

    // Written on the connection's thread; trackers on other threads may see slightly stale values.
    private final long[] marks = new long[EXCHANGE_MARKS];
    private long startNanos;
    private long startMillis;
    private long clientTlsStart;
    private long clientTlsEnd;
    /** Status of the server's final response for the current exchange; 0 for none. */
    private int upstreamStatus;
    /** The connection's context, for a stream's; null for the connection's own. */
    private final ClientFlowContext connectionFlow;
    /** The ClientHello that started the connection's session, once read. */
    private volatile ClientHello clientHello;
    /** The session's server (the client's proxy) the current exchange is forwarded through, or null. */
    private volatile String forwardedVia;
    /** The SOCKS version the client connection began with, or 0. */
    private volatile int socksVersion;

    ClientFlowContext(
            long connectionId,
            Supplier<InetSocketAddress> clientAddress,
            Supplier<SSLSession> clientSslSession,
            ClientDetails clientDetails) {
        super(connectionId, clientAddress, clientSslSession, clientDetails);
        this.connectionFlow = null;
    }

    /** The context of HTTP/2 stream {@code streamId} of {@code connection}'s client connection. */
    ClientFlowContext(ClientFlowContext connection, int streamId) {
        this(connection, streamId, org.microproxy.http.HttpVersion.HTTP_2_0);
    }

    /** The context of stream {@code streamId} of {@code connection}'s HTTP/2 or HTTP/3 client connection. */
    ClientFlowContext(ClientFlowContext connection, int streamId, org.microproxy.http.HttpVersion version) {
        super(connection, streamId, version);
        this.connectionFlow = connection;
        // The client handshake that the stream's connection began with.
        clientTlsStart = connection.clientTlsStart;
        clientTlsEnd = connection.clientTlsEnd;
    }

    /** Forgets the previous exchange: the first byte of a new request has arrived. */
    void startExchange() {
        Arrays.fill(marks, 0);
        upstreamStatus = 0;
        startMillis = System.currentTimeMillis();
        startNanos = now();
    }

    /** Records that phase {@code mark} happened now. */
    void mark(int mark) {
        marks[mark] = now();
    }

    /** Records that phase {@code mark} happened now, unless it already has (it began earlier). */
    void markFirst(int mark) {
        if (marks[mark] == 0) {
            marks[mark] = now();
        }
    }

    void clientTlsStarted() {
        clientTlsStart = now();
        clientTlsEnd = 0;
    }

    void clientTlsFinished() {
        clientTlsEnd = now();
    }

    /**
     * Records the ClientHello the client connection's session started with; for a stream's
     * context, the one that started the session inside the stream (an intercepted {@code CONNECT}
     * stream), which the stream's exchange sees rather than its connection's.
     */
    void clientHello(ClientHello hello) {
        clientHello = hello;
    }

    @Override
    public ClientHello getClientHello() {
        ClientHello own = clientHello;
        return own != null || connectionFlow == null ? own : connectionFlow.getClientHello();
    }

    /**
     * The ClientHello recorded for this context itself: for a stream's, the one read in the
     * stream's tunnel, never its connection's; null if none was.
     */
    ClientHello ownClientHello() {
        return clientHello;
    }

    void upstreamStatus(int status) {
        upstreamStatus = status;
    }

    @Override
    public OptionalInt upstreamStatus() {
        int status = upstreamStatus;
        return status == 0 ? OptionalInt.empty() : OptionalInt.of(status);
    }

    /** The client's proxy ({@code host:port}) the current exchange is forwarded through, or null. */
    void forwardedVia(String proxy) {
        forwardedVia = proxy;
    }

    @Override
    public Optional<String> forwardedVia() {
        return Optional.ofNullable(forwardedVia);
    }

    /** Records that the client connection began with a SOCKS handshake of {@code version}. */
    void socksVersion(int version) {
        socksVersion = version;
    }

    @Override
    public OptionalInt socksVersion() {
        int version = socksVersion;
        if (version == 0 && connectionFlow != null) return connectionFlow.socksVersion();
        return version == 0 ? OptionalInt.empty() : OptionalInt.of(version);
    }

    @Override
    public FlowTimings timings() {
        long start = startNanos;
        if (start == 0) {
            return FlowTimings.NONE;
        }
        long tls = clientTlsStart == 0 || clientTlsEnd == 0 ? -1 : clientTlsEnd - clientTlsStart;
        return new FlowTimings(startMillis, offset(DNS_START, start), offset(DNS_END, start),
                offset(CONNECT_START, start), offset(CONNECT_END, start), offset(TLS_START, start),
                offset(TLS_END, start), offset(REQUEST_SENT, start), offset(FIRST_RESPONSE_BYTE, start),
                offset(RESPONSE_COMPLETE, start), tls);
    }

    private long offset(int mark, long start) {
        long at = marks[mark];
        return at == 0 ? -1 : Math.max(0, at - start);
    }

    /** {@link System#nanoTime()}, never 0 (which means "not yet"). */
    private static long now() {
        long t = System.nanoTime();
        return t == 0 ? 1 : t;
    }
}
