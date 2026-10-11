package org.microproxy;

import java.time.Duration;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Limits and timers for HTTP/3 ({@link HttpProxyServerBootstrap#withHttp3(boolean)} and {@link
 * HttpProxyServerBootstrap#withHttp3Upstream(boolean)}). Every value has a default meant for
 * browsers and API clients; a client that goes past a limit gets its stream reset, or the
 * connection closed with an HTTP/3 error code. Where HTTP/2 counts frames to defend itself,
 * HTTP/3 leaves much of the work to QUIC: the stream limit and flow control are QUIC's, enforced
 * by the transport.
 *
 * <p>The rate limits count events within {@link Builder#rateWindow(Duration) one window} (10
 * seconds by default); the count starts again with each window.
 *
 * <pre>{@code
 * MicroProxy.bootstrap()
 *         .withReverseProxy("https://backend.internal")
 *         .withSslContextSource(new KeyStoreSslContextSource(Path.of("site.p12"), password))
 *         .withHttp3(true)
 *         .withHttp3Options(Http3Options.builder().maxConcurrentStreams(250).build())
 *         .start();
 * }</pre>
 */
public final class Http3Options {

    /** The congestion controllers of the proxy's QUIC connections (see {@link Builder#quicCongestionControl}). */
    public enum QuicCongestionControl {
        /** CUBIC (RFC 9438), the default. */
        CUBIC,
        /** NewReno (RFC 9002). */
        NEW_RENO,
        /** BBR, experimental: models the bottleneck bandwidth and RTT rather than reacting to loss. */
        BBR;

        /**
         * The controller with a name, ignoring case: {@code cubic}, {@code newreno} (or {@code
         * new_reno}) or {@code bbr}.
         *
         * @param name the name
         * @return the controller
         * @throws IllegalArgumentException for any other name
         */
        public static QuicCongestionControl parse(String name) {
            return switch (name.strip().toLowerCase(java.util.Locale.ROOT)) {
                case "cubic" -> CUBIC;
                case "newreno", "new_reno", "new-reno" -> NEW_RENO;
                case "bbr" -> BBR;
                default -> throw new IllegalArgumentException("unknown QUIC congestion controller: " + name
                        + " (cubic, newreno or bbr)");
            };
        }
    }

    /** The defaults: see each {@link Builder} method. */
    public static final Http3Options DEFAULT = builder().build();

    private final int maxConcurrentStreams;
    private final long streamReceiveWindow;
    private final long connectionReceiveWindow;
    private final long maxFieldSectionSize;
    private final long qpackMaxTableCapacity;
    private final int qpackBlockedStreams;
    private final Duration rateWindow;
    private final int maxUnknownFrames;
    private final int maxUnknownStreams;
    private final int maxRapidResets;
    private final boolean retry;
    private final boolean zeroRtt;
    private final boolean upstreamZeroRtt;
    private final Duration upstreamHandshakeTimeout;
    private final Duration upstreamFailureTimeout;
    private final boolean altSvc;
    private final Duration altSvcMaxAge;
    private final Duration transparentRelayIdleTimeout;
    private final Duration transparentPendingTimeout;
    private final int transparentMaxPending;
    private final int transparentMaxPendingPerSource;
    private final int transparentMaxRelayFlows;
    private final int transparentMaxRelayFlowsPerSource;
    private final long transparentMaxBufferedBytes;
    private final String connectUdpTemplate;
    private final Duration connectUdpIdleTimeout;
    private final int connectUdpMaxFlows;
    private final int connectUdpMaxFlowsPerConnection;
    private final int connectUdpMaxQueued;
    private final long connectUdpMaxQueuedBytes;
    private final boolean connectUdpInterceptQuic;
    private final Set<Integer> connectUdpQuicPorts;
    private final QuicCongestionControl quicCongestionControl;

    private Http3Options(Builder b) {
        maxConcurrentStreams = b.maxConcurrentStreams;
        streamReceiveWindow = b.streamReceiveWindow;
        connectionReceiveWindow = b.connectionReceiveWindow;
        maxFieldSectionSize = b.maxFieldSectionSize;
        qpackMaxTableCapacity = b.qpackMaxTableCapacity;
        qpackBlockedStreams = b.qpackBlockedStreams;
        rateWindow = b.rateWindow;
        maxUnknownFrames = b.maxUnknownFrames;
        maxUnknownStreams = b.maxUnknownStreams;
        maxRapidResets = b.maxRapidResets;
        retry = b.retry;
        zeroRtt = b.zeroRtt;
        upstreamZeroRtt = b.upstreamZeroRtt;
        upstreamHandshakeTimeout = b.upstreamHandshakeTimeout;
        upstreamFailureTimeout = b.upstreamFailureTimeout;
        altSvc = b.altSvc;
        altSvcMaxAge = b.altSvcMaxAge;
        transparentRelayIdleTimeout = b.transparentRelayIdleTimeout;
        transparentPendingTimeout = b.transparentPendingTimeout;
        transparentMaxPending = b.transparentMaxPending;
        transparentMaxPendingPerSource = b.transparentMaxPendingPerSource;
        transparentMaxRelayFlows = b.transparentMaxRelayFlows;
        transparentMaxRelayFlowsPerSource = b.transparentMaxRelayFlowsPerSource;
        transparentMaxBufferedBytes = b.transparentMaxBufferedBytes;
        connectUdpTemplate = b.connectUdpTemplate;
        connectUdpIdleTimeout = b.connectUdpIdleTimeout;
        connectUdpMaxFlows = b.connectUdpMaxFlows;
        connectUdpMaxFlowsPerConnection = b.connectUdpMaxFlowsPerConnection;
        connectUdpMaxQueued = b.connectUdpMaxQueued;
        connectUdpMaxQueuedBytes = b.connectUdpMaxQueuedBytes;
        connectUdpInterceptQuic = b.connectUdpInterceptQuic;
        connectUdpQuicPorts = b.connectUdpQuicPorts;
        quicCongestionControl = b.quicCongestionControl;
    }

    /**
     * Starts a builder with the default settings.
     *
     * @return a new builder with default settings
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Starts a builder initialized with these settings.
     *
     * @return a new builder initialized with these settings
     */
    public Builder toBuilder() {
        Builder b = new Builder();
        b.maxConcurrentStreams = maxConcurrentStreams;
        b.streamReceiveWindow = streamReceiveWindow;
        b.connectionReceiveWindow = connectionReceiveWindow;
        b.maxFieldSectionSize = maxFieldSectionSize;
        b.qpackMaxTableCapacity = qpackMaxTableCapacity;
        b.qpackBlockedStreams = qpackBlockedStreams;
        b.rateWindow = rateWindow;
        b.maxUnknownFrames = maxUnknownFrames;
        b.maxUnknownStreams = maxUnknownStreams;
        b.maxRapidResets = maxRapidResets;
        b.retry = retry;
        b.zeroRtt = zeroRtt;
        b.upstreamZeroRtt = upstreamZeroRtt;
        b.upstreamHandshakeTimeout = upstreamHandshakeTimeout;
        b.upstreamFailureTimeout = upstreamFailureTimeout;
        b.altSvc = altSvc;
        b.altSvcMaxAge = altSvcMaxAge;
        b.transparentRelayIdleTimeout = transparentRelayIdleTimeout;
        b.transparentPendingTimeout = transparentPendingTimeout;
        b.transparentMaxPending = transparentMaxPending;
        b.transparentMaxPendingPerSource = transparentMaxPendingPerSource;
        b.transparentMaxRelayFlows = transparentMaxRelayFlows;
        b.transparentMaxRelayFlowsPerSource = transparentMaxRelayFlowsPerSource;
        b.transparentMaxBufferedBytes = transparentMaxBufferedBytes;
        b.connectUdpTemplate = connectUdpTemplate;
        b.connectUdpIdleTimeout = connectUdpIdleTimeout;
        b.connectUdpMaxFlows = connectUdpMaxFlows;
        b.connectUdpMaxFlowsPerConnection = connectUdpMaxFlowsPerConnection;
        b.connectUdpMaxQueued = connectUdpMaxQueued;
        b.connectUdpMaxQueuedBytes = connectUdpMaxQueuedBytes;
        b.connectUdpInterceptQuic = connectUdpInterceptQuic;
        b.connectUdpQuicPorts = connectUdpQuicPorts;
        b.quicCongestionControl = quicCongestionControl;
        return b;
    }

    /** {@return the request streams a client may have open at once (QUIC's bidirectional stream limit)} */
    public int maxConcurrentStreams() {
        return maxConcurrentStreams;
    }

    /** {@return the flow-control window of each stream: the most a peer may send ahead of the proxy's reading} */
    public long streamReceiveWindow() {
        return streamReceiveWindow;
    }

    /** {@return the flow-control window of a connection, for all its streams together} */
    public long connectionReceiveWindow() {
        return connectionReceiveWindow;
    }

    /**
     * SETTINGS_MAX_FIELD_SECTION_SIZE, or 0 for the default: the proxy's {@code max_header_size}
     * plus {@code max_initial_line_length}, the same room an HTTP/1 request head has.
     *
     * @return the largest field section accepted, or zero to derive it from the HTTP/1 limits
     */
    public long maxFieldSectionSize() {
        return maxFieldSectionSize;
    }

    /** {@return SETTINGS_QPACK_MAX_TABLE_CAPACITY: the QPACK dynamic table each side may use, in bytes} */
    public long qpackMaxTableCapacity() {
        return qpackMaxTableCapacity;
    }

    /** {@return SETTINGS_QPACK_BLOCKED_STREAMS: streams that may wait for the peer's QPACK encoder stream at once} */
    public int qpackBlockedStreams() {
        return qpackBlockedStreams;
    }

    /** {@return the window the rate limits count events in} */
    public Duration rateWindow() {
        return rateWindow;
    }

    /** {@return frames of unknown and reserved types, and empty DATA frames, a peer may send per window} */
    public int maxUnknownFrames() {
        return maxUnknownFrames;
    }

    /** {@return unidirectional streams of unknown and reserved types a peer may open per window} */
    public int maxUnknownStreams() {
        return maxUnknownStreams;
    }

    /** {@return requests a client may cancel before their response completes, per window} */
    public int maxRapidResets() {
        return maxRapidResets;
    }

    /** {@return whether the HTTP/3 listeners validate client addresses with a QUIC Retry first} */
    public boolean retry() {
        return retry;
    }

    /**
     * Whether the HTTP/3 listeners accept 0-RTT early data from clients that resume a session: off
     * by default. See {@link Builder#zeroRtt(boolean)}.
     *
     * @return whether 0-RTT is accepted
     */
    public boolean zeroRtt() {
        return zeroRtt;
    }

    /**
     * Whether requests that are safe to replay go to HTTP/3 servers as 0-RTT early data when the
     * proxy resumes a session with them: on by default. See {@link Builder#upstreamZeroRtt(boolean)}.
     *
     * @return whether the proxy sends 0-RTT data to servers
     */
    public boolean upstreamZeroRtt() {
        return upstreamZeroRtt;
    }

    /** {@return how long a QUIC handshake with a server may take before its request goes over TCP instead} */
    public Duration upstreamHandshakeTimeout() {
        return upstreamHandshakeTimeout;
    }

    /** {@return how long a server whose QUIC handshake failed is reached over TCP only} */
    public Duration upstreamFailureTimeout() {
        return upstreamFailureTimeout;
    }

    /** {@return whether a reverse proxy serving HTTP/3 advertises it with Alt-Svc on its TCP responses} */
    public boolean altSvc() {
        return altSvc;
    }

    /** {@return the max-age ({@code ma}) of the proxy's own Alt-Svc advertisement} */
    public Duration altSvcMaxAge() {
        return altSvcMaxAge;
    }

    /** {@return how long a relayed QUIC flow of the transparent QUIC listener lives without a datagram either way} */
    public Duration transparentRelayIdleTimeout() {
        return transparentRelayIdleTimeout;
    }

    /** {@return how long the transparent QUIC listener waits for a new client's complete ClientHello, and its decision} */
    public Duration transparentPendingTimeout() {
        return transparentPendingTimeout;
    }

    /** {@return the new clients the transparent QUIC listener holds at once while it reads their ClientHellos} */
    public int transparentMaxPending() {
        return transparentMaxPending;
    }

    /** {@return the new clients from one IP address that the transparent QUIC listener holds at once} */
    public int transparentMaxPendingPerSource() {
        return transparentMaxPendingPerSource;
    }

    /** {@return the QUIC flows the transparent QUIC listener relays at once, each with a socket of its own} */
    public int transparentMaxRelayFlows() {
        return transparentMaxRelayFlows;
    }

    /** {@return the relayed QUIC flows of one IP address at once} */
    public int transparentMaxRelayFlowsPerSource() {
        return transparentMaxRelayFlowsPerSource;
    }

    /** {@return the bytes of datagrams the transparent QUIC listener holds for new clients, all together} */
    public long transparentMaxBufferedBytes() {
        return transparentMaxBufferedBytes;
    }

    /** {@return the URI template CONNECT-UDP requests name their target with (RFC 9298)} */
    public String connectUdpTemplate() {
        return connectUdpTemplate;
    }

    /** {@return how long a CONNECT-UDP flow lives without a datagram in either direction} */
    public Duration connectUdpIdleTimeout() {
        return connectUdpIdleTimeout;
    }

    /** {@return the CONNECT-UDP flows the proxy relays at once} */
    public int connectUdpMaxFlows() {
        return connectUdpMaxFlows;
    }

    /** {@return the CONNECT-UDP flows one client connection may have open at once} */
    public int connectUdpMaxFlowsPerConnection() {
        return connectUdpMaxFlowsPerConnection;
    }

    /** {@return the datagrams a CONNECT-UDP flow queues in each direction, beyond which it drops them} */
    public int connectUdpMaxQueued() {
        return connectUdpMaxQueued;
    }

    /** {@return the bytes of datagrams a CONNECT-UDP flow queues in each direction, beyond which it drops them} */
    public long connectUdpMaxQueuedBytes() {
        return connectUdpMaxQueuedBytes;
    }

    /** {@return whether QUIC inside CONNECT-UDP flows is decided on as transparent QUIC is, rather than relayed} */
    public boolean connectUdpInterceptQuic() {
        return connectUdpInterceptQuic;
    }

    /** {@return the target ports of the CONNECT-UDP flows whose QUIC is decided on; empty for every port} */
    public Set<Integer> connectUdpQuicPorts() {
        return connectUdpQuicPorts;
    }

    /** {@return the congestion controller of the proxy's QUIC connections, to clients and to servers} */
    public QuicCongestionControl quicCongestionControl() {
        return quicCongestionControl;
    }

    @Override
    public String toString() {
        return "Http3Options[maxConcurrentStreams=" + maxConcurrentStreams + ", streamReceiveWindow=" + streamReceiveWindow
                + ", connectionReceiveWindow=" + connectionReceiveWindow + ", maxFieldSectionSize=" + maxFieldSectionSize
                + ", qpackMaxTableCapacity=" + qpackMaxTableCapacity + ", qpackBlockedStreams=" + qpackBlockedStreams
                + ", rateWindow=" + rateWindow + ", maxUnknownFrames=" + maxUnknownFrames
                + ", maxUnknownStreams=" + maxUnknownStreams + ", maxRapidResets=" + maxRapidResets + ", retry=" + retry
                + ", zeroRtt=" + zeroRtt + ", upstreamZeroRtt=" + upstreamZeroRtt
                + ", upstreamHandshakeTimeout=" + upstreamHandshakeTimeout
                + ", upstreamFailureTimeout=" + upstreamFailureTimeout + ", altSvc=" + altSvc
                + ", altSvcMaxAge=" + altSvcMaxAge + ", transparentRelayIdleTimeout=" + transparentRelayIdleTimeout
                + ", transparentPendingTimeout=" + transparentPendingTimeout + ", transparentMaxPending="
                + transparentMaxPending + ", transparentMaxPendingPerSource=" + transparentMaxPendingPerSource
                + ", transparentMaxRelayFlows=" + transparentMaxRelayFlows + ", transparentMaxRelayFlowsPerSource="
                + transparentMaxRelayFlowsPerSource + ", transparentMaxBufferedBytes=" + transparentMaxBufferedBytes
                + ", connectUdpTemplate=" + connectUdpTemplate + ", connectUdpIdleTimeout=" + connectUdpIdleTimeout
                + ", connectUdpMaxFlows=" + connectUdpMaxFlows + ", connectUdpMaxFlowsPerConnection="
                + connectUdpMaxFlowsPerConnection + ", connectUdpMaxQueued=" + connectUdpMaxQueued
                + ", connectUdpMaxQueuedBytes=" + connectUdpMaxQueuedBytes + ", connectUdpInterceptQuic="
                + connectUdpInterceptQuic + ", connectUdpQuicPorts=" + connectUdpQuicPorts
                + ", quicCongestionControl=" + quicCongestionControl + "]";
    }

    /** Builds {@link Http3Options}. */
    public static final class Builder {
        private int maxConcurrentStreams = 100;
        private long streamReceiveWindow = 256 * 1024;
        private long connectionReceiveWindow = 1024 * 1024;
        private long maxFieldSectionSize;
        private long qpackMaxTableCapacity = 4096;
        private int qpackBlockedStreams = 16;
        private Duration rateWindow = Duration.ofSeconds(10);
        private int maxUnknownFrames = 1000;
        private int maxUnknownStreams = 100;
        private int maxRapidResets = 100;
        private boolean retry;
        private boolean zeroRtt;
        private boolean upstreamZeroRtt = true;
        private Duration upstreamHandshakeTimeout = Duration.ofSeconds(1);
        private Duration upstreamFailureTimeout = Duration.ofMinutes(5);
        private boolean altSvc = true;
        private Duration altSvcMaxAge = Duration.ofHours(24);
        private Duration transparentRelayIdleTimeout = Duration.ofSeconds(60);
        private Duration transparentPendingTimeout = Duration.ofSeconds(5);
        private int transparentMaxPending = 1024;
        private int transparentMaxPendingPerSource = 32;
        private int transparentMaxRelayFlows = 4096;
        private int transparentMaxRelayFlowsPerSource = 256;
        private long transparentMaxBufferedBytes = 8L * 1024 * 1024;
        private String connectUdpTemplate = "/.well-known/masque/udp/{target_host}/{target_port}/";
        private Duration connectUdpIdleTimeout = Duration.ofSeconds(60);
        private int connectUdpMaxFlows = 4096;
        private int connectUdpMaxFlowsPerConnection = 64;
        private int connectUdpMaxQueued = 128;
        private long connectUdpMaxQueuedBytes = 512 * 1024;
        private boolean connectUdpInterceptQuic;
        private Set<Integer> connectUdpQuicPorts = Set.of(443);
        private QuicCongestionControl quicCongestionControl = QuicCongestionControl.CUBIC;

        private Builder() {}

        /**
         * Request streams a client may have open at once (default 100): QUIC's limit on the
         * bidirectional streams it may open, which the transport enforces and raises as streams
         * end. Each runs its own exchange.
         *
         * @param n the maximum streams open at once
         * @return this builder
         */
        public Builder maxConcurrentStreams(int n) {
            maxConcurrentStreams = positive(n, "maxConcurrentStreams");
            return this;
        }

        /**
         * QUIC's flow-control window per stream (default 256 KiB): the most a peer sends on a
         * stream before the proxy has read it, request bodies from clients and response bodies from
         * servers alike.
         *
         * @param bytes the stream window, at least 16384 bytes
         * @return this builder
         */
        public Builder streamReceiveWindow(long bytes) {
            if (bytes < 16_384) throw new IllegalArgumentException("streamReceiveWindow below 16384: " + bytes);
            streamReceiveWindow = bytes;
            return this;
        }

        /**
         * QUIC's flow-control window per connection (default 1 MiB), for all its streams together.
         *
         * @param bytes the connection window, at least 16384 bytes
         * @return this builder
         */
        public Builder connectionReceiveWindow(long bytes) {
            if (bytes < 16_384) throw new IllegalArgumentException("connectionReceiveWindow below 16384: " + bytes);
            connectionReceiveWindow = bytes;
            return this;
        }

        /**
         * The largest field section the proxy accepts, counted as HTTP/3 counts it (names and
         * values plus 32 octets per field), advertised as SETTINGS_MAX_FIELD_SECTION_SIZE. A larger
         * request is answered {@code 431}, a larger response fails its exchange. 0 (the default)
         * derives it from the HTTP/1 limits: {@code withMaxHeaderSize} plus {@code
         * withMaxInitialLineLength}.
         *
         * @param bytes the limit, or zero to derive it from the HTTP/1 limits
         * @return this builder
         */
        public Builder maxFieldSectionSize(long bytes) {
            if (bytes < 0) throw new IllegalArgumentException("negative maxFieldSectionSize: " + bytes);
            maxFieldSectionSize = bytes;
            return this;
        }

        /**
         * The QPACK dynamic table (default 4096 bytes): the most the proxy keeps for a peer's
         * field sections, advertised as SETTINGS_QPACK_MAX_TABLE_CAPACITY, and the most it uses
         * for its own. 0 turns the dynamic table off: field sections are encoded with the static
         * table and literals only.
         *
         * @param bytes the table capacity, 0 or more
         * @return this builder
         */
        public Builder qpackMaxTableCapacity(long bytes) {
            if (bytes < 0 || bytes > (1L << 30)) throw new IllegalArgumentException("qpackMaxTableCapacity out of range: " + bytes);
            qpackMaxTableCapacity = bytes;
            return this;
        }

        /**
         * Streams whose field sections may wait for the peer's QPACK encoder stream at once
         * (default 16), advertised as SETTINGS_QPACK_BLOCKED_STREAMS. One more is a connection
         * error QPACK_DECOMPRESSION_FAILED; each waits at most the idle timeout.
         *
         * @param n the limit, 0 or more
         * @return this builder
         */
        public Builder qpackBlockedStreams(int n) {
            if (n < 0) throw new IllegalArgumentException("negative qpackBlockedStreams: " + n);
            qpackBlockedStreams = n;
            return this;
        }

        /**
         * The window the rate limits below count events in (default 10 s).
         *
         * @param window the counting window
         * @return this builder
         */
        public Builder rateWindow(Duration window) {
            rateWindow = positive(window, "rateWindow");
            return this;
        }

        /**
         * Frames of unknown and reserved types (which HTTP/3 says to ignore), and empty DATA
         * frames, a peer may send per window, on all its streams together (default 1000); more is
         * a connection error H3_EXCESSIVE_LOAD.
         *
         * @param n the maximum per window
         * @return this builder
         */
        public Builder maxUnknownFrames(int n) {
            maxUnknownFrames = positive(n, "maxUnknownFrames");
            return this;
        }

        /**
         * Unidirectional streams of unknown and reserved types (which HTTP/3 says to abandon) a
         * peer may open per window (default 100); more is a connection error H3_EXCESSIVE_LOAD.
         *
         * @param n the maximum per window
         * @return this builder
         */
        public Builder maxUnknownStreams(int n) {
            maxUnknownStreams = positive(n, "maxUnknownStreams");
            return this;
        }

        /**
         * Requests a client may cancel (reset) before their response completes, per window
         * (default 100), against the Rapid Reset attack; more is a connection error
         * H3_EXCESSIVE_LOAD.
         *
         * @param n the maximum per window
         * @return this builder
         */
        public Builder maxRapidResets(int n) {
            maxRapidResets = positive(n, "maxRapidResets");
            return this;
        }

        /**
         * Whether the HTTP/3 listener answers a client's first packet with a QUIC Retry, so that
         * only clients that can receive at their address cost it a handshake (default off: it
         * costs every client a round trip). The transparent QUIC listener sends Retry only to the
         * clients it intercepts: a relayed client's server would refuse the token.
         *
         * @param retry whether to send Retry
         * @return this builder
         */
        public Builder retry(boolean retry) {
            this.retry = retry;
            return this;
        }

        /**
         * Whether the HTTP/3 listeners ({@code --http3} and the clients the transparent QUIC
         * listener intercepts) accept 0-RTT early data (default off). The listeners always send
         * session tickets and resume sessions, which saves a client the certificate exchange; with
         * 0-RTT on, a resuming client may also send its first requests before the handshake
         * completes, saving a round trip.
         *
         * <p>Early data can be replayed: an attacker who captures a client's first flight can send
         * it again (RFC 8446 section 8). The QUIC layer accepts a ticket's early data once, and only
         * while the client's ticket age matches the proxy's, within one process. On top of that the
         * proxy treats a request any part of which arrived as early data as RFC 8470 says: it
         * answers {@code 425 Too Early} unless the method is safe to repeat ({@code GET}, {@code
         * HEAD} or {@code OPTIONS}, without a body), and forwards the rest with {@code Early-Data:
         * 1}, so the server can answer {@code 425} itself. Filters see {@link
         * org.microproxy.FlowContext#isEarlyData()} (Starlark {@code ctx.early_data}) and may
         * answer {@code 425} to requests they deem unsafe; a client sends them again once its
         * handshake completes.
         *
         * @param enabled whether to accept 0-RTT
         * @return this builder
         */
        public Builder zeroRtt(boolean enabled) {
            zeroRtt = enabled;
            return this;
        }

        /**
         * Whether the proxy sends requests to HTTP/3 servers as 0-RTT early data when it resumes a
         * session with them (default on). Only requests safe to repeat go early: {@code GET},
         * {@code HEAD} and {@code OPTIONS} without a body (RFC 8470 section 2.1); others wait for
         * the handshake. A server that answers {@code 425 Too Early} gets the request again after
         * the handshake, unless the request itself arrived as early data, whose client gets the
         * {@code 425}. The proxy keeps session tickets per server for as long as it runs.
         *
         * @param enabled whether to send 0-RTT data to servers
         * @return this builder
         */
        public Builder upstreamZeroRtt(boolean enabled) {
            upstreamZeroRtt = enabled;
            return this;
        }

        /**
         * How long a QUIC handshake with a server may take (default 1 s) before the request goes
         * over TCP instead; the server then stays on TCP for the {@link #upstreamFailureTimeout}.
         *
         * @param timeout the handshake timeout
         * @return this builder
         */
        public Builder upstreamHandshakeTimeout(Duration timeout) {
            upstreamHandshakeTimeout = positive(timeout, "upstreamHandshakeTimeout");
            return this;
        }

        /**
         * How long a server whose QUIC handshake failed or timed out is reached over TCP only
         * (default 5 minutes), before HTTP/3 is tried again.
         *
         * @param timeout how long a failure is remembered
         * @return this builder
         */
        public Builder upstreamFailureTimeout(Duration timeout) {
            upstreamFailureTimeout = positive(timeout, "upstreamFailureTimeout");
            return this;
        }

        /**
         * Whether a reverse proxy serving HTTP/3 adds {@code Alt-Svc: h3=":<port>"} to the
         * responses it sends over TCP (default on), so that clients find its HTTP/3 listener. A
         * response whose server's own {@code Alt-Svc} field is left after the {@code h3} stripping
         * keeps it instead, and {@code proxyToClientResponse} filters may remove the field.
         *
         * @param advertise whether to advertise HTTP/3
         * @return this builder
         */
        public Builder altSvc(boolean advertise) {
            altSvc = advertise;
            return this;
        }

        /**
         * How long clients may remember the proxy's HTTP/3 advertisement (the {@code ma}
         * parameter, default 24 hours).
         *
         * @param maxAge the advertisement's lifetime, in whole seconds
         * @return this builder
         */
        public Builder altSvcMaxAge(Duration maxAge) {
            altSvcMaxAge = positive(maxAge, "altSvcMaxAge");
            return this;
        }

        /**
         * How long a QUIC flow that the transparent QUIC listener relays untouched (an ignored
         * host, a client offering no HTTP/3) lives without a datagram in either direction (default
         * 60 s), after which its socket to the server is closed. Make it at least the QUIC idle
         * timeout of the clients and servers (often 30 s).
         *
         * @param timeout the idle timeout of a relayed flow
         * @return this builder
         * @see HttpProxyServerBootstrap#withTransparentQuicPort(int)
         */
        public Builder transparentRelayIdleTimeout(Duration timeout) {
            transparentRelayIdleTimeout = positive(timeout, "transparentRelayIdleTimeout");
            return this;
        }

        /**
         * How long the transparent QUIC listener holds a new client's datagrams (default 5 s) for
         * its ClientHello to complete and the proxy to decide on it; a client still pending then is
         * forgotten, its datagrams dropped.
         *
         * @param timeout the longest a client may stay pending
         * @return this builder
         */
        public Builder transparentPendingTimeout(Duration timeout) {
            transparentPendingTimeout = positive(timeout, "transparentPendingTimeout");
            return this;
        }

        /**
         * The new clients (half-open QUIC flows: Initials whose ClientHello is being read or decided
         * on) the transparent QUIC listener holds at once (default 1024), and from one IP address
         * (default 32). Initials of further new clients are dropped, as a full socket buffer would
         * drop them; clients send them again.
         *
         * @param total the most new clients held at once
         * @param perSource the most new clients of one IP address held at once
         * @return this builder
         */
        public Builder transparentMaxPending(int total, int perSource) {
            transparentMaxPending = positive(total, "transparentMaxPending");
            transparentMaxPendingPerSource = positive(perSource, "transparentMaxPendingPerSource");
            return this;
        }

        /**
         * The QUIC flows the transparent QUIC listener relays at once (default 4096), and for one
         * IP address (default 256); each has a UDP socket to its server. A new flow past either
         * limit is dropped.
         *
         * @param total the most relayed flows at once
         * @param perSource the most relayed flows of one IP address at once
         * @return this builder
         */
        public Builder transparentMaxRelayFlows(int total, int perSource) {
            transparentMaxRelayFlows = positive(total, "transparentMaxRelayFlows");
            transparentMaxRelayFlowsPerSource = positive(perSource, "transparentMaxRelayFlowsPerSource");
            return this;
        }

        /**
         * The bytes of datagrams the transparent QUIC listener holds for all its new clients
         * together (default 8 MiB); each one may hold 16 datagrams at most. Datagrams past it are
         * dropped.
         *
         * @param bytes the most bytes held, at least 65536
         * @return this builder
         */
        public Builder transparentMaxBufferedBytes(long bytes) {
            if (bytes < 65_536) throw new IllegalArgumentException("transparentMaxBufferedBytes below 65536: " + bytes);
            transparentMaxBufferedBytes = bytes;
            return this;
        }

        /**
         * The URI template that CONNECT-UDP requests (MASQUE, RFC 9298) name their target with, on a
         * forward proxy's HTTP/3 listener: by default the well-known {@code
         * /.well-known/masque/udp/{target_host}/{target_port}/}. A path, optionally with a query,
         * or an absolute URI whose path and query count, with the variables {@code {target_host}}
         * and {@code {target_port}} once each.
         *
         * @param template the template
         * @return this builder
         * @throws IllegalArgumentException if it lacks one of the variables
         */
        public Builder connectUdpTemplate(String template) {
            Objects.requireNonNull(template, "connectUdpTemplate");
            if (!template.contains("{target_host}") || !template.contains("{target_port}")) {
                throw new IllegalArgumentException("a CONNECT-UDP template needs {target_host} and {target_port}: " + template);
            }
            connectUdpTemplate = template;
            return this;
        }

        /**
         * How long a CONNECT-UDP flow lives without a datagram in either direction (default 60
         * s), after which the proxy closes its socket and ends the client's stream.
         *
         * @param timeout the idle timeout of a CONNECT-UDP flow
         * @return this builder
         */
        public Builder connectUdpIdleTimeout(Duration timeout) {
            connectUdpIdleTimeout = positive(timeout, "connectUdpIdleTimeout");
            return this;
        }

        /**
         * The CONNECT-UDP flows the proxy relays at once (default 4096), and that one client
         * connection may have open (default 64); each has a UDP socket of its own. A request past
         * either limit is answered {@code 503}.
         *
         * @param total the most flows at once
         * @param perConnection the most flows of one client connection at once
         * @return this builder
         */
        public Builder connectUdpMaxFlows(int total, int perConnection) {
            connectUdpMaxFlows = positive(total, "connectUdpMaxFlows");
            connectUdpMaxFlowsPerConnection = positive(perConnection, "connectUdpMaxFlowsPerConnection");
            return this;
        }

        /**
         * The datagrams (default 128) and bytes (default 512 KiB) a CONNECT-UDP flow queues in
         * each direction while the other side is not ready for them (a client that does not read
         * its stream, a target socket that does not keep up). Datagrams past either bound are
         * dropped, as a network drops what it cannot carry.
         *
         * @param datagrams the most datagrams queued in one direction
         * @param bytes the most bytes queued in one direction, at least 65527 (one datagram)
         * @return this builder
         */
        public Builder connectUdpQueue(int datagrams, long bytes) {
            connectUdpMaxQueued = positive(datagrams, "connectUdpMaxQueued");
            if (bytes < 65_527) throw new IllegalArgumentException("connectUdpMaxQueuedBytes below 65527: " + bytes);
            connectUdpMaxQueuedBytes = bytes;
            return this;
        }

        /**
         * Whether QUIC inside CONNECT-UDP flows is decided on as {@linkplain
         * org.microproxy.HttpProxyServerBootstrap#withTransparentQuicPort transparent QUIC} is
         * (default false: relayed as any UDP). A flow to one of the {@linkplain #connectUdpQuicPorts
         * QUIC ports} whose first datagram from the client is a QUIC Initial has its ClientHello
         * read, then goes through the same rules, with the flow's target as the server: HTTP/3 is
         * served as HTTP/3 (filters and frame hooks see its requests), other protocols through the
         * {@linkplain org.microproxy.quic.QuicInterceptor QUIC hooks}, and an ignored or declined
         * host is relayed as before. The ignore and allow host rules then apply to such flows.
         *
         * @param intercept whether to decide on QUIC inside CONNECT-UDP flows
         * @return this builder
         */
        public Builder connectUdpInterceptQuic(boolean intercept) {
            connectUdpInterceptQuic = intercept;
            return this;
        }

        /**
         * The target ports of the CONNECT-UDP flows whose QUIC {@link #connectUdpInterceptQuic} decides
         * on (default 443); none for every port.
         *
         * @param ports the UDP ports, from 1 to 65535
         * @return this builder
         * @throws IllegalArgumentException if a port is out of range
         */
        public Builder connectUdpQuicPorts(int... ports) {
            Set<Integer> set = new TreeSet<>();
            for (int port : ports) {
                if (port < 1 || port > 65535) throw new IllegalArgumentException("not a UDP port: " + port);
                set.add(port);
            }
            connectUdpQuicPorts = Collections.unmodifiableSet(set);
            return this;
        }

        /**
         * The congestion controller of the proxy's QUIC connections, those its HTTP/3 and
         * transparent QUIC listeners accept and those it opens to servers (default {@link
         * QuicCongestionControl#CUBIC CUBIC}). {@link QuicCongestionControl#BBR BBR} is
         * experimental; it suits paths with a large bandwidth-delay product or random loss.
         *
         * @param control the controller
         * @return this builder
         */
        public Builder quicCongestionControl(QuicCongestionControl control) {
            quicCongestionControl = Objects.requireNonNull(control, "control");
            return this;
        }

        /**
         * Creates the configured HTTP/3 options.
         *
         * @return the configured HTTP/3 options
         */
        public Http3Options build() {
            return new Http3Options(this);
        }

        private static int positive(int n, String what) {
            if (n <= 0) throw new IllegalArgumentException(what + " must be positive: " + n);
            return n;
        }

        private static Duration positive(Duration d, String what) {
            Objects.requireNonNull(d, what);
            if (d.isNegative() || d.isZero()) throw new IllegalArgumentException(what + " must be positive: " + d);
            return d;
        }
    }
}
