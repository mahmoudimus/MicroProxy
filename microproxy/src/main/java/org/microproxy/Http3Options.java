package org.microproxy;

import java.time.Duration;
import java.util.Objects;

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
    private final Duration upstreamHandshakeTimeout;
    private final Duration upstreamFailureTimeout;
    private final boolean altSvc;
    private final Duration altSvcMaxAge;

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
        upstreamHandshakeTimeout = b.upstreamHandshakeTimeout;
        upstreamFailureTimeout = b.upstreamFailureTimeout;
        altSvc = b.altSvc;
        altSvcMaxAge = b.altSvcMaxAge;
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
        b.upstreamHandshakeTimeout = upstreamHandshakeTimeout;
        b.upstreamFailureTimeout = upstreamFailureTimeout;
        b.altSvc = altSvc;
        b.altSvcMaxAge = altSvcMaxAge;
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

    /** {@return whether the HTTP/3 listener validates client addresses with a QUIC Retry first} */
    public boolean retry() {
        return retry;
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

    @Override
    public String toString() {
        return "Http3Options[maxConcurrentStreams=" + maxConcurrentStreams + ", streamReceiveWindow=" + streamReceiveWindow
                + ", connectionReceiveWindow=" + connectionReceiveWindow + ", maxFieldSectionSize=" + maxFieldSectionSize
                + ", qpackMaxTableCapacity=" + qpackMaxTableCapacity + ", qpackBlockedStreams=" + qpackBlockedStreams
                + ", rateWindow=" + rateWindow + ", maxUnknownFrames=" + maxUnknownFrames
                + ", maxUnknownStreams=" + maxUnknownStreams + ", maxRapidResets=" + maxRapidResets + ", retry=" + retry
                + ", upstreamHandshakeTimeout=" + upstreamHandshakeTimeout
                + ", upstreamFailureTimeout=" + upstreamFailureTimeout + ", altSvc=" + altSvc
                + ", altSvcMaxAge=" + altSvcMaxAge + "]";
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
        private Duration upstreamHandshakeTimeout = Duration.ofSeconds(1);
        private Duration upstreamFailureTimeout = Duration.ofMinutes(5);
        private boolean altSvc = true;
        private Duration altSvcMaxAge = Duration.ofHours(24);

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
         * costs every client a round trip).
         *
         * @param retry whether to send Retry
         * @return this builder
         */
        public Builder retry(boolean retry) {
            this.retry = retry;
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
