package org.microproxy;

import java.time.Duration;
import java.util.Objects;

/**
 * Limits for HTTP/2 client connections ({@link HttpProxyServerBootstrap#withHttp2(boolean)}). Every
 * value has a default meant for browsers and API clients; a peer that goes past a limit gets its
 * stream refused or reset, or the connection closed with {@code GOAWAY}. The window sizes apply to
 * the proxy's connections to servers too ({@link HttpProxyServerBootstrap#withHttp2Upstream}), and
 * {@link Builder#coalesceConnections(boolean)} lets those serve more than one server name.
 *
 * <p>The rate limits count frames received within {@link Builder#rateWindow(Duration) one window}
 * (10 seconds by default); the count starts again with each window.
 *
 * <pre>{@code
 * MicroProxy.bootstrap()
 *         .withManInTheMiddle(mitm)      // HTTP/2 to clients and servers is on by default
 *         .withHttp2Options(Http2Options.builder().maxConcurrentStreams(250).build())
 *         .start();
 * }</pre>
 */
public final class Http2Options {

    /** The defaults: see each {@link Builder} method. */
    public static final Http2Options DEFAULT = builder().build();

    private final int maxConcurrentStreams;
    private final int initialWindowSize;
    private final int connectionWindowSize;
    private final int maxHeaderListSize;
    private final Duration settingsAckTimeout;
    private final Duration rateWindow;
    private final int maxRapidResets;
    private final int maxPings;
    private final int maxSettings;
    private final int maxResets;
    private final int maxWindowUpdates;
    private final int maxEmptyFrames;
    private final boolean coalesceConnections;
    private final io.github.mahmoudimus.http2.Http2ClientProfile upstreamProfile;

    private Http2Options(Builder b) {
        maxConcurrentStreams = b.maxConcurrentStreams;
        initialWindowSize = b.initialWindowSize;
        connectionWindowSize = b.connectionWindowSize;
        maxHeaderListSize = b.maxHeaderListSize;
        settingsAckTimeout = b.settingsAckTimeout;
        rateWindow = b.rateWindow;
        maxRapidResets = b.maxRapidResets;
        maxPings = b.maxPings;
        maxSettings = b.maxSettings;
        maxResets = b.maxResets;
        maxWindowUpdates = b.maxWindowUpdates;
        maxEmptyFrames = b.maxEmptyFrames;
        coalesceConnections = b.coalesceConnections;
        upstreamProfile = b.upstreamProfile;
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
        b.initialWindowSize = initialWindowSize;
        b.connectionWindowSize = connectionWindowSize;
        b.maxHeaderListSize = maxHeaderListSize;
        b.settingsAckTimeout = settingsAckTimeout;
        b.rateWindow = rateWindow;
        b.maxRapidResets = maxRapidResets;
        b.maxPings = maxPings;
        b.maxSettings = maxSettings;
        b.maxResets = maxResets;
        b.maxWindowUpdates = maxWindowUpdates;
        b.maxEmptyFrames = maxEmptyFrames;
        b.coalesceConnections = coalesceConnections;
        b.upstreamProfile = upstreamProfile;
        return b;
    }

    /**
     * SETTINGS_MAX_CONCURRENT_STREAMS: streams a client may have open at once.
     *
     * @return the maximum simultaneous client streams
     */
    public int maxConcurrentStreams() {
        return maxConcurrentStreams;
    }

    /**
     * SETTINGS_INITIAL_WINDOW_SIZE: request body bytes buffered per stream, at most.
     *
     * @return the stream receive window size in bytes
     */
    public int initialWindowSize() {
        return initialWindowSize;
    }

    /** {@return the connection's receive window: request body bytes buffered per connection, at most} */
    public int connectionWindowSize() {
        return connectionWindowSize;
    }

    /**
     * SETTINGS_MAX_HEADER_LIST_SIZE, or 0 for the default: the proxy's {@code max_header_size}
     * plus {@code max_initial_line_length}, the same room an HTTP/1 request head has.
     *
     * @return the maximum header list size in bytes, or zero to derive it from HTTP/1 limits
     */
    public int maxHeaderListSize() {
        return maxHeaderListSize;
    }

    /** {@return how long the client may take to acknowledge the proxy's SETTINGS} */
    public Duration settingsAckTimeout() {
        return settingsAckTimeout;
    }

    /** {@return the window the rate limits count frames in} */
    public Duration rateWindow() {
        return rateWindow;
    }

    /** {@return streams the client may reset (or open past the concurrency limit) before they complete, per window} */
    public int maxRapidResets() {
        return maxRapidResets;
    }

    /**
     * PING frames per window.
     *
     * @return the maximum PING frames per rate window
     */
    public int maxPings() {
        return maxPings;
    }

    /**
     * SETTINGS frames per window.
     *
     * @return the maximum SETTINGS frames per rate window
     */
    public int maxSettings() {
        return maxSettings;
    }

    /**
     * RST_STREAM and PRIORITY frames per window.
     *
     * @return the maximum RST_STREAM and PRIORITY frames per rate window
     */
    public int maxResets() {
        return maxResets;
    }

    /**
     * WINDOW_UPDATE frames per window.
     *
     * @return the maximum WINDOW_UPDATE frames per rate window
     */
    public int maxWindowUpdates() {
        return maxWindowUpdates;
    }

    /**
     * DATA frames without data or END_STREAM, and empty trailing HEADERS, per window.
     *
     * @return the maximum empty frames per rate window
     */
    public int maxEmptyFrames() {
        return maxEmptyFrames;
    }

    /**
     * Whether an HTTP/2 connection to a server may carry requests for other server names than the
     * one it was made for (connection coalescing, RFC 9113 section 9.1.1).
     *
     * @return true if connections to servers are coalesced
     * @see Builder#coalesceConnections(boolean)
     */
    public boolean coalesceConnections() {
        return coalesceConnections;
    }

    /**
     * The HTTP/2 fingerprint connections to servers present, or null for the proxy's own.
     *
     * @return the profile, or null
     * @see Builder#upstreamProfile(io.github.mahmoudimus.http2.Http2ClientProfile)
     */
    public io.github.mahmoudimus.http2.Http2ClientProfile upstreamProfile() {
        return upstreamProfile;
    }

    @Override
    public String toString() {
        return "Http2Options[maxConcurrentStreams=" + maxConcurrentStreams + ", initialWindowSize=" + initialWindowSize
                + ", connectionWindowSize=" + connectionWindowSize + ", maxHeaderListSize=" + maxHeaderListSize
                + ", settingsAckTimeout=" + settingsAckTimeout + ", rateWindow=" + rateWindow
                + ", maxRapidResets=" + maxRapidResets + ", maxPings=" + maxPings + ", maxSettings=" + maxSettings
                + ", maxResets=" + maxResets + ", maxWindowUpdates=" + maxWindowUpdates
                + ", maxEmptyFrames=" + maxEmptyFrames + ", coalesceConnections=" + coalesceConnections + "]";
    }

    /** Builds {@link Http2Options}. */
    public static final class Builder {
        private int maxConcurrentStreams = 100;
        private int initialWindowSize = 256 * 1024;
        private int connectionWindowSize = 1024 * 1024;
        private int maxHeaderListSize;
        private Duration settingsAckTimeout = Duration.ofSeconds(10);
        private Duration rateWindow = Duration.ofSeconds(10);
        private int maxRapidResets = 100;
        private int maxPings = 100;
        private int maxSettings = 100;
        private int maxResets = 1000;
        private int maxWindowUpdates = 10_000;
        private int maxEmptyFrames = 1000;
        private boolean coalesceConnections;
        private io.github.mahmoudimus.http2.Http2ClientProfile upstreamProfile;

        private Builder() {}

        /**
         * Streams a client may have open at once (default 100). Each runs its own exchange, with
         * its own server connection; streams beyond the limit are refused with {@code
         * REFUSED_STREAM}, which clients retry.
         *
         * @param n the maximum streams open at once
         * @return this builder
         */
        public Builder maxConcurrentStreams(int n) {
            maxConcurrentStreams = positive(n, "maxConcurrentStreams");
            return this;
        }

        /**
         * The flow-control window of each stream's request body (default 256 KiB): the most the
         * proxy buffers for a stream whose body it has not read yet.
         *
         * @param bytes the stream receive window size, at least 65535 bytes
         * @return this builder
         */
        public Builder initialWindowSize(int bytes) {
            if (bytes < 65_535) throw new IllegalArgumentException("initialWindowSize below 65535: " + bytes);
            initialWindowSize = bytes;
            return this;
        }

        /**
         * The connection's flow-control window (default 1 MiB): the most the proxy buffers for all
         * of a connection's streams together.
         *
         * @param bytes the connection receive window size, at least 65535 bytes
         * @return this builder
         */
        public Builder connectionWindowSize(int bytes) {
            if (bytes < 65_535) throw new IllegalArgumentException("connectionWindowSize below 65535: " + bytes);
            connectionWindowSize = bytes;
            return this;
        }

        /**
         * The largest request header section, counted as HTTP/2 counts it (names and values plus 32
         * octets per field); larger requests have their stream reset. 0 (the default) derives it
         * from the HTTP/1 limits: {@code withMaxHeaderSize} plus {@code withMaxInitialLineLength}.
         *
         * @param bytes the maximum header list size, or zero to derive it from HTTP/1 limits
         * @return this builder
         */
        public Builder maxHeaderListSize(int bytes) {
            if (bytes < 0) throw new IllegalArgumentException("negative maxHeaderListSize: " + bytes);
            maxHeaderListSize = bytes;
            return this;
        }

        /**
         * How long the client may take to acknowledge the proxy's SETTINGS (default 10 s) before {@code GOAWAY SETTINGS_TIMEOUT}.
         *
         * @param timeout the maximum wait for a SETTINGS acknowledgement
         * @return this builder
         */
        public Builder settingsAckTimeout(Duration timeout) {
            settingsAckTimeout = positive(timeout, "settingsAckTimeout");
            return this;
        }

        /**
         * The window the rate limits below count frames in (default 10 s).
         *
         * @param window the frame-counting window duration
         * @return this builder
         */
        public Builder rateWindow(Duration window) {
            rateWindow = positive(window, "rateWindow");
            return this;
        }

        /**
         * Streams the client may reset before their response completes, or open past the
         * concurrency limit, per window (default 100), against the Rapid Reset attack
         * (CVE-2023-44487); more is {@code GOAWAY ENHANCE_YOUR_CALM}.
         *
         * @param n the maximum rapid resets per window
         * @return this builder
         */
        public Builder maxRapidResets(int n) {
            maxRapidResets = positive(n, "maxRapidResets");
            return this;
        }

        /**
         * PING frames per window (default 100); more is {@code GOAWAY ENHANCE_YOUR_CALM}.
         *
         * @param n the maximum PING frames per window
         * @return this builder
         */
        public Builder maxPings(int n) {
            maxPings = positive(n, "maxPings");
            return this;
        }

        /**
         * SETTINGS frames per window (default 100); more is {@code GOAWAY ENHANCE_YOUR_CALM}.
         *
         * @param n the maximum SETTINGS frames per window
         * @return this builder
         */
        public Builder maxSettings(int n) {
            maxSettings = positive(n, "maxSettings");
            return this;
        }

        /**
         * RST_STREAM and PRIORITY frames per window (default 1000); more is {@code GOAWAY ENHANCE_YOUR_CALM}.
         *
         * @param n the maximum RST_STREAM and PRIORITY frames per window
         * @return this builder
         */
        public Builder maxResets(int n) {
            maxResets = positive(n, "maxResets");
            return this;
        }

        /**
         * WINDOW_UPDATE frames per window (default 10000); more is {@code GOAWAY ENHANCE_YOUR_CALM}.
         *
         * @param n the maximum WINDOW_UPDATE frames per window
         * @return this builder
         */
        public Builder maxWindowUpdates(int n) {
            maxWindowUpdates = positive(n, "maxWindowUpdates");
            return this;
        }

        /**
         * Frames that carry nothing, DATA frames with no data and no END_STREAM, per window
         * (default 1000); more is {@code GOAWAY ENHANCE_YOUR_CALM}.
         *
         * @param n the maximum empty frames per window
         * @return this builder
         */
        public Builder maxEmptyFrames(int n) {
            maxEmptyFrames = positive(n, "maxEmptyFrames");
            return this;
        }

        /**
         * Lets the proxy's HTTP/2 connections to servers ({@link
         * HttpProxyServerBootstrap#withHttp2Upstream}) carry requests for other server names than
         * the one each was made for, as RFC 9113 section 9.1.1 allows (default off). A request for
         * {@code b.example.com} may then take a stream on the connection made for {@code
         * a.example.com} when the certificate that server presented is valid for {@code
         * b.example.com}, and either {@code b.example.com} resolves (with the proxy's own resolver)
         * to the address the connection went to, or the server named it in an ORIGIN frame (RFC
         * 8336).
         *
         * <p>Connections are never coalesced across routes (direct, or through which chained
         * proxy), MITM managers, client connections whose connections are private, or TLS settings:
         * the context the MITM manager gives each name must be the same, a manager that configures
         * server sockets itself keeps every connection to its own name, and a connection on which
         * the proxy presented a client certificate serves no other name. A request that a server
         * answers {@code 421 Misdirected Request} on a coalesced connection is sent again on a
         * connection of its own when it can be (no body, a buffered one, or one not read yet), and
         * that name is not coalesced onto that connection again.
         *
         * @param coalesce true to coalesce connections to servers
         * @return this builder
         */
        public Builder coalesceConnections(boolean coalesce) {
            coalesceConnections = coalesce;
            return this;
        }

        /**
         * The HTTP/2 fingerprint of connections to servers (default none: the proxy's own): the
         * profile's SETTINGS in its order, its connection WINDOW_UPDATE, the priority on request
         * HEADERS and its pseudo-header order, such as {@link
         * io.github.mahmoudimus.http2.Http2ClientProfile#chrome156()}, to go with a browser's TLS
         * fingerprint. The connection holds itself to what the profile advertises: its stream and
         * connection receive windows become the profile's (in place of {@link #initialWindowSize}
         * and {@link #connectionWindowSize}), and so does its HPACK table size. With a {@link
         * HttpProxyServerBootstrap#withFrameInterceptor frame interceptor} the HEADERS carry no
         * priority.
         *
         * @param profile the profile, or null for none
         * @return this builder
         */
        public Builder upstreamProfile(io.github.mahmoudimus.http2.Http2ClientProfile profile) {
            upstreamProfile = profile;
            return this;
        }

        /**
         * Creates the configured HTTP/2 limits.
         *
         * @return the configured HTTP/2 limits
         */
        public Http2Options build() {
            return new Http2Options(this);
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
