package org.microproxy;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import javax.net.ssl.SSLSession;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;

/**
 * What an access log needs to know about one finished exchange or flow, handed to {@link
 * ActivityTracker#flowEnded} once it is over: an HTTP exchange once its response has been written
 * (or it was abandoned), a {@code CONNECT} tunnel, a SOCKS client's tunnel, a WebSocket session, a
 * tunnel seen by the TCP hooks, a CONNECT-UDP flow, and a QUIC flow the transparent QUIC listener
 * relayed or intercepted stream by stream, each when it closes.
 *
 * <p>Records are immutable, except for the {@linkplain #uniqueId() unique id}, which is made the
 * first time it is asked for. Values the proxy does not know are {@code null}, or {@code -1} for
 * numbers.
 */
public final class FlowRecord {

    /** What kind of exchange or flow a record is about; {@code %MP_FLOW%} renders its {@link #label()}. */
    public enum Kind {
        /** An HTTP/1.x exchange ({@code h1}). */
        HTTP1("h1"),
        /** An HTTP/2 stream's exchange ({@code h2}). */
        HTTP2("h2"),
        /** An HTTP/3 stream's exchange ({@code h3}). */
        HTTP3("h3"),
        /** A {@code CONNECT} tunnel, over HTTP/1, HTTP/2 or HTTP/3, or a transparent TLS connection ({@code tunnel}). */
        TUNNEL("tunnel"),
        /** A SOCKS client's tunnel ({@code socks}). */
        SOCKS("socks"),
        /** A WebSocket session, from its opening handshake to its close ({@code websocket}). */
        WEBSOCKET("websocket"),
        /** A raw TCP tunnel passed through the TCP hooks ({@code tcp}). */
        TCP("tcp"),
        /** A CONNECT-UDP (MASQUE) flow ({@code udp}). */
        UDP("udp"),
        /** A QUIC flow intercepted stream by stream ({@code quic}). */
        QUIC("quic"),
        /** A transparent QUIC flow whose datagrams were relayed untouched, or dropped ({@code quic_relay}). */
        QUIC_RELAY("quic_relay");

        private final String label;

        Kind(String label) {
            this.label = label;
        }

        /** {@return the short name an access log shows, such as {@code h2} or {@code tunnel}} */
        public String label() {
            return label;
        }

        /** {@return whether this is an HTTP exchange rather than a tunnel or flow} */
        public boolean isHttp() {
            return this == HTTP1 || this == HTTP2 || this == HTTP3;
        }
    }

    private final FlowContext context;
    private final Kind kind;
    private final HttpRequest request;
    private final HttpResponse response;
    private final HttpHeaders trailers;
    private final ResponseSource source;
    private final long startEpochMillis;
    private final long durationNanos;
    private final FlowTimings timings;
    private final long bytesReceived;
    private final long bytesSent;
    private final long upstreamBytesSent;
    private final long upstreamBytesReceived;
    private final InetSocketAddress upstreamAddress;
    private final InetSocketAddress upstreamLocalAddress;
    private final InetSocketAddress downstreamLocalAddress;
    private final String upstreamCluster;
    private final SSLSession upstreamSslSession;
    private final String upstreamTransportFailureReason;
    private final EnumSet<ResponseFlag> responseFlags;
    private final ProxyFailure failure;
    private final String responseCodeDetails;
    private volatile String uniqueId;

    private FlowRecord(Builder b) {
        this.context = b.context;
        this.kind = b.kind;
        this.request = b.request;
        this.response = b.response;
        this.trailers = b.trailers;
        this.source = b.source;
        this.startEpochMillis = b.startEpochMillis;
        this.durationNanos = b.durationNanos;
        this.timings = b.timings;
        this.bytesReceived = b.bytesReceived;
        this.bytesSent = b.bytesSent;
        this.upstreamBytesSent = b.upstreamBytesSent;
        this.upstreamBytesReceived = b.upstreamBytesReceived;
        this.upstreamAddress = b.upstreamAddress;
        this.upstreamLocalAddress = b.upstreamLocalAddress;
        this.downstreamLocalAddress = b.downstreamLocalAddress;
        this.upstreamCluster = b.upstreamCluster;
        this.upstreamSslSession = b.upstreamSslSession;
        this.upstreamTransportFailureReason = b.upstreamTransportFailureReason;
        this.responseFlags = EnumSet.noneOf(ResponseFlag.class);
        this.responseFlags.addAll(b.responseFlags);
        this.failure = b.failure;
        this.responseCodeDetails = b.responseCodeDetails;
        this.uniqueId = b.uniqueId;
    }

    /**
     * Starts a record of an exchange or flow on {@code context}.
     *
     * @param context the client's context of the exchange or flow
     * @param kind what kind of exchange or flow it is
     * @return a builder
     */
    public static Builder builder(FlowContext context, Kind kind) {
        return new Builder(context, kind);
    }

    /** {@return the client's context of the exchange or flow} */
    public FlowContext context() {
        return context;
    }

    /** {@return what kind of exchange or flow this is} */
    public Kind kind() {
        return kind;
    }

    /**
     * The request as the client sent it, before the proxy and filters rewrote it; for a tunnel or
     * a flow, the {@code CONNECT} (real, or made up for a SOCKS client, a transparent connection or
     * a QUIC flow) that opened it. Null when the request could not be read.
     *
     * @return the client's request head, or {@code null}
     */
    public HttpRequest request() {
        return request;
    }

    /** {@return the response head the client got (or that a SOCKS or transparent client's tunnel was answered with), or {@code null}} */
    public HttpResponse response() {
        return response;
    }

    /** {@return the response's trailers, or {@code null} when it had none} */
    public HttpHeaders trailers() {
        return trailers;
    }

    /** {@return where the response came from, or {@code null} when there was none} */
    public ResponseSource source() {
        return source;
    }

    /** {@return the status of the response the client got, or 0 when it got none} */
    public int responseCode() {
        return response == null ? 0 : response.status().code();
    }

    /** {@return when the exchange or flow started (wall clock, epoch milliseconds); 0 when unknown} */
    public long startEpochMillis() {
        return startEpochMillis;
    }

    /**
     * How long the exchange or flow lasted: for HTTP, from the first byte of the request to the
     * last byte of the response (or until it was abandoned); for a tunnel or a flow, until it
     * closed.
     *
     * @return the duration, or empty when unknown
     */
    public Optional<Duration> duration() {
        return durationNanos < 0 ? Optional.empty() : Optional.of(Duration.ofNanos(durationNanos));
    }

    /** {@return the duration in nanoseconds, or -1 when unknown} */
    public long durationNanos() {
        return durationNanos;
    }

    /** {@return the exchange's phase timings (see {@link FlowContext#timings()})} */
    public FlowTimings timings() {
        return timings;
    }

    /**
     * Bytes received from the client: the request body for HTTP, the client's payload for a tunnel
     * or a flow.
     *
     * @return the byte count, or -1 when unknown
     */
    public long bytesReceived() {
        return bytesReceived;
    }

    /**
     * Bytes sent to the client: the response body for HTTP, the server's payload for a tunnel or a
     * flow.
     *
     * @return the byte count, or -1 when unknown
     */
    public long bytesSent() {
        return bytesSent;
    }

    /** {@return the bytes written to the server connection, heads and framing included, or -1 when unknown} */
    public long upstreamBytesSent() {
        return upstreamBytesSent;
    }

    /** {@return the bytes read from the server connection, heads and framing included, or -1 when unknown} */
    public long upstreamBytesReceived() {
        return upstreamBytesReceived;
    }

    /** {@return the address the proxy was connected to for the exchange: the server, or a chained proxy; or {@code null}} */
    public InetSocketAddress upstreamAddress() {
        return upstreamAddress;
    }

    /** {@return the proxy's local address on its connection to the server, or {@code null}} */
    public InetSocketAddress upstreamLocalAddress() {
        return upstreamLocalAddress;
    }

    /** {@return the proxy's local address on the client connection, or {@code null}} */
    public InetSocketAddress downstreamLocalAddress() {
        return downstreamLocalAddress;
    }

    /**
     * The name of where the exchange went: the chained proxy it went through ({@code host:port}),
     * or else the server's {@code host:port}.
     *
     * @return the upstream's name, or {@code null}
     */
    public String upstreamCluster() {
        return upstreamCluster;
    }

    /** {@return the TLS session with the server (or a TLS chained proxy), or {@code null}} */
    public SSLSession upstreamSslSession() {
        return upstreamSslSession;
    }

    /** {@return why the TLS handshake with the server failed, or {@code null}} */
    public String upstreamTransportFailureReason() {
        return upstreamTransportFailureReason;
    }

    /** {@return the response flags (see {@link FlowContext#responseFlags()}), unmodifiable} */
    public Set<ResponseFlag> responseFlags() {
        return java.util.Collections.unmodifiableSet(responseFlags);
    }

    /** {@return why the proxy had to answer itself (see {@link FlowContext#failure()}), or empty} */
    public Optional<ProxyFailure> failure() {
        return Optional.ofNullable(failure);
    }

    /** {@return the response code details (see {@link FlowContext#responseCodeDetails()}), or {@code null}} */
    public String responseCodeDetails() {
        return responseCodeDetails;
    }

    /**
     * An id unique to this exchange or flow: a random UUID made the first time it is asked for.
     *
     * @return the unique id
     */
    public String uniqueId() {
        String id = uniqueId;
        if (id == null) {
            id = UUID.randomUUID().toString();
            uniqueId = id;
        }
        return id;
    }

    @Override
    public String toString() {
        return "FlowRecord[" + kind.label() + " conn " + context.getConnectionId()
                + (context.getStreamId() != 0 ? " stream " + context.getStreamId() : "") + " " + responseCode()
                + " " + ResponseFlag.render(responseFlags, false) + "]";
    }

    /** Builds a {@link FlowRecord}; unset values are unknown. */
    public static final class Builder {
        private final FlowContext context;
        private final Kind kind;
        private HttpRequest request;
        private HttpResponse response;
        private HttpHeaders trailers;
        private ResponseSource source;
        private long startEpochMillis;
        private long durationNanos = -1;
        private FlowTimings timings = FlowTimings.NONE;
        private long bytesReceived = -1;
        private long bytesSent = -1;
        private long upstreamBytesSent = -1;
        private long upstreamBytesReceived = -1;
        private InetSocketAddress upstreamAddress;
        private InetSocketAddress upstreamLocalAddress;
        private InetSocketAddress downstreamLocalAddress;
        private String upstreamCluster;
        private SSLSession upstreamSslSession;
        private String upstreamTransportFailureReason;
        private Set<ResponseFlag> responseFlags = Set.of();
        private ProxyFailure failure;
        private String responseCodeDetails;
        private String uniqueId;

        private Builder(FlowContext context, Kind kind) {
            this.context = Objects.requireNonNull(context);
            this.kind = Objects.requireNonNull(kind);
        }

        /**
         * Sets the client's request.
         *
         * @param request the request head, or {@code null}
         * @return this builder
         */
        public Builder request(HttpRequest request) {
            this.request = request;
            return this;
        }

        /**
         * Sets the response the client got, and where it came from.
         *
         * @param response the response head, or {@code null}
         * @param source where it came from, or {@code null}
         * @return this builder
         */
        public Builder response(HttpResponse response, ResponseSource source) {
            this.response = response;
            this.source = source;
            return this;
        }

        /**
         * Sets the response's trailers.
         *
         * @param trailers the trailers, or {@code null}
         * @return this builder
         */
        public Builder trailers(HttpHeaders trailers) {
            this.trailers = trailers;
            return this;
        }

        /**
         * Sets when the exchange started and how long it lasted.
         *
         * @param startEpochMillis the wall-clock start, in epoch milliseconds
         * @param durationNanos the duration in nanoseconds, or -1 when unknown
         * @return this builder
         */
        public Builder time(long startEpochMillis, long durationNanos) {
            this.startEpochMillis = startEpochMillis;
            this.durationNanos = durationNanos;
            return this;
        }

        /**
         * Sets the phase timings.
         *
         * @param timings the timings
         * @return this builder
         */
        public Builder timings(FlowTimings timings) {
            this.timings = Objects.requireNonNull(timings);
            return this;
        }

        /**
         * Sets the bytes exchanged with the client.
         *
         * @param received bytes received from the client, or -1
         * @param sent bytes sent to the client, or -1
         * @return this builder
         */
        public Builder bytes(long received, long sent) {
            this.bytesReceived = received;
            this.bytesSent = sent;
            return this;
        }

        /**
         * Sets the bytes exchanged with the server, on the wire.
         *
         * @param sent bytes written to the server, or -1
         * @param received bytes read from the server, or -1
         * @return this builder
         */
        public Builder upstreamBytes(long sent, long received) {
            this.upstreamBytesSent = sent;
            this.upstreamBytesReceived = received;
            return this;
        }

        /**
         * Sets what the exchange was connected to.
         *
         * @param address the server or chained proxy, or {@code null}
         * @param localAddress the proxy's end of that connection, or {@code null}
         * @param cluster the chained proxy's or server's name, or {@code null}
         * @param session the TLS session with it, or {@code null}
         * @return this builder
         */
        public Builder upstream(InetSocketAddress address, InetSocketAddress localAddress, String cluster,
                SSLSession session) {
            this.upstreamAddress = address;
            this.upstreamLocalAddress = localAddress;
            this.upstreamCluster = cluster;
            this.upstreamSslSession = session;
            return this;
        }

        /**
         * Sets why the TLS handshake with the server failed.
         *
         * @param reason the reason, or {@code null}
         * @return this builder
         */
        public Builder upstreamTransportFailureReason(String reason) {
            this.upstreamTransportFailureReason = reason;
            return this;
        }

        /**
         * Sets the proxy's local address on the client connection.
         *
         * @param address the address, or {@code null}
         * @return this builder
         */
        public Builder downstreamLocalAddress(InetSocketAddress address) {
            this.downstreamLocalAddress = address;
            return this;
        }

        /**
         * Sets the outcome: flags, failure and details.
         *
         * @param flags the response flags
         * @param failure the failure, or {@code null}
         * @param details the response code details, or {@code null}
         * @return this builder
         */
        public Builder outcome(Set<ResponseFlag> flags, ProxyFailure failure, String details) {
            this.responseFlags = Objects.requireNonNull(flags);
            this.failure = failure;
            this.responseCodeDetails = details;
            return this;
        }

        /**
         * Fixes the unique id instead of making a random one when asked.
         *
         * @param uniqueId the id
         * @return this builder
         */
        public Builder uniqueId(String uniqueId) {
            this.uniqueId = uniqueId;
            return this;
        }

        /** {@return the record} */
        public FlowRecord build() {
            return new FlowRecord(this);
        }
    }
}
