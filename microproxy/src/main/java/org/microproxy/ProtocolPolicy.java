package org.microproxy;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * How the proxy behaves, where it can behave in more than one way, for the exchanges of clients
 * that speak one protocol: HTTP/1.x, HTTP/2 or HTTP/3 (the protocol the client speaks to the
 * proxy, {@link FlowContext#getHttpVersion()}). Configured on the bootstrap per protocol ({@link
 * HttpProxyServerBootstrap#onHttp1}, {@link HttpProxyServerBootstrap#onHttp2}, {@link
 * HttpProxyServerBootstrap#onHttp3}) and for all of them ({@link
 * HttpProxyServerBootstrap#onAllProtocols}), so that a proxy can, say, keep LittleProxy's order
 * of events for its HTTP/1.1 clients while serving HTTP/2 and HTTP/3 clients natively:
 *
 * <pre>{@code
 * MicroProxy.bootstrap()
 *         .onHttp1(p -> p.preset(ProtocolPolicy.littleProxy()))
 *         .onHttp3(p -> p.tlsRetryWithoutSni(true))
 *         .start();
 * }</pre>
 *
 * <p>A policy sets some of its fields and leaves the others to whatever applies below it. For an
 * exchange the proxy takes each field from, in order: the request's own filters, where a hook
 * decides that field for one request; the policy of the client's protocol; the policy for all
 * protocols ({@code onAllProtocols} and the bootstrap's own setters, such as {@link
 * HttpProxyServerBootstrap#withTlsRetryWithoutSni}); and last the protocol's defaults, which are
 * {@link #defaults()} except for HTTP/1 with {@link
 * HttpProxyServerBootstrap#withLittleProxyCompatibility()}, which makes them {@link
 * #littleProxy()}.
 *
 * <p>Which policy applies: an HTTP/1.x connection's exchanges (its {@code CONNECT}s included)
 * take HTTP/1's; an HTTP/2 connection's streams (their {@code CONNECT}s and extended {@code
 * CONNECT}s included) HTTP/2's; an HTTP/3 connection's streams HTTP/3's. The requests a client
 * sends inside a tunnel the proxy intercepts take the policy of what the client speaks inside it,
 * which may differ from that of the {@code CONNECT} that opened it (HTTP/1.1 inside a {@code
 * CONNECT} stream of an HTTP/2 connection, say). SOCKS clients and transparent TLS connections,
 * whose {@code CONNECT} the proxy makes up, are HTTP/1 connections until what they carry says
 * otherwise (HTTP/2 negotiated inside the intercepted TLS); a reverse proxy's clients take the
 * policy of the protocol they speak to it; transparent QUIC and the QUIC inside a CONNECT-UDP
 * flow are HTTP/3.
 *
 * <p>Instances are immutable and thread-safe, and equal when they set the same fields alike.
 */
public final class ProtocolPolicy {

    private static final ProtocolPolicy EMPTY = new Builder().build();

    private static final ProtocolPolicy DEFAULTS = new Builder()
            .resolveBeforeProxyToServerRequest(false)
            .filterConnectAnswer(true)
            .servePlainHttpAfterConnect(true)
            .proxyProtocolDestination(ProxyProtocolDestination.LOCAL_ADDRESS)
            .tlsRetryWithoutSni(false)
            .generatedResponses(GeneratedResponses.REPLACEABLE)
            .build();

    private static final ProtocolPolicy LITTLE_PROXY = new Builder()
            .resolveBeforeProxyToServerRequest(true)
            .filterConnectAnswer(false)
            .servePlainHttpAfterConnect(false)
            .proxyProtocolDestination(ProxyProtocolDestination.SERVER_ADDRESS)
            .tlsRetryWithoutSni(true)
            .generatedResponses(GeneratedResponses.REPLACEABLE)
            .build();

    private final Boolean resolveBeforeProxyToServerRequest;
    private final Boolean filterConnectAnswer;
    private final Boolean servePlainHttpAfterConnect;
    private final ProxyProtocolDestination proxyProtocolDestination;
    private final Boolean tlsRetryWithoutSni;
    private final Boolean allowChunkedLength;
    private final GeneratedResponses generatedResponses;

    private ProtocolPolicy(Builder b) {
        resolveBeforeProxyToServerRequest = b.resolveBeforeProxyToServerRequest;
        filterConnectAnswer = b.filterConnectAnswer;
        servePlainHttpAfterConnect = b.servePlainHttpAfterConnect;
        proxyProtocolDestination = b.proxyProtocolDestination;
        tlsRetryWithoutSni = b.tlsRetryWithoutSni;
        allowChunkedLength = b.allowChunkedLength;
        generatedResponses = b.generatedResponses;
    }

    /**
     * A policy that sets nothing: every field is left to what applies below it.
     *
     * @return the empty policy
     */
    public static ProtocolPolicy empty() {
        return EMPTY;
    }

    /**
     * MicroProxy's defaults, every field set (but the HTTP/1-only {@link #allowChunkedLength()},
     * which {@link HttpProxyServerBootstrap#withAllowChunkedLength} decides):
     *
     * <ul>
     *   <li>{@link #resolveBeforeProxyToServerRequest()}: {@code false}, so {@link
     *       HttpFilters#proxyToServerRequest} can answer or redirect a request without a DNS
     *       lookup;
     *   <li>{@link #filterConnectAnswer()}: {@code true}, so response filters see the {@code 200}
     *       that opens a {@code CONNECT} tunnel and can turn it into a refusal;
     *   <li>{@link #servePlainHttpAfterConnect()}: {@code true}, so plain HTTP sent after a {@code
     *       CONNECT} that could be intercepted (a {@code ws://} WebSocket, say) is served as HTTP,
     *       its requests seen by filters;
     *   <li>{@link #proxyProtocolDestination()}: {@link ProxyProtocolDestination#LOCAL_ADDRESS};
     *   <li>{@link #tlsRetryWithoutSni()}: {@code false};
     *   <li>{@link #generatedResponses()}: {@link GeneratedResponses#REPLACEABLE}, so a filter can
     *       brand the proxy's own responses.
     * </ul>
     *
     * @return MicroProxy's default policy
     */
    public static ProtocolPolicy defaults() {
        return DEFAULTS;
    }

    /**
     * LittleProxy's behaviour, as of LittleProxy 2.9.1, every field set (but the HTTP/1-only
     * {@link #allowChunkedLength()}: LittleProxy rejects such requests, through Netty's {@code
     * HttpObjectDecoder}, as MicroProxy does by default). {@link
     * HttpProxyServerBootstrap#withLittleProxyCompatibility()} makes it HTTP/1's defaults;
     * LittleProxy never spoke HTTP/2 or HTTP/3. Field by field:
     *
     * <ul>
     *   <li>{@link #resolveBeforeProxyToServerRequest()}: {@code true}. {@code
     *       ClientToProxyConnection.doReadHTTPInitial} creates the server connection ({@code
     *       ProxyToServerConnection.create}, whose {@code setupConnectionParameters} resolves the
     *       server) before it calls {@code proxyToServerRequest}, and answers {@code 502} without
     *       calling it when the name does not resolve.
     *   <li>{@link #filterConnectAnswer()}: {@code false}. {@code
     *       ClientToProxyConnection.RespondCONNECTSuccessful} writes the {@code 200 Connection
     *       established} straight to the client: no response filter sees it.
     *   <li>{@link #servePlainHttpAfterConnect()}: {@code false}. With interception on, a {@code
     *       CONNECT} to a server that does not speak TLS is answered and relayed as it is ({@code
     *       ProxyToServerConnection.initializeConnectionFlow}, after {@code
     *       shouldRetryWithoutSsl}); what the client sends then is only looked at for a TLS
     *       handshake ({@code checkAndPerformTlsDetection}).
     *   <li>{@link #proxyProtocolDestination()}: {@link ProxyProtocolDestination#SERVER_ADDRESS}
     *       ({@code ProxyToServerConnection.SendProxyProtocolHeader}).
     *   <li>{@link #tlsRetryWithoutSni()}: {@code true}. {@code
     *       ProxyToServerConnection.connectionFailed} connects again without SNI after an {@code
     *       unrecognized_name} handshake failure.
     *   <li>{@link #generatedResponses()}: {@link GeneratedResponses#REPLACEABLE}. {@code
     *       ClientToProxyConnection.respondWithShortCircuitResponse}, which writes the proxy's error
     *       responses ({@code writeBadGateway}, {@code writeBadRequest}, {@code
     *       writeGatewayTimeout}) and filters' short-circuit responses, runs {@code
     *       proxyToClientResponse} and writes the response it returns. (LittleProxy 1.x wrote the
     *       response it was given instead, which forks of it kept: {@link
     *       GeneratedResponses#IN_PLACE}.)
     * </ul>
     *
     * @return LittleProxy's policy
     */
    public static ProtocolPolicy littleProxy() {
        return LITTLE_PROXY;
    }

    /**
     * A preset policy by its configuration name: {@code littleproxy} for {@link #littleProxy()},
     * {@code microproxy} or {@code defaults} for {@link #defaults()} (any case).
     *
     * @param name the preset's name
     * @return the preset
     * @throws IllegalArgumentException for any other name
     */
    public static ProtocolPolicy preset(String name) {
        return switch (token(name)) {
            case "littleproxy" -> LITTLE_PROXY;
            case "microproxy", "defaults" -> DEFAULTS;
            default -> throw new IllegalArgumentException("unknown protocol policy preset (littleproxy or microproxy): "
                    + name.strip());
        };
    }

    /**
     * A builder for a policy for all protocols, HTTP/2 or HTTP/3; HTTP/1's is an {@link
     * Http1PolicyBuilder}.
     *
     * @return an empty builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Whether the server's name is resolved before {@link HttpFilters#proxyToServerRequest} runs,
     * so that a name that does not resolve is answered {@code 502} without that hook being called
     * (as LittleProxy does), rather than after it, so that the hook can answer or redirect the
     * request without a DNS lookup (MicroProxy's default). Applies to direct connections; a
     * request through a chained proxy is never resolved by the proxy.
     *
     * @return the field's value, or empty when this policy leaves it unset
     */
    public Optional<Boolean> resolveBeforeProxyToServerRequest() {
        return Optional.ofNullable(resolveBeforeProxyToServerRequest);
    }

    /**
     * Whether the proxy's {@code 200 Connection established} answer to a client's {@code CONNECT}
     * goes through {@link HttpFilters#serverToProxyResponse} and {@link
     * HttpFilters#proxyToClientResponse}, so that filters can see it or turn it into a refusal
     * (MicroProxy's default), rather than straight to the client (as LittleProxy writes it).
     * Either way trackers are told ({@link ActivityTracker#responseSentToClient}), and {@link
     * HttpFilters#proxyToClientResponseSent} and {@link HttpFilters#exchangeEnded} run. The
     * {@code CONNECT}s the proxy makes up itself (transparent TLS, SOCKS, raw TCP reverse
     * proxying) always go through the filters.
     *
     * @return the field's value, or empty when this policy leaves it unset
     */
    public Optional<Boolean> filterConnectAnswer() {
        return Optional.ofNullable(filterConnectAnswer);
    }

    /**
     * Whether plain HTTP that a client sends after a {@code CONNECT} that could be intercepted (a
     * {@code ws://} WebSocket through the proxy, say) is served as HTTP, its requests going
     * through the filters to the {@code CONNECT}'s target (MicroProxy's default), rather than
     * relayed to the target as raw bytes (as LittleProxy does).
     *
     * @return the field's value, or empty when this policy leaves it unset
     */
    public Optional<Boolean> servePlainHttpAfterConnect() {
        return Optional.ofNullable(servePlainHttpAfterConnect);
    }

    /**
     * Which address a PROXY protocol header the proxy sends to a server names as its destination
     * ({@link ProxyProtocolDestination}).
     *
     * @return the field's value, or empty when this policy leaves it unset
     */
    public Optional<ProxyProtocolDestination> proxyProtocolDestination() {
        return Optional.ofNullable(proxyProtocolDestination);
    }

    /**
     * Whether a TLS handshake with a server that rejects the server name the proxy sends with an
     * {@code unrecognized_name} alert is tried once more without SNI (see {@link
     * HttpProxyServerBootstrap#withTlsRetryWithoutSni}).
     *
     * @return the field's value, or empty when this policy leaves it unset
     */
    public Optional<Boolean> tlsRetryWithoutSni() {
        return Optional.ofNullable(tlsRetryWithoutSni);
    }

    /**
     * How {@link HttpFilters#proxyToClientResponse} treats the responses the proxy answers with
     * itself: its error responses and the short-circuit responses filters returned from earlier
     * hooks ({@link GeneratedResponses}): it may replace them ({@link
     * GeneratedResponses#REPLACEABLE}), change them in place only ({@link
     * GeneratedResponses#IN_PLACE}), or never see them ({@link GeneratedResponses#SKIP}).
     *
     * @return the field's value, or empty when this policy leaves it unset
     */
    public Optional<GeneratedResponses> generatedResponses() {
        return Optional.ofNullable(generatedResponses);
    }

    /**
     * HTTP/1 only: whether an HTTP/1.1 request with both {@code Transfer-Encoding} and {@code
     * Content-Length} is accepted (see {@link HttpProxyServerBootstrap#withAllowChunkedLength}).
     * Set with {@link Http1PolicyBuilder#allowChunkedLength}; a policy for other protocols
     * ignores it.
     *
     * @return the field's value, or empty when this policy leaves it unset
     */
    public Optional<Boolean> allowChunkedLength() {
        return Optional.ofNullable(allowChunkedLength);
    }

    /**
     * This policy with the fields it leaves unset taken from {@code fallback}.
     *
     * @param fallback the policy whose fields fill this one's gaps
     * @return the merged policy
     */
    public ProtocolPolicy orElse(ProtocolPolicy fallback) {
        Objects.requireNonNull(fallback, "fallback");
        Builder merged = new Builder();
        merged.setAll(fallback, true);
        merged.setAll(this, true);
        return merged.build();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ProtocolPolicy p
                && Objects.equals(resolveBeforeProxyToServerRequest, p.resolveBeforeProxyToServerRequest)
                && Objects.equals(filterConnectAnswer, p.filterConnectAnswer)
                && Objects.equals(servePlainHttpAfterConnect, p.servePlainHttpAfterConnect)
                && proxyProtocolDestination == p.proxyProtocolDestination
                && Objects.equals(tlsRetryWithoutSni, p.tlsRetryWithoutSni)
                && Objects.equals(allowChunkedLength, p.allowChunkedLength)
                && generatedResponses == p.generatedResponses;
    }

    @Override
    public int hashCode() {
        return Objects.hash(resolveBeforeProxyToServerRequest, filterConnectAnswer, servePlainHttpAfterConnect,
                proxyProtocolDestination, tlsRetryWithoutSni, allowChunkedLength, generatedResponses);
    }

    /**
     * {@return the fields this policy sets, by their configuration names, such as {@code
     * ProtocolPolicy[tls_retry_without_sni=true]}}
     */
    @Override
    public String toString() {
        StringBuilder s = new StringBuilder("ProtocolPolicy[");
        field(s, "resolve_before_proxy_to_server_request", resolveBeforeProxyToServerRequest);
        field(s, "filter_connect_answer", filterConnectAnswer);
        field(s, "serve_plain_http_after_connect", servePlainHttpAfterConnect);
        field(s, "proxy_protocol_destination", proxyProtocolDestination == null ? null
                : proxyProtocolDestination.name().toLowerCase(Locale.ROOT));
        field(s, "tls_retry_without_sni", tlsRetryWithoutSni);
        field(s, "allow_chunked_length", allowChunkedLength);
        field(s, "generated_responses",
                generatedResponses == null ? null : generatedResponses.name().toLowerCase(Locale.ROOT));
        if (s.charAt(s.length() - 1) == ',') s.setLength(s.length() - 1);
        return s.append(']').toString();
    }

    private static void field(StringBuilder s, String name, Object value) {
        if (value != null) s.append(name).append('=').append(value).append(',');
    }

    /** A configuration token: stripped, lower case, {@code -} read as {@code _}. */
    static String token(String value) {
        return value.strip().toLowerCase(Locale.ROOT).replace('-', '_');
    }

    /**
     * Builds a {@link ProtocolPolicy}. Setters overwrite what an earlier call (or {@link #preset})
     * set; fields never set are left to what applies below the policy.
     */
    public static class Builder {

        Boolean resolveBeforeProxyToServerRequest;
        Boolean filterConnectAnswer;
        Boolean servePlainHttpAfterConnect;
        ProxyProtocolDestination proxyProtocolDestination;
        Boolean tlsRetryWithoutSni;
        Boolean allowChunkedLength;
        GeneratedResponses generatedResponses;

        Builder() {}

        /**
         * Sets every field that {@code preset} sets (such as {@link ProtocolPolicy#littleProxy()}),
         * overwriting what was set before; setters called after it overwrite it in turn. A
         * builder for other protocols than HTTP/1 leaves the HTTP/1-only fields alone.
         *
         * @param preset the policy whose fields to copy
         * @return this builder
         */
        public Builder preset(ProtocolPolicy preset) {
            setAll(Objects.requireNonNull(preset, "preset"), false);
            return this;
        }

        void setAll(ProtocolPolicy p, boolean http1Fields) {
            if (p.resolveBeforeProxyToServerRequest != null) {
                resolveBeforeProxyToServerRequest = p.resolveBeforeProxyToServerRequest;
            }
            if (p.filterConnectAnswer != null) filterConnectAnswer = p.filterConnectAnswer;
            if (p.servePlainHttpAfterConnect != null) servePlainHttpAfterConnect = p.servePlainHttpAfterConnect;
            if (p.proxyProtocolDestination != null) proxyProtocolDestination = p.proxyProtocolDestination;
            if (p.tlsRetryWithoutSni != null) tlsRetryWithoutSni = p.tlsRetryWithoutSni;
            if (p.generatedResponses != null) generatedResponses = p.generatedResponses;
            if (http1Fields && p.allowChunkedLength != null) allowChunkedLength = p.allowChunkedLength;
        }

        /**
         * Sets {@link ProtocolPolicy#resolveBeforeProxyToServerRequest()}.
         *
         * @param resolveFirst whether the server is resolved before {@code proxyToServerRequest}
         * @return this builder
         */
        public Builder resolveBeforeProxyToServerRequest(boolean resolveFirst) {
            resolveBeforeProxyToServerRequest = resolveFirst;
            return this;
        }

        /**
         * Sets {@link ProtocolPolicy#filterConnectAnswer()}.
         *
         * @param filter whether the {@code CONNECT}'s {@code 200} goes through response filters
         * @return this builder
         */
        public Builder filterConnectAnswer(boolean filter) {
            filterConnectAnswer = filter;
            return this;
        }

        /**
         * Sets {@link ProtocolPolicy#servePlainHttpAfterConnect()}.
         *
         * @param serve whether plain HTTP after a {@code CONNECT} is served as HTTP
         * @return this builder
         */
        public Builder servePlainHttpAfterConnect(boolean serve) {
            servePlainHttpAfterConnect = serve;
            return this;
        }

        /**
         * Sets {@link ProtocolPolicy#proxyProtocolDestination()}.
         *
         * @param destination the destination a sent PROXY header names
         * @return this builder
         */
        public Builder proxyProtocolDestination(ProxyProtocolDestination destination) {
            proxyProtocolDestination = Objects.requireNonNull(destination, "destination");
            return this;
        }

        /**
         * Sets {@link ProtocolPolicy#tlsRetryWithoutSni()}.
         *
         * @param retry whether to retry without SNI after an {@code unrecognized_name} alert
         * @return this builder
         */
        public Builder tlsRetryWithoutSni(boolean retry) {
            tlsRetryWithoutSni = retry;
            return this;
        }

        /**
         * Sets {@link ProtocolPolicy#generatedResponses()}.
         *
         * @param value how {@code proxyToClientResponse} treats generated responses
         * @return this builder
         */
        public Builder generatedResponses(GeneratedResponses value) {
            generatedResponses = Objects.requireNonNull(value, "generatedResponses");
            return this;
        }

        /**
         * Sets a field by its configuration name, as the properties file and the command line
         * name them: {@code preset} ({@link ProtocolPolicy#preset(String)}), {@code
         * resolve_before_proxy_to_server_request}, {@code filter_connect_answer}, {@code
         * serve_plain_http_after_connect}, {@code proxy_protocol_destination} ({@code
         * local_address} or {@code server_address}), {@code tls_retry_without_sni} and {@code
         * generated_responses} ({@link GeneratedResponses#parse}), and for
         * HTTP/1 {@code allow_chunked_length}. Booleans are {@code true} or {@code false}.
         *
         * @param name the field's name ({@code -} may stand for {@code _})
         * @param value its value
         * @return this builder
         * @throws IllegalArgumentException for an unknown field (or one of another protocol), or
         *     a value the field does not take
         */
        public Builder set(String name, String value) {
            Objects.requireNonNull(value, "value");
            switch (token(name)) {
                case "preset" -> preset(ProtocolPolicy.preset(value));
                case "resolve_before_proxy_to_server_request" -> resolveBeforeProxyToServerRequest(bool(name, value));
                case "filter_connect_answer" -> filterConnectAnswer(bool(name, value));
                case "serve_plain_http_after_connect" -> servePlainHttpAfterConnect(bool(name, value));
                case "proxy_protocol_destination" -> proxyProtocolDestination(ProxyProtocolDestination.parse(value));
                case "tls_retry_without_sni" -> tlsRetryWithoutSni(bool(name, value));
                case "generated_responses" -> generatedResponses(GeneratedResponses.parse(value));
                default -> throw new IllegalArgumentException("unknown protocol policy field: " + name.strip()
                        + (token(name).equals("allow_chunked_length") ? " (HTTP/1 only)" : ""));
            }
            return this;
        }

        static boolean bool(String name, String value) {
            return switch (token(value)) {
                case "true" -> true;
                case "false" -> false;
                default -> throw new IllegalArgumentException(name.strip() + " must be true or false: " + value.strip());
            };
        }

        /**
         * The policy set so far.
         *
         * @return the policy
         */
        public ProtocolPolicy build() {
            return new ProtocolPolicy(this);
        }
    }

    private static final List<String> NAMES = List.of("preset", "resolve_before_proxy_to_server_request",
            "filter_connect_answer", "serve_plain_http_after_connect", "proxy_protocol_destination",
            "tls_retry_without_sni", "generated_responses");

    /**
     * The configuration names {@link Builder#set} takes, {@code preset} first; {@link
     * Http1PolicyBuilder#set} takes {@code allow_chunked_length} too.
     *
     * @return the names, in a fixed order
     */
    public static List<String> configurationNames() {
        return NAMES;
    }
}
