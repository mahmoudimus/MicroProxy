package org.microproxy;

import java.util.Set;

/**
 * Why an exchange or a flow ended the way it did, in the vocabulary of Envoy's access-log response
 * flags: each constant has Envoy's short code ({@code UF}, {@code UT}, ...) and long name, so logs
 * read by tools made for Envoy keep their meaning. {@link FlowContext#responseFlags()} has the
 * flags of the exchange in progress (or the last one); access logs render them with {@code
 * %RESPONSE_FLAGS%} and {@code %RESPONSE_FLAGS_LONG%}.
 *
 * <p>The proxy sets the flags that apply to it (see the README's response-flags table); the
 * others exist so filters and configurations can name every Envoy flag, and so a filter can set
 * one with {@link FlowContext#addResponseFlag}. The constants are in Envoy's order, which is the
 * order flags are rendered in.
 */
public enum ResponseFlag {
    /** {@code LH}: a local health check failed. Not set by the proxy. */
    FAILED_LOCAL_HEALTH_CHECK("LH", "FailedLocalHealthCheck"),
    /** {@code UH}: no healthy upstream. Not set by the proxy. */
    NO_HEALTHY_UPSTREAM("UH", "NoHealthyUpstream"),
    /** {@code UT}: the server did not answer within the idle timeout. */
    UPSTREAM_REQUEST_TIMEOUT("UT", "UpstreamRequestTimeout"),
    /** {@code LR}: the proxy reset the stream itself. */
    LOCAL_RESET("LR", "LocalReset"),
    /** {@code UR}: the server reset the stream or closed the connection mid-response. */
    UPSTREAM_REMOTE_RESET("UR", "UpstreamRemoteReset"),
    /** {@code UF}: no connection could be made to the server, or its TLS handshake failed. */
    UPSTREAM_CONNECTION_FAILURE("UF", "UpstreamConnectionFailure"),
    /** {@code UC}: the server closed the connection before its response head was complete. */
    UPSTREAM_CONNECTION_TERMINATION("UC", "UpstreamConnectionTermination"),
    /** {@code UO}: no server connection was available (the shared pool was exhausted). */
    UPSTREAM_OVERFLOW("UO", "UpstreamOverflow"),
    /** {@code NR}: there was nowhere to send the request. */
    NO_ROUTE_FOUND("NR", "NoRouteFound"),
    /** {@code DI}: the request was delayed on purpose. Not set by the proxy. */
    DELAY_INJECTED("DI", "DelayInjected"),
    /** {@code FI}: a fault was injected. Not set by the proxy. */
    FAULT_INJECTED("FI", "FaultInjected"),
    /** {@code RL}: the request was refused by a rate or concurrency limit. */
    RATE_LIMITED("RL", "RateLimited"),
    /** {@code UAEX}: the client was refused by the proxy authenticator. */
    UNAUTHORIZED_EXTERNAL_SERVICE("UAEX", "UnauthorizedExternalService"),
    /** {@code RLSE}: the rate-limit service failed. Not set by the proxy. */
    RATE_LIMIT_SERVICE_ERROR("RLSE", "RateLimitServiceError"),
    /** {@code DC}: the client went away before the response was complete. */
    DOWNSTREAM_CONNECTION_TERMINATION("DC", "DownstreamConnectionTermination"),
    /** {@code URX}: every route was tried (with backoff between chained proxies) and failed. */
    UPSTREAM_RETRY_LIMIT_EXCEEDED("URX", "UpstreamRetryLimitExceeded"),
    /** {@code SI}: the exchange, tunnel or flow sat idle for the idle timeout. */
    STREAM_IDLE_TIMEOUT("SI", "StreamIdleTimeout"),
    /** {@code IH}: the request had invalid proxy-specific headers. Not set by the proxy. */
    INVALID_ENVOY_REQUEST_HEADERS("IH", "InvalidEnvoyRequestHeaders"),
    /** {@code DPE}: the client's request was malformed, refused as such, or too large. */
    DOWNSTREAM_PROTOCOL_ERROR("DPE", "DownstreamProtocolError"),
    /** {@code UMSDR}: the upstream stream reached its maximum duration. Not set by the proxy. */
    UPSTREAM_MAX_STREAM_DURATION_REACHED("UMSDR", "UpstreamMaxStreamDurationReached"),
    /** {@code RFCF}: served by a cache filter. Not set by the proxy, which says {@code cache} in the details. */
    RESPONSE_FROM_CACHE_FILTER("RFCF", "ResponseFromCacheFilter"),
    /** {@code NFCF}: no filter configuration was found. Not set by the proxy. */
    NO_FILTER_CONFIG_FOUND("NFCF", "NoFilterConfigFound"),
    /** {@code DT}: the request exceeded its maximum duration. Not set by the proxy. */
    DURATION_TIMEOUT("DT", "DurationTimeout"),
    /** {@code UPE}: the server's response was malformed. */
    UPSTREAM_PROTOCOL_ERROR("UPE", "UpstreamProtocolError"),
    /** {@code NC}: no upstream cluster was found. Not set by the proxy. */
    NO_CLUSTER_FOUND("NC", "NoClusterFound"),
    /** {@code OM}: the request was refused under overload. Not set by the proxy. */
    OVERLOAD_MANAGER("OM", "OverloadManagerTerminated"),
    /** {@code DF}: the server's name did not resolve. */
    DNS_RESOLUTION_FAILED("DF", "DnsResolutionFailed"),
    /** {@code DO}: the request was dropped under overload. Not set by the proxy. */
    DROP_OVERLOAD("DO", "DropOverload"),
    /** {@code DR}: the client reset its HTTP/2 or HTTP/3 stream. */
    DOWNSTREAM_REMOTE_RESET("DR", "DownstreamRemoteReset"),
    /** {@code UDO}: the request was dropped unconditionally under overload. Not set by the proxy. */
    UNCONDITIONAL_DROP_OVERLOAD("UDO", "UnconditionalDropOverload");

    private static final ResponseFlag[] VALUES = values();

    private final String code;
    private final String longName;

    ResponseFlag(String code, String longName) {
        this.code = code;
        this.longName = longName;
    }

    /** {@return Envoy's short code, such as {@code UF}} */
    public String code() {
        return code;
    }

    /** {@return Envoy's long name, such as {@code UpstreamConnectionFailure}} */
    public String longName() {
        return longName;
    }

    /**
     * The flag with the short code or long name {@code name}, ignoring case, or with this enum's
     * constant name ({@code UPSTREAM_CONNECTION_FAILURE}).
     *
     * @param name a short code, long name or constant name
     * @return the flag
     * @throws IllegalArgumentException if no flag has that name
     */
    public static ResponseFlag of(String name) {
        String n = name.strip();
        for (ResponseFlag f : VALUES) {
            if (f.code.equalsIgnoreCase(n) || f.longName.equalsIgnoreCase(n) || f.name().equalsIgnoreCase(n)) return f;
        }
        throw new IllegalArgumentException("unknown response flag: " + name);
    }

    /**
     * Renders {@code flags} as Envoy does: the short (or long) names in this enum's order,
     * separated by commas, or {@code -} when there are none.
     *
     * @param flags the flags
     * @param longNames whether to use the long names
     * @return the rendered flags
     */
    public static String render(Set<ResponseFlag> flags, boolean longNames) {
        if (flags.isEmpty()) return "-";
        StringBuilder sb = new StringBuilder();
        for (ResponseFlag f : VALUES) {
            if (!flags.contains(f)) continue;
            if (!sb.isEmpty()) sb.append(',');
            sb.append(longNames ? f.longName : f.code);
        }
        return sb.toString();
    }
}
