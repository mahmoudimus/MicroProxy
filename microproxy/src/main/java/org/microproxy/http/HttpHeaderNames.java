package org.microproxy.http;

/** Common header names. Header lookups in {@link HttpHeaders} are case-insensitive. */
public final class HttpHeaderNames {

    /** The {@code Accept-Encoding} header field name. */
    public static final String ACCEPT_ENCODING = "Accept-Encoding";
    /** The {@code Connection} header field name. */
    public static final String CONNECTION = "Connection";
    /** The {@code Content-Encoding} header field name. */
    public static final String CONTENT_ENCODING = "Content-Encoding";
    /** The {@code Content-Length} header field name. */
    public static final String CONTENT_LENGTH = "Content-Length";
    /** The {@code Content-Type} header field name. */
    public static final String CONTENT_TYPE = "Content-Type";
    /** The {@code Date} header field name. */
    public static final String DATE = "Date";
    /** The {@code Expect} header field name. */
    public static final String EXPECT = "Expect";
    /** The {@code Host} header field name. */
    public static final String HOST = "Host";
    /** The {@code Keep-Alive} header field name. */
    public static final String KEEP_ALIVE = "Keep-Alive";
    /** The {@code Location} header field name. */
    public static final String LOCATION = "Location";
    /** The {@code Proxy-Authenticate} header field name. */
    public static final String PROXY_AUTHENTICATE = "Proxy-Authenticate";
    /** The {@code Proxy-Authorization} header field name. */
    public static final String PROXY_AUTHORIZATION = "Proxy-Authorization";
    /** The {@code Proxy-Connection} header field name. */
    public static final String PROXY_CONNECTION = "Proxy-Connection";
    /** The {@code Sec-WebSocket-Extensions} header field name. */
    public static final String SEC_WEBSOCKET_EXTENSIONS = "Sec-WebSocket-Extensions";
    /** The {@code Sec-WebSocket-Key} header field name. */
    public static final String SEC_WEBSOCKET_KEY = "Sec-WebSocket-Key";
    /** The {@code TE} header field name. */
    public static final String TE = "TE";
    /** The {@code Trailer} header field name. */
    public static final String TRAILER = "Trailer";
    /** The {@code Transfer-Encoding} header field name. */
    public static final String TRANSFER_ENCODING = "Transfer-Encoding";
    /** The {@code Upgrade} header field name. */
    public static final String UPGRADE = "Upgrade";
    /** The {@code User-Agent} header field name. */
    public static final String USER_AGENT = "User-Agent";
    /** The {@code Via} header field name. */
    public static final String VIA = "Via";

    /**
     * Distributed tracing headers: W3C Trace Context and Baggage, B3 (single and multiple header
     * forms), and the trace headers of other common tracing systems ({@code uber-trace-id}, {@code
     * X-Amzn-Trace-Id}, {@code X-Cloud-Trace-Context}, gRPC's {@code grpc-trace-bin}, {@code
     * sentry-trace}).
     * {@link org.microproxy.HttpProxyServerBootstrap#withoutTracingHeadersUpstream()} removes them
     * from requests sent upstream. {@code X-Request-Id} is not among them: it is often wanted by
     * the server, and can be added with {@link
     * org.microproxy.HttpProxyServerBootstrap#plusStrippedRequestHeaders(String...)}.
     */
    public static final java.util.List<String> TRACING_HEADERS = java.util.List.of(
            "traceparent", "tracestate", "baggage",
            "b3", "X-B3-TraceId", "X-B3-SpanId", "X-B3-ParentSpanId", "X-B3-Sampled", "X-B3-Flags",
            "uber-trace-id", "X-Amzn-Trace-Id", "X-Cloud-Trace-Context", "grpc-trace-bin", "sentry-trace");

    private HttpHeaderNames() {}
}
