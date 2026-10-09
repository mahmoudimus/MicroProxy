package org.microproxy;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import org.microproxy.extras.HttpLogger;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.WebSocketFrame;

/**
 * Builds {@link HttpFilters} from lambdas, one per hook, instead of a class that overrides the
 * hooks it needs:
 *
 * <pre>{@code
 * HttpFilters filters = HttpFilters.builder()
 *         .onRequest(req -> req.uri().endsWith("/blocked") ? forbidden() : null)
 *         .onResponse(res -> { res.headers().set("X-Proxy", "micro"); return res; })
 *         .onWebSocketFrame((frame, fromClient) -> frame.isPing() ? null : frame)
 *         .build();
 * MicroProxy.bootstrap().withFiltersSource((request, ctx) -> filters).start();
 * }</pre>
 *
 * <p>Registering the same hook twice runs both, in order: the first short-circuit response wins,
 * and transformations feed into each other ({@code null} aborts, as in {@link HttpFiltersChain}).
 *
 * <p>Bodies and WebSocket frames are only parsed into pieces when a body or frame hook was
 * registered ({@link Built#sees}); otherwise they are relayed by the proxy's fast path, just as for
 * a filters class that does not override those hooks. The built filters keep no state of their
 * own, so one instance can serve every request if the lambdas allow it.
 */
public final class HttpFiltersBuilder {

    /** The streams a built filter inspects piece by piece. */
    public enum Body {
        /** Request body pieces ({@link #onRequestBody}). */
        REQUEST,
        /** Response body pieces ({@link #onResponseBody}). */
        RESPONSE,
        /** WebSocket frames, rewritten ({@link #onWebSocketFrame}). */
        WEBSOCKET_FRAMES,
        /**
         * WebSocket frames, only watched ({@link HttpFilters#webSocketFrameReceived(WebSocketFrame,
         * boolean)}), such as an {@link HttpLogger} logging frames; the upgrade is left alone.
         */
        OBSERVED_WEBSOCKET_FRAMES
    }

    private Function<HttpRequest, HttpResponse> onRequest;
    private Consumer<HttpContent> onRequestBody;
    private Function<HttpRequest, HttpResponse> beforeSending;
    private UnaryOperator<HttpResponse> onResponse;
    private UnaryOperator<HttpContent> onResponseBody;
    private UnaryOperator<HttpResponse> beforeResponding;
    private Function<ProxyFailure, HttpResponse> onFailure;
    private BiFunction<WebSocketFrame, Boolean, WebSocketFrame> onWebSocketFrame;
    private Function<String, InetSocketAddress> resolver;
    private BooleanSupplier allowMitm;
    private int requestBuffer;
    private int responseBuffer;
    private HttpLogger logger;
    private Duration connectTimeout;

    HttpFiltersBuilder() {}

    /**
     * The request head as the client sent it ({@code clientToProxyRequest}); a whole {@link
     * org.microproxy.http.FullHttpRequest} when buffered ({@link #bufferRequests}). Return a
     * response to answer without contacting the server, or {@code null} to continue.
     */
    public HttpFiltersBuilder onRequest(Function<HttpRequest, HttpResponse> hook) {
        onRequest = firstAnswer(onRequest, hook);
        return this;
    }

    /** Each piece of a streamed request body, ending with a {@code LastHttpContent}. */
    public HttpFiltersBuilder onRequestBody(Consumer<HttpContent> hook) {
        onRequestBody = onRequestBody == null ? hook : onRequestBody.andThen(hook);
        return this;
    }

    /**
     * The request head just before it goes to the server ({@code proxyToServerRequest}), with the
     * proxy's own header changes applied. Return a response to answer instead, or {@code null}.
     */
    public HttpFiltersBuilder beforeSending(Function<HttpRequest, HttpResponse> hook) {
        beforeSending = firstAnswer(beforeSending, hook);
        return this;
    }

    /**
     * The response head from the server ({@code serverToProxyResponse}); a whole {@link
     * org.microproxy.http.FullHttpResponse} when buffered ({@link #bufferResponses}). Return it
     * (changed or not), a replacement, or {@code null} to abort the exchange.
     */
    public HttpFiltersBuilder onResponse(UnaryOperator<HttpResponse> hook) {
        onResponse = chain(onResponse, hook);
        return this;
    }

    /** Each piece of a streamed response body: return it, a replacement, or {@code null} to abort. */
    public HttpFiltersBuilder onResponseBody(UnaryOperator<HttpContent> hook) {
        onResponseBody = chain(onResponseBody, hook);
        return this;
    }

    /** The response head just before it goes to the client ({@code proxyToClientResponse}). */
    public HttpFiltersBuilder beforeResponding(UnaryOperator<HttpResponse> hook) {
        beforeResponding = chain(beforeResponding, hook);
        return this;
    }

    /**
     * The proxy's own answer when the request fails ({@code proxyToServerFailure}): return a
     * response to send instead of the default, or {@code null}.
     */
    public HttpFiltersBuilder onFailure(Function<ProxyFailure, HttpResponse> hook) {
        onFailure = firstAnswer(onFailure, hook);
        return this;
    }

    /**
     * Each WebSocket frame, with whether it came from the client: return it, a replacement, or
     * {@code null} to drop it (see {@link HttpFilters#filterWebSocketFrame}).
     */
    public HttpFiltersBuilder onWebSocketFrame(BiFunction<WebSocketFrame, Boolean, WebSocketFrame> hook) {
        BiFunction<WebSocketFrame, Boolean, WebSocketFrame> previous = onWebSocketFrame;
        onWebSocketFrame = previous == null ? hook : (frame, fromClient) -> {
            WebSocketFrame f = previous.apply(frame, fromClient);
            return f == null ? null : hook.apply(f, fromClient);
        };
        return this;
    }

    /** Chooses the server address for {@code host:port}; {@code null} resolves as usual. */
    public HttpFiltersBuilder resolveWith(Function<String, InetSocketAddress> resolver) {
        this.resolver = Objects.requireNonNull(resolver);
        return this;
    }

    /** Whether CONNECT requests may be intercepted (default true when MITM is configured). */
    public HttpFiltersBuilder allowMitm(BooleanSupplier allow) {
        this.allowMitm = Objects.requireNonNull(allow);
        return this;
    }

    /**
     * The connect timeout for these requests' new connections, instead of the server's (see
     * {@link HttpFilters#proxyToServerConnectTimeout()}).
     */
    public HttpFiltersBuilder connectTimeout(Duration timeout) {
        if (timeout == null || !timeout.isPositive()) throw new IllegalArgumentException("must be positive: " + timeout);
        this.connectTimeout = timeout;
        return this;
    }

    /** Buffer request bodies up to {@code maxBytes}, so {@link #onRequest} gets the whole request. */
    public HttpFiltersBuilder bufferRequests(int maxBytes) {
        this.requestBuffer = positive(maxBytes);
        return this;
    }

    /** Buffer response bodies up to {@code maxBytes}, so {@link #onResponse} gets the whole response. */
    public HttpFiltersBuilder bufferResponses(int maxBytes) {
        this.responseBuffer = positive(maxBytes);
        return this;
    }

    /**
     * Logs each exchange with {@code logger}, around these hooks: requests as the client sent them
     * (before {@link #onRequest}) and as forwarded (after {@link #beforeSending}), responses as the
     * server sent them (before {@link #onResponse}) and as delivered (after {@link
     * #beforeResponding}). Bodies are only parsed when the logger's level needs them.
     *
     * <p>The logger keeps state per exchange, so the built filters must be used as their own
     * source, which binds them to each request: {@code withFiltersSource(built)}, {@code
     * plusFiltersSource(built)} or a member of an {@link HttpFiltersChain}. Returned from a lambda
     * source instead, they run their hooks but log nothing (with one warning).
     */
    public HttpFiltersBuilder log(HttpLogger logger) {
        if (this.logger != null) throw new IllegalStateException("a logger is already set");
        this.logger = Objects.requireNonNull(logger);
        return this;
    }

    public Built build() {
        return new Built(this);
    }

    private static int positive(int n) {
        if (n <= 0) throw new IllegalArgumentException("buffer size must be positive");
        return n;
    }

    private static <T, R> Function<T, R> firstAnswer(Function<T, R> first, Function<T, R> next) {
        Objects.requireNonNull(next);
        if (first == null) return next;
        return t -> {
            R r = first.apply(t);
            return r != null ? r : next.apply(t);
        };
    }

    private static <T> UnaryOperator<T> chain(UnaryOperator<T> first, UnaryOperator<T> next) {
        Objects.requireNonNull(next);
        if (first == null) return next;
        return t -> {
            T r = first.apply(t);
            return r == null ? null : next.apply(r);
        };
    }

    /**
     * Filters made by {@link HttpFiltersBuilder}. They are also a {@link HttpFiltersSource} that
     * returns them for every request (bound to the exchange when a {@linkplain #log logger} is
     * set), so {@code withFiltersSource(built)} works.
     */
    public static final class Built implements SelectiveFilters, HttpFiltersSource {
        private static final System.Logger LOG = System.getLogger(Built.class.getName());
        private static volatile boolean warnedUnbound;

        private final Function<HttpRequest, HttpResponse> onRequest;
        private final Consumer<HttpContent> onRequestBody;
        private final Function<HttpRequest, HttpResponse> beforeSending;
        private final UnaryOperator<HttpResponse> onResponse;
        private final UnaryOperator<HttpContent> onResponseBody;
        private final UnaryOperator<HttpResponse> beforeResponding;
        private final Function<ProxyFailure, HttpResponse> onFailure;
        private final BiFunction<WebSocketFrame, Boolean, WebSocketFrame> onWebSocketFrame;
        private final Function<String, InetSocketAddress> resolver;
        private final BooleanSupplier allowMitm;
        private final int requestBuffer;
        private final int responseBuffer;
        private final HttpLogger logger;
        private final Duration connectTimeout;
        /** The logger's filters for one exchange, once bound by {@link #filterRequest}. */
        private final SelectiveFilters logged;

        private Built(HttpFiltersBuilder b) {
            onRequest = b.onRequest;
            onRequestBody = b.onRequestBody;
            beforeSending = b.beforeSending;
            onResponse = b.onResponse;
            onResponseBody = b.onResponseBody;
            beforeResponding = b.beforeResponding;
            onFailure = b.onFailure;
            onWebSocketFrame = b.onWebSocketFrame;
            resolver = b.resolver;
            allowMitm = b.allowMitm;
            requestBuffer = b.requestBuffer;
            responseBuffer = b.responseBuffer;
            logger = b.logger;
            connectTimeout = b.connectTimeout;
            logged = null;
        }

        /** {@code base}'s hooks, logging one exchange with {@code logged}. */
        private Built(Built base, SelectiveFilters logged) {
            onRequest = base.onRequest;
            onRequestBody = base.onRequestBody;
            beforeSending = base.beforeSending;
            onResponse = base.onResponse;
            onResponseBody = base.onResponseBody;
            beforeResponding = base.beforeResponding;
            onFailure = base.onFailure;
            onWebSocketFrame = base.onWebSocketFrame;
            resolver = base.resolver;
            allowMitm = base.allowMitm;
            requestBuffer = base.requestBuffer;
            responseBuffer = base.responseBuffer;
            logger = base.logger;
            connectTimeout = base.connectTimeout;
            this.logged = logged;
        }

        /**
         * These filters, for any request. With a {@linkplain HttpFiltersBuilder#log logger}, a copy
         * bound to this exchange (or these filters alone when the logger skips the request).
         */
        @Override
        public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
            if (logger == null || logged != null) return this;
            SelectiveFilters exchange = logger.filterRequest(originalRequest, flowContext);
            return exchange == null ? this : new Built(this, exchange);
        }

        /**
         * Whether these filters inspect {@code body} piece by piece. The proxy relays anything
         * they don't inspect through its fast path.
         */
        @Override
        public boolean sees(Body body) {
            boolean own = switch (body) {
                case REQUEST -> onRequestBody != null;
                case RESPONSE -> onResponseBody != null;
                case WEBSOCKET_FRAMES -> onWebSocketFrame != null;
                case OBSERVED_WEBSOCKET_FRAMES -> false;
            };
            return own || logged != null && logged.sees(body);
        }

        @Override
        public int requestBufferSizeInBytes(HttpRequest request) {
            return requestBuffer;
        }

        @Override
        public int responseBufferSizeInBytes(HttpResponse response) {
            return responseBuffer;
        }

        @Override
        public HttpResponse clientToProxyRequest(HttpObject httpObject) {
            if (logged != null) {
                logged.clientToProxyRequest(httpObject);
            } else if (logger != null && httpObject instanceof HttpRequest && !warnedUnbound) {
                warnedUnbound = true;
                LOG.log(System.Logger.Level.WARNING, "filters built with log(...) were used without being bound to"
                        + " each request; pass them to withFiltersSource or plusFiltersSource to log");
            }
            return switch (httpObject) {
                case HttpRequest request -> onRequest == null ? null : onRequest.apply(request);
                case HttpContent piece -> {
                    if (onRequestBody != null) onRequestBody.accept(piece);
                    yield null;
                }
                case HttpResponse response -> null;
            };
        }

        @Override
        public HttpResponse proxyToServerRequest(HttpObject httpObject) {
            HttpResponse answer = httpObject instanceof HttpRequest request && beforeSending != null
                    ? beforeSending.apply(request) : null;
            if (answer == null && logged != null) logged.proxyToServerRequest(httpObject);
            return answer;
        }

        @Override
        public void proxyToServerRequestSending() {
            if (logged != null) logged.proxyToServerRequestSending();
        }

        @Override
        public void proxyToServerRequestSent() {
            if (logged != null) logged.proxyToServerRequestSent();
        }

        @Override
        public HttpObject serverToProxyResponse(HttpObject httpObject) {
            HttpObject o = logged == null ? httpObject : logged.serverToProxyResponse(httpObject);
            return switch (o) {
                case null -> null;
                case HttpResponse response -> onResponse == null ? response : onResponse.apply(response);
                case HttpContent piece -> onResponseBody == null ? piece : onResponseBody.apply(piece);
                case HttpRequest request -> request;
            };
        }

        @Override
        public void serverToProxyResponseTimedOut() {
            if (logged != null) logged.serverToProxyResponseTimedOut();
        }

        @Override
        public void serverToProxyResponseReceiving() {
            if (logged != null) logged.serverToProxyResponseReceiving();
        }

        @Override
        public void serverToProxyResponseReceived() {
            if (logged != null) logged.serverToProxyResponseReceived();
        }

        @Override
        public HttpObject proxyToClientResponse(HttpObject httpObject) {
            HttpObject o = httpObject instanceof HttpResponse response && beforeResponding != null
                    ? beforeResponding.apply(response) : httpObject;
            return logged == null || o == null ? o : logged.proxyToClientResponse(o);
        }

        @Override
        public void proxyToClientResponseSent(HttpResponse response, ResponseSource source) {
            if (logged != null) logged.proxyToClientResponseSent(response, source);
        }

        @Override
        public void exchangeEnded(boolean completed) {
            if (logged != null) logged.exchangeEnded(completed);
        }

        @Override
        public HttpResponse proxyToServerFailure(ProxyFailure failure) {
            return onFailure == null ? null : onFailure.apply(failure);
        }

        @Override
        public void webSocketFrameReceived(WebSocketFrame frame, boolean fromClient) {
            if (logged != null) logged.webSocketFrameReceived(frame, fromClient);
        }

        @Override
        public WebSocketFrame filterWebSocketFrame(WebSocketFrame frame, boolean fromClient) {
            return onWebSocketFrame == null ? frame : onWebSocketFrame.apply(frame, fromClient);
        }

        @Override
        public InetSocketAddress proxyToServerResolutionStarted(String resolvingServerHostAndPort) {
            return resolver == null ? null : resolver.apply(resolvingServerHostAndPort);
        }

        @Override
        public boolean proxyToServerAllowMitm() {
            return allowMitm == null || allowMitm.getAsBoolean();
        }

        @Override
        public Duration proxyToServerConnectTimeout() {
            return connectTimeout;
        }
    }
}
