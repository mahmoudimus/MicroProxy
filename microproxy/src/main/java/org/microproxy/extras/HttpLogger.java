package org.microproxy.extras;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiPredicate;
import java.util.function.Consumer;
import org.microproxy.FlowContext;
import org.microproxy.FlowTimings;
import org.microproxy.HttpFiltersBuilder;
import org.microproxy.HttpFiltersBuilder.Body;
import org.microproxy.HttpFiltersSource;
import org.microproxy.ResponseSource;
import org.microproxy.SelectiveFilters;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpMessage;
import org.microproxy.http.HttpBodies;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMessage;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.http.LastHttpContent;
import org.microproxy.http.WebSocketFrame;

/**
 * Logs whole requests and responses for debugging and audits, like OkHttp's {@code
 * HttpLoggingInterceptor} or a mitmproxy flow dump. It is a filters source; add it with {@code
 * bootstrap.plusFiltersSource(logger)}, in an {@link org.microproxy.HttpFiltersChain}, or inside
 * built filters with {@link HttpFiltersBuilder#log}:
 *
 * <pre>{@code
 * HttpLogger logger = HttpLogger.builder()
 *         .level(HttpLogger.Level.HEADERS)
 *         .redactQueryParams("token", "api_key")
 *         .build();
 * MicroProxy.bootstrap().plusFiltersSource(logger).start();
 * }</pre>
 *
 * <p>For each exchange it logs the request as the client sent it, with the changes made before it
 * was forwarded (by the proxy and by filters) when there are any, then the response as the server
 * sent it, with the changes made before it was delivered, the {@link ResponseSource}, the
 * server's status ({@link FlowContext#upstreamStatus()}) and the timings ({@link
 * FlowContext#timings()}). Each message is one string handed to the sink, every line starting
 * with {@code [conn <id> #<n>]}: the client connection, as in the proxy's own log lines, and the
 * exchange's number on it. Responses are logged once they have been delivered in full.
 *
 * <p>{@link Level#BASIC} and {@link Level#HEADERS} look only at heads, so bodies keep the proxy's
 * fast path. {@link Level#BODY} reads bodies piece by piece and keeps at most {@link
 * Builder#maxBodyBytes} of each; it never changes what is forwarded. Bodies are decoded ({@code
 * gzip}, {@code deflate}, {@code br}, {@code zstd}, see {@link HttpBodies}) when the whole body was
 * kept, and shown as text in their charset, or summarised when they are binary.
 *
 * <p>The values of {@code Authorization}, {@code Cookie}, {@code Set-Cookie} and {@code
 * Proxy-Authorization} are replaced with {@value #REDACTED} unless {@link Builder#redactNothing()}
 * says otherwise. Bodies are not redacted: {@link Level#BODY} logs payloads, with whatever secrets
 * and personal data they carry.
 *
 * <p>Lines go to the {@code System.Logger} named {@value #LOGGER_NAME} at INFO unless a {@link
 * Builder#sink} is given; when that logger is off, the filters are not even created. A sink that
 * throws is reported once and never disturbs the proxy.
 */
public final class HttpLogger implements HttpFiltersSource {

    /** How much of each message to log. */
    public enum Level {
        /** The request line, the status line, timings and the body sizes from the heads. */
        BASIC,
        /** Also the headers, and how the proxy and filters changed them. */
        HEADERS,
        /** Also the bodies, up to {@link Builder#maxBodyBytes} each. */
        BODY
    }

    /** How messages are written. */
    public enum Format {
        /** Readable blocks of lines, one block per message. */
        TEXT,
        /** One JSON object per message, on one line. */
        JSON
    }

    /** The {@code System.Logger} lines go to without a {@link Builder#sink}. */
    public static final String LOGGER_NAME = "org.microproxy.http";
    /** What redacted values are replaced with. */
    public static final String REDACTED = "██";
    /** Headers redacted unless {@link Builder#redactNothing()} is called. */
    public static final List<String> DEFAULT_REDACTED_HEADERS =
            List.of("Authorization", "Cookie", "Set-Cookie", "Proxy-Authorization");
    /** The default for {@link Builder#maxBodyBytes}. */
    public static final int DEFAULT_MAX_BODY_BYTES = 4096;

    private static final System.Logger HTTP_LOG = System.getLogger(LOGGER_NAME);
    private static final System.Logger LOG = System.getLogger(HttpLogger.class.getName());

    private final Level level;
    private final Format format;
    private final Set<String> redactedHeaders;
    private final Set<String> redactedQueryParams;
    private final int maxBodyBytes;
    private final BiPredicate<HttpRequest, FlowContext> only;
    private final Consumer<String> sink;
    private final boolean webSocketFrames;
    private final AtomicBoolean sinkFailed = new AtomicBoolean();
    private final AtomicBoolean loggerFailed = new AtomicBoolean();
    /** The number of requests seen on each client connection. */
    private final Map<FlowContext, AtomicLong> sequences = Collections.synchronizedMap(new WeakHashMap<>());

    private HttpLogger(Builder b) {
        level = b.level;
        format = b.format;
        redactedHeaders = lowerCase(b.redactedHeaders);
        redactedQueryParams = lowerCase(b.redactedQueryParams);
        maxBodyBytes = b.maxBodyBytes;
        only = b.only;
        sink = b.sink;
        webSocketFrames = b.webSocketFrames;
    }

    /**
     * Starts a logger at {@link Level#HEADERS}, writing {@link Format#TEXT} with the default redaction.
     *
     * @return a new builder with default settings
     */
    public static Builder builder() {
        return new Builder();
    }

    /** {@return the configured logging detail} */
    public Level level() {
        return level;
    }

    /** {@return the configured log output format} */
    public Format format() {
        return format;
    }

    /** {@return the redacted header names, in lower case} */
    public Set<String> redactedHeaders() {
        return redactedHeaders;
    }

    /** {@return the redacted query parameter names, in lower case} */
    public Set<String> redactedQueryParams() {
        return redactedQueryParams;
    }

    /** {@return the maximum body bytes retained per log entry} */
    public int maxBodyBytes() {
        return maxBodyBytes;
    }

    /** {@return whether WebSocket frames are logged (at {@link Level#BODY})} */
    public boolean logsWebSocketFrames() {
        return webSocketFrames && level == Level.BODY;
    }

    /**
     * Filters that log this exchange, or {@code null} when it is not logged: the {@link
     * Builder#only} predicate declined it, or the default {@code System.Logger} is off at INFO.
     */
    @Override
    public SelectiveFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
        // Numbered per client connection: an HTTP/2 connection's streams share one sequence.
        FlowContext connection = flowContext == null ? null : flowContext.getConnectionContext();
        long seq = sequences.computeIfAbsent(connection, k -> new AtomicLong()).incrementAndGet();
        if (sink == null && !HTTP_LOG.isLoggable(System.Logger.Level.INFO)) return null;
        try {
            if (only != null && !only.test(originalRequest, flowContext)) return null;
            return new Exchange(originalRequest, flowContext, seq);
        } catch (RuntimeException e) {
            failed(e);
            return null;
        }
    }

    @Override
    public String toString() {
        return "HttpLogger[" + level + ", " + format + "]";
    }

    // ---------------------------------------------------------------------------------------
    // Output
    // ---------------------------------------------------------------------------------------

    private void emit(String message) {
        try {
            if (sink != null) {
                sink.accept(message);
            } else {
                HTTP_LOG.log(System.Logger.Level.INFO, message);
            }
        } catch (RuntimeException e) {
            if (sinkFailed.compareAndSet(false, true)) {
                LOG.log(System.Logger.Level.WARNING, "HttpLogger sink failed; later failures are not reported", e);
            }
        }
    }

    private void failed(RuntimeException e) {
        if (loggerFailed.compareAndSet(false, true)) {
            LOG.log(System.Logger.Level.WARNING, "HttpLogger failed to log an exchange; later failures are not"
                    + " reported", e);
        }
    }

    private static Set<String> lowerCase(Set<String> names) {
        Set<String> lower = new LinkedHashSet<>();
        names.forEach(n -> lower.add(n.toLowerCase(Locale.ROOT)));
        return Collections.unmodifiableSet(lower);
    }

    // ---------------------------------------------------------------------------------------
    // One exchange
    // ---------------------------------------------------------------------------------------

    private record Header(String name, String value) {
        static List<Header> of(HttpHeaders headers) {
            List<Header> list = new ArrayList<>(headers.size());
            for (Map.Entry<String, String> e : headers) list.add(new Header(e.getKey(), e.getValue()));
            return List.copyOf(list);
        }
    }

    /** A request head as it was at one moment. */
    private record RequestHead(String method, String uri, String version, List<Header> headers) {
        static RequestHead of(HttpRequest r) {
            return new RequestHead(r.method().name(), r.uri(), r.protocolVersion().text(), Header.of(r.headers()));
        }

        boolean sameLine(RequestHead o) {
            return method.equals(o.method) && uri.equals(o.uri) && version.equals(o.version);
        }
    }

    /** A response head as it was at one moment. */
    private record ResponseHead(int status, String reason, String version, List<Header> headers) {
        static ResponseHead of(HttpResponse r) {
            return new ResponseHead(r.status().code(), r.status().reasonPhrase(), r.protocolVersion().text(),
                    Header.of(r.headers()));
        }

        boolean sameLine(ResponseHead o) {
            return status == o.status && reason.equals(o.reason) && version.equals(o.version);
        }
    }

    /** Headers removed and added between two versions of a head. */
    private record Diff(List<Header> removed, List<Header> added) {
        static Diff between(List<Header> before, List<Header> after) {
            List<Header> remaining = new ArrayList<>(after);
            List<Header> removed = new ArrayList<>();
            for (Header h : before) {
                int i = indexOf(remaining, h);
                if (i >= 0) {
                    remaining.remove(i);
                } else {
                    removed.add(h);
                }
            }
            return new Diff(removed, remaining);
        }

        private static int indexOf(List<Header> headers, Header h) {
            for (int i = 0; i < headers.size(); i++) {
                Header c = headers.get(i);
                if (c.name.equalsIgnoreCase(h.name) && c.value.equals(h.value)) return i;
            }
            return -1;
        }

        boolean isEmpty() {
            return removed.isEmpty() && added.isEmpty();
        }
    }

    /** The first {@code cap} bytes of a body, and how long it was. */
    private static final class Capture {
        private final int cap;
        private byte[] data = new byte[0];
        private int length;
        long total;
        boolean complete;

        Capture(int cap) {
            this.cap = cap;
        }

        void add(byte[] bytes) {
            total += bytes.length;
            int n = Math.min(bytes.length, cap - length);
            if (n <= 0) return;
            if (length + n > data.length) {
                data = Arrays.copyOf(data, Math.min(cap, Math.max(length + n, Math.max(256, data.length * 2))));
            }
            System.arraycopy(bytes, 0, data, length, n);
            length += n;
        }

        byte[] kept() {
            return Arrays.copyOf(data, length);
        }

        boolean truncated() {
            return total > length;
        }
    }

    /**
     * What to show of a body: the text (or {@code null} when it is binary or could not be
     * decoded), what to show instead, and remarks for the summary.
     */
    private record BodyView(long bytes, String text, String placeholder, List<String> remarks) {}

    private final class Exchange implements SelectiveFilters {
        private final FlowContext ctx;
        private final String prefix;
        private final long connectionId;
        private final long seq;
        /** The HTTP/2 stream, or 0. */
        private final int streamId;
        private final RequestHead clientRequest;
        private final String url;
        private final boolean bodies = level == Level.BODY;
        private final Capture requestBody = new Capture(maxBodyBytes);
        private final Capture responseBody = new Capture(maxBodyBytes);
        /** The request being proxied, which the proxy and filters change in place. */
        private HttpRequest request;
        private boolean forwarded;
        private boolean requestLogged;
        private Object serverObject;
        private ResponseHead serverResponse;

        Exchange(HttpRequest original, FlowContext ctx, long seq) {
            this.ctx = ctx;
            this.connectionId = ctx == null ? 0 : ctx.getConnectionId();
            this.seq = seq;
            this.streamId = ctx == null ? 0 : ctx.getStreamId();
            this.prefix = "[conn " + connectionId + " #" + seq + (streamId != 0 ? " stream " + streamId : "") + "] ";
            this.clientRequest = RequestHead.of(original);
            this.url = fullUrl(original, ctx);
        }

        @Override
        public boolean sees(Body stream) {
            return switch (stream) {
                case REQUEST, RESPONSE -> bodies;
                case OBSERVED_WEBSOCKET_FRAMES -> logsWebSocketFrames();
                case WEBSOCKET_FRAMES -> false;
            };
        }

        @Override
        public HttpResponse clientToProxyRequest(HttpObject httpObject) {
            try {
                switch (httpObject) {
                    case HttpRequest r -> {
                        request = r;
                        if (bodies && r instanceof FullHttpMessage full) {
                            requestBody.add(full.content());
                            requestBody.complete = true;
                        }
                    }
                    case HttpContent piece -> {
                        if (bodies) {
                            requestBody.add(piece.content());
                            if (piece instanceof LastHttpContent) requestBody.complete = true;
                        }
                    }
                    case HttpResponse r -> {}
                }
            } catch (RuntimeException e) {
                failed(e);
            }
            return null;
        }

        @Override
        public void proxyToServerRequestSending() {
            try {
                forwarded = true;
                // Without a body to wait for, the head is final now: log before the server answers.
                if (!bodies || requestBody.complete) logRequest();
            } catch (RuntimeException e) {
                failed(e);
            }
        }

        @Override
        public void proxyToServerRequestSent() {
            try {
                logRequest();
            } catch (RuntimeException e) {
                failed(e);
            }
        }

        @Override
        public HttpObject serverToProxyResponse(HttpObject httpObject) {
            try {
                switch (httpObject) {
                    case HttpResponse r -> {
                        if (serverResponse == null && !"CONNECT".equals(clientRequest.method)) {
                            serverObject = r;
                            serverResponse = ResponseHead.of(r);
                            if (bodies && r instanceof FullHttpMessage full) {
                                responseBody.add(full.content());
                                responseBody.complete = true;
                            }
                        }
                    }
                    case HttpContent piece -> {
                        if (bodies && serverResponse != null && !responseBody.complete) {
                            responseBody.add(piece.content());
                            if (piece instanceof LastHttpContent) responseBody.complete = true;
                        }
                    }
                    case HttpRequest r -> {}
                }
            } catch (RuntimeException e) {
                failed(e);
            }
            return httpObject;
        }

        @Override
        public void proxyToClientResponseSent(HttpResponse response, ResponseSource source) {
            try {
                logRequest();
                logResponse(response, source);
            } catch (RuntimeException e) {
                failed(e);
            }
        }

        @Override
        public void webSocketFrameReceived(WebSocketFrame frame, boolean fromClient) {
            if (!logsWebSocketFrames()) return;
            try {
                emit(format == Format.JSON ? frameJson(frame, fromClient) : frameText(frame, fromClient));
            } catch (RuntimeException e) {
                failed(e);
            }
        }

        // --- requests ---------------------------------------------------------------------------

        private void logRequest() {
            if (requestLogged) return;
            requestLogged = true;
            RequestHead sent = forwarded && request != null ? RequestHead.of(request) : null;
            if (sent != null && sent.sameLine(clientRequest) && Diff.between(clientRequest.headers, sent.headers).isEmpty()) {
                sent = null;
            }
            BodyView body = bodies ? view(requestBody, clientRequest.headers) : null;
            emit(format == Format.JSON ? requestJson(sent, body) : requestText(sent, body));
        }

        private String requestText(RequestHead sent, BodyView body) {
            StringBuilder sb = new StringBuilder();
            String line = "--> " + clientRequest.method + " " + redactUri(url) + " " + clientRequest.version;
            if (level == Level.BASIC) {
                return line(sb, line + sizeRemark(declaredSize(clientRequest.headers), isChunked(clientRequest.headers)))
                        .toString().stripTrailing();
            }
            line(sb, line);
            headers(sb, clientRequest.headers);
            if (sent != null) {
                line(sb, "--> forwarded as " + sent.method + " " + redactUri(sent.uri) + " " + sent.version);
                diff(sb, Diff.between(clientRequest.headers, sent.headers));
            }
            String end = "--> END " + clientRequest.method;
            if (body != null) {
                bodyText(sb, body);
                end += summary(body);
            } else {
                end += sizeRemark(declaredSize(clientRequest.headers), isChunked(clientRequest.headers));
            }
            return line(sb, end).toString().stripTrailing();
        }

        private String requestJson(RequestHead sent, BodyView body) {
            Json j = start("request");
            j.field("method", clientRequest.method).field("url", redactUri(url)).field("version", clientRequest.version);
            if (level != Level.BASIC) {
                j.raw("headers", headersJson(redacted(clientRequest.headers)));
                if (sent != null) {
                    Json f = new Json().field("method", sent.method).field("uri", redactUri(sent.uri))
                            .field("version", sent.version);
                    diffJson(f, Diff.between(clientRequest.headers, sent.headers));
                    j.raw("forwarded", f.end());
                }
            }
            bodyJson(j, body, clientRequest.headers);
            return j.end();
        }

        // --- responses --------------------------------------------------------------------------

        private void logResponse(HttpResponse response, ResponseSource source) {
            ResponseHead delivered = ResponseHead.of(response);
            ResponseHead main = serverResponse != null ? serverResponse : delivered;
            ResponseHead changed = null;
            if (serverResponse != null && (!serverResponse.sameLine(delivered)
                    || !Diff.between(serverResponse.headers, delivered.headers).isEmpty())) {
                changed = delivered;
            }
            BodyView body = null;
            BodyView deliveredBody = null;
            if (bodies) {
                if (serverResponse == null || response instanceof FullHttpMessage && response != serverObject) {
                    // Made by the proxy or a filter, or replaced by a complete response.
                    Capture made = new Capture(maxBodyBytes);
                    if (response instanceof FullHttpMessage full) made.add(full.content());
                    made.complete = true;
                    BodyView view = view(made, delivered.headers);
                    if (serverResponse == null) body = view;
                    else deliveredBody = view;
                }
                if (serverResponse != null) body = view(responseBody, serverResponse.headers);
            }
            emit(format == Format.JSON ? responseJson(delivered, main, changed, source, body, deliveredBody)
                    : responseText(delivered, main, changed, source, body, deliveredBody));
        }

        private String responseText(ResponseHead delivered, ResponseHead main, ResponseHead changed,
                ResponseSource source, BodyView body, BodyView deliveredBody) {
            StringBuilder sb = new StringBuilder();
            List<String> info = new ArrayList<>();
            FlowTimings t = ctx == null ? FlowTimings.NONE : ctx.timings();
            t.total().ifPresent(d -> info.add(millis(d)));
            t.timeToFirstByte().ifPresent(d -> info.add("ttfb " + millis(d)));
            info.add("source=" + source.name().toLowerCase(Locale.ROOT));
            OptionalInt upstream = upstream(delivered, source);
            upstream.ifPresent(s -> info.add("upstream=" + s));
            if (level == Level.BASIC) {
                long size = declaredSize(delivered.headers);
                if (size >= 0) info.add(size + "-byte body");
                else if (isChunked(delivered.headers)) info.add("chunked body");
            }
            line(sb, "<-- " + delivered.status + " " + delivered.reason + " " + redactUri(url)
                    + " (" + String.join(", ", info) + ")");
            if (level == Level.BASIC) return sb.toString().stripTrailing();
            headers(sb, main.headers);
            if (changed != null) {
                line(sb, "<-- delivered as " + changed.version + " " + changed.status + " " + changed.reason);
                diff(sb, Diff.between(main.headers, changed.headers));
            }
            String end = "<-- END HTTP";
            if (body != null) {
                bodyText(sb, body);
                end += summary(body);
                if (deliveredBody != null) {
                    line(sb, "<-- delivered body" + summary(deliveredBody));
                    bodyText(sb, deliveredBody);
                }
            } else {
                end += sizeRemark(declaredSize(main.headers), isChunked(main.headers));
            }
            return line(sb, end).toString().stripTrailing();
        }

        private String responseJson(ResponseHead delivered, ResponseHead main, ResponseHead changed,
                ResponseSource source, BodyView body, BodyView deliveredBody) {
            Json j = start("response");
            j.field("status", delivered.status).field("reason", delivered.reason).field("url", redactUri(url))
                    .field("version", main.version).field("source", source.name());
            OptionalInt upstream = ctx == null ? OptionalInt.empty() : ctx.upstreamStatus();
            j.raw("upstream_status", upstream.isPresent() ? String.valueOf(upstream.getAsInt()) : "null");
            FlowTimings t = ctx == null ? FlowTimings.NONE : ctx.timings();
            j.raw("ttfb_ms", t.timeToFirstByte().map(HttpLogger::jsonMillis).orElse("null"));
            j.raw("total_ms", t.total().map(HttpLogger::jsonMillis).orElse("null"));
            if (level != Level.BASIC) {
                j.raw("headers", headersJson(redacted(main.headers)));
                if (changed != null) {
                    Json d = new Json().field("status", changed.status).field("reason", changed.reason)
                            .field("version", changed.version);
                    diffJson(d, Diff.between(main.headers, changed.headers));
                    if (deliveredBody != null) bodyJson(d, deliveredBody, changed.headers);
                    j.raw("delivered", d.end());
                }
            }
            bodyJson(j, body, main.headers);
            return j.end();
        }

        /** The server's status, when the line about {@code delivered} should name it. */
        private OptionalInt upstream(ResponseHead delivered, ResponseSource source) {
            OptionalInt upstream = ctx == null ? OptionalInt.empty() : ctx.upstreamStatus();
            if (upstream.isPresent() && (source != ResponseSource.SERVER || upstream.getAsInt() != delivered.status)) {
                return upstream;
            }
            return OptionalInt.empty();
        }

        // --- WebSocket frames -------------------------------------------------------------------

        private String frameText(WebSocketFrame frame, boolean fromClient) {
            StringBuilder line = new StringBuilder(fromClient ? "--> WS " : "<-- WS ");
            line.append(opcode(frame)).append(" (").append(frame.payloadLength()).append(" bytes");
            if (!frame.isFinal()) line.append(", not final");
            String text = frameTextPayload(frame);
            if (frame.isTruncated()) line.append(", too large to show");
            else if ((frame.rsv() & 4) != 0) line.append(", compressed");
            else if (text != null && frame.payloadLength() > maxBodyBytes) line.append(", first ").append(maxBodyBytes).append(" bytes shown");
            line.append(')');
            if (text != null && !text.isEmpty()) line.append(": ").append(text);
            return prefixLines(line.toString());
        }

        private String frameJson(WebSocketFrame frame, boolean fromClient) {
            Json j = start("websocket");
            j.field("from", fromClient ? "client" : "server").field("opcode", opcode(frame))
                    .raw("fin", String.valueOf(frame.isFinal())).field("bytes", frame.payloadLength());
            String text = frameTextPayload(frame);
            j.raw("payload", Json.string(text));
            j.raw("truncated", String.valueOf(frame.isTruncated() || text != null && frame.payloadLength() > maxBodyBytes));
            return j.end();
        }

        /** The payload to show: text frames' text, close frames' code and reason; else null. */
        private String frameTextPayload(WebSocketFrame frame) {
            if (frame.isTruncated() || (frame.rsv() & 4) != 0) return null;
            byte[] payload = frame.payload();
            if (frame.isClose()) {
                if (payload.length < 2) return "";
                int code = (payload[0] & 0xff) << 8 | payload[1] & 0xff;
                String reason = new String(payload, 2, Math.min(payload.length - 2, maxBodyBytes), StandardCharsets.UTF_8);
                return reason.isEmpty() ? String.valueOf(code) : code + " " + reason;
            }
            if (!frame.isText() && !(frame.isContinuation() && looksLikeText(payload))) return null;
            return new String(payload, 0, Math.min(payload.length, maxBodyBytes), StandardCharsets.UTF_8);
        }

        // --- shared ------------------------------------------------------------------------------

        private Json start(String type) {
            Json j = new Json().field("type", type).field("conn", connectionId).field("seq", seq);
            if (streamId != 0) j.field("stream", streamId);
            Optional<java.time.Instant> start = ctx == null ? Optional.empty() : ctx.timings().start();
            start.ifPresent(s -> j.field("time", s.toString()));
            return j;
        }

        private StringBuilder line(StringBuilder sb, String line) {
            return sb.append(prefix).append(line).append('\n');
        }

        private String prefixLines(String text) {
            StringBuilder sb = new StringBuilder();
            text.lines().forEach(l -> line(sb, l));
            return sb.toString().stripTrailing();
        }

        private void headers(StringBuilder sb, List<Header> headers) {
            for (Header h : headers) line(sb, h.name + ": " + redactHeader(h));
        }

        private void diff(StringBuilder sb, Diff diff) {
            for (Header h : diff.removed) line(sb, "- " + h.name + ": " + redactHeader(h));
            for (Header h : diff.added) line(sb, "+ " + h.name + ": " + redactHeader(h));
        }

        private void diffJson(Json j, Diff diff) {
            j.raw("removed", headersJson(redacted(diff.removed))).raw("added", headersJson(redacted(diff.added)));
        }

        private void bodyText(StringBuilder sb, BodyView body) {
            if (body.bytes == 0) return;
            line(sb, "");
            if (body.text == null) {
                line(sb, body.placeholder);
                return;
            }
            String text = body.text.endsWith("\n") ? body.text.substring(0, body.text.length() - 1) : body.text;
            text.lines().forEach(l -> line(sb, l));
            if (text.isEmpty()) line(sb, "");
        }

        private void bodyJson(Json j, BodyView body, List<Header> headers) {
            if (body == null) {
                long size = declaredSize(headers);
                j.raw("body_bytes", size >= 0 ? String.valueOf(size) : "null");
                return;
            }
            j.field("body_bytes", body.bytes);
            if (body.bytes == 0) return;
            j.raw("body", Json.string(body.text));
            if (body.text == null) j.field("body_note", body.placeholder);
            if (!body.remarks.isEmpty()) j.field("body_remarks", String.join(", ", body.remarks));
        }

        private String summary(BodyView body) {
            if (body.bytes == 0) return " (no body)";
            List<String> parts = new ArrayList<>();
            parts.add(body.bytes + "-byte body");
            parts.addAll(body.remarks);
            return " (" + String.join(", ", parts) + ")";
        }

        private BodyView view(Capture capture, List<Header> headers) {
            List<String> remarks = new ArrayList<>();
            if (!capture.complete) remarks.add("incomplete");
            if (capture.total == 0) return new BodyView(0, null, null, remarks);
            HttpHeaders h = new HttpHeaders();
            for (Header header : headers) {
                if (header.name.equalsIgnoreCase(HttpHeaderNames.CONTENT_TYPE)
                        || header.name.equalsIgnoreCase(HttpHeaderNames.CONTENT_ENCODING)) {
                    h.add(header.name, header.value);
                }
            }
            FullHttpMessage message = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, h,
                    capture.kept());
            List<String> codings = HttpBodies.contentEncodings(message);
            String encoded = String.join(", ", codings);
            byte[] data;
            boolean cut = capture.truncated();
            if (!codings.isEmpty()) {
                if (cut || !capture.complete) {
                    return placeholder(capture, "<" + capture.total + " bytes, " + encoded
                            + "-encoded, longer than " + maxBodyBytes + " bytes: not decoded>", remarks);
                }
                if (!HttpBodies.canDecode(message)) {
                    return placeholder(capture, "<" + capture.total + " bytes, " + encoded + "-encoded>", remarks);
                }
                try {
                    data = HttpBodies.decodedPrefix(message, maxBodyBytes + 1);
                } catch (IOException e) {
                    return placeholder(capture, "<" + capture.total + " bytes of corrupt " + encoded + " data>", remarks);
                }
                remarks.add(encoded + "-decoded");
                if (data.length > maxBodyBytes) {
                    cut = true;
                    data = Arrays.copyOf(data, maxBodyBytes);
                } else {
                    remarks.add(data.length + " bytes decoded");
                }
            } else {
                data = message.content();
            }
            String mediaType = HttpBodies.mediaType(message);
            if (!HttpBodies.isText(message) && !(mediaType.isEmpty() && looksLikeText(data))) {
                String type = mediaType.isEmpty() ? "application/octet-stream" : mediaType;
                return placeholder(capture, "<" + capture.total + " bytes of " + type + ">", remarks);
            }
            if (cut) remarks.add("first " + maxBodyBytes + " bytes shown");
            Charset charset = HttpBodies.charset(message, StandardCharsets.UTF_8);
            return new BodyView(capture.total, new String(data, charset), null, remarks);
        }

        private static BodyView placeholder(Capture capture, String text, List<String> remarks) {
            return new BodyView(capture.total, null, text, remarks);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------

    private List<Header> redacted(List<Header> headers) {
        return headers.stream().map(h -> new Header(h.name, redactHeader(h))).toList();
    }

    private String redactHeader(Header h) {
        return redactedHeaders.contains(h.name.toLowerCase(Locale.ROOT)) ? REDACTED : h.value;
    }

    /** {@code uri} with the values of redacted query parameters replaced. */
    String redactUri(String uri) {
        if (redactedQueryParams.isEmpty()) return uri;
        int q = uri.indexOf('?');
        if (q < 0) return uri;
        int hash = uri.indexOf('#', q);
        int end = hash < 0 ? uri.length() : hash;
        StringBuilder sb = new StringBuilder(uri.length()).append(uri, 0, q + 1);
        String[] params = uri.substring(q + 1, end).split("&", -1);
        for (int i = 0; i < params.length; i++) {
            if (i > 0) sb.append('&');
            String param = params[i];
            int eq = param.indexOf('=');
            String name = eq < 0 ? param : param.substring(0, eq);
            if (eq >= 0 && redactedQueryParams.contains(decode(name).toLowerCase(Locale.ROOT))) {
                sb.append(name).append('=').append(REDACTED);
            } else {
                sb.append(param);
            }
        }
        return sb.append(uri, end, uri.length()).toString();
    }

    private static String decode(String name) {
        try {
            return URLDecoder.decode(name, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return name;
        }
    }

    /**
     * The absolute URL of a request: as received for absolute-form and CONNECT requests, otherwise
     * rebuilt from the Host header ({@code https} inside an intercepted TLS session).
     */
    private static String fullUrl(HttpRequest request, FlowContext ctx) {
        String uri = request.uri();
        String lower = uri.toLowerCase(Locale.ROOT);
        if (lower.startsWith("http://") || lower.startsWith("https://") || HttpMethod.CONNECT.equals(request.method())) {
            return uri;
        }
        String host = request.headers().get(HttpHeaderNames.HOST);
        if (host == null || host.isEmpty()) return uri;
        String scheme = ctx != null && ctx.getClientSslSession() != null ? "https" : "http";
        return scheme + "://" + host + (uri.startsWith("/") ? uri : "/" + uri);
    }

    /** The {@code Content-Length} among {@code headers}, or -1. */
    private static long declaredSize(List<Header> headers) {
        for (Header h : headers) {
            if (h.name.equalsIgnoreCase(HttpHeaderNames.CONTENT_LENGTH)) {
                try {
                    return Long.parseLong(h.value.strip());
                } catch (NumberFormatException e) {
                    return -1;
                }
            }
        }
        return -1;
    }

    private static boolean isChunked(List<Header> headers) {
        for (Header h : headers) {
            if (h.name.equalsIgnoreCase(HttpHeaderNames.TRANSFER_ENCODING)
                    && h.value.toLowerCase(Locale.ROOT).contains("chunked")) {
                return true;
            }
        }
        return false;
    }

    private static String sizeRemark(long size, boolean chunked) {
        if (size > 0) return " (" + size + "-byte body)";
        if (size == 0) return " (no body)";
        return chunked ? " (chunked body)" : "";
    }

    private static String opcode(WebSocketFrame frame) {
        return switch (frame.opcode()) {
            case WebSocketFrame.OPCODE_CONTINUATION -> "continuation";
            case WebSocketFrame.OPCODE_TEXT -> "text";
            case WebSocketFrame.OPCODE_BINARY -> "binary";
            case WebSocketFrame.OPCODE_CLOSE -> "close";
            case WebSocketFrame.OPCODE_PING -> "ping";
            case WebSocketFrame.OPCODE_PONG -> "pong";
            default -> "opcode " + frame.opcode();
        };
    }

    /**
     * Whether bytes of unknown type read as text: valid UTF-8 (ignoring a character cut at the end)
     * without control characters other than whitespace.
     */
    static boolean looksLikeText(byte[] data) {
        for (int end = data.length; end >= Math.max(0, data.length - 3); end--) {
            try {
                String s = StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(data, 0, end)).toString();
                return s.chars().allMatch(c -> c >= 0x20 || c == '\n' || c == '\r' || c == '\t' || c == '\f');
            } catch (CharacterCodingException e) {
                // Try again without a character cut at the end.
            }
        }
        return false;
    }

    private static String millis(Duration d) {
        long micros = d.toNanos() / 1000;
        return micros < 10_000 ? String.format(Locale.ROOT, "%.1f ms", micros / 1000.0) : micros / 1000 + " ms";
    }

    private static String jsonMillis(Duration d) {
        return String.format(Locale.ROOT, "%.3f", d.toNanos() / 1_000_000.0);
    }

    /** The headers as a JSON array of {@code [name, value]} pairs. */
    private static String headersJson(List<Header> headers) {
        List<String> pairs = new ArrayList<>(headers.size());
        for (Header h : headers) pairs.add("[" + Json.string(h.name) + "," + Json.string(h.value) + "]");
        return Json.array(pairs);
    }

    /** Configures an {@link HttpLogger}. */
    public static final class Builder {
        private Level level = Level.HEADERS;
        private Format format = Format.TEXT;
        private final Set<String> redactedHeaders = new LinkedHashSet<>(DEFAULT_REDACTED_HEADERS);
        private final Set<String> redactedQueryParams = new LinkedHashSet<>();
        private int maxBodyBytes = DEFAULT_MAX_BODY_BYTES;
        private BiPredicate<HttpRequest, FlowContext> only;
        private Consumer<String> sink;
        private boolean webSocketFrames;

        private Builder() {}

        /**
         * How much to log (default {@link Level#HEADERS}).
         *
         * @param level the amount of HTTP detail to log
         * @return this builder
         */
        public Builder level(Level level) {
            this.level = Objects.requireNonNull(level);
            return this;
        }

        /**
         * Readable blocks (default) or JSON lines.
         *
         * @param format the log output format
         * @return this builder
         */
        public Builder format(Format format) {
            this.format = Objects.requireNonNull(format);
            return this;
        }

        /**
         * Also replaces the values of these headers (any case) with {@value HttpLogger#REDACTED}, on
         * both sides of the proxy. {@link HttpLogger#DEFAULT_REDACTED_HEADERS} are redacted already.
         *
         * @param headerNames the header names whose values to redact
         * @return this builder
         */
        public Builder redact(String... headerNames) {
            for (String name : headerNames) redactedHeaders.add(Objects.requireNonNull(name));
            return this;
        }

        /**
         * Also replaces the values of these query parameters (any case) in logged URLs.
         *
         * @param names the query parameter names whose values to redact
         * @return this builder
         */
        public Builder redactQueryParams(String... names) {
            for (String name : names) redactedQueryParams.add(Objects.requireNonNull(name));
            return this;
        }

        /**
         * Redacts nothing, not even the default headers; later {@code redact} calls add to that.
         *
         * @return this builder
         */
        public Builder redactNothing() {
            redactedHeaders.clear();
            redactedQueryParams.clear();
            return this;
        }

        /**
         * At {@link Level#BODY}, keeps at most this many bytes of each body (and of each WebSocket
         * frame's text); the rest is counted but not kept. Default {@value
         * HttpLogger#DEFAULT_MAX_BODY_BYTES}.
         *
         * @param maxBodyBytes the maximum body bytes to retain in each log entry
         * @return this builder
         */
        public Builder maxBodyBytes(int maxBodyBytes) {
            if (maxBodyBytes < 0) throw new IllegalArgumentException("maxBodyBytes must not be negative");
            this.maxBodyBytes = maxBodyBytes;
            return this;
        }

        /**
         * Logs only the exchanges whose request (as the client sent it) matches.
         *
         * @param predicate the predicate deciding which exchanges to log
         * @return this builder
         */
        public Builder only(BiPredicate<HttpRequest, FlowContext> predicate) {
            this.only = Objects.requireNonNull(predicate);
            return this;
        }

        /**
         * Where each message goes, as one string (several lines in {@link Format#TEXT}). Default:
         * the {@code System.Logger} {@value HttpLogger#LOGGER_NAME} at INFO.
         *
         * @param sink the consumer receiving each formatted log entry
         * @return this builder
         */
        public Builder sink(Consumer<String> sink) {
            this.sink = Objects.requireNonNull(sink);
            return this;
        }

        /**
         * At {@link Level#BODY}, also logs WebSocket frames after an upgrade: text frames' text
         * (up to {@link #maxBodyBytes}), other frames' sizes. Off by default, since it makes the
         * proxy parse every frame.
         *
         * @param log whether to log WebSocket frames
         * @return this builder
         */
        public Builder webSocketFrames(boolean log) {
            this.webSocketFrames = log;
            return this;
        }

        /**
         * Creates the configured HTTP exchange logger.
         *
         * @return the configured exchange logger
         */
        public HttpLogger build() {
            return new HttpLogger(this);
        }
    }
}
