package org.microproxy.extras;

import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import javax.net.ssl.SSLSession;
import java.time.Duration;
import java.util.Optional;
import java.util.OptionalInt;
import org.microproxy.ActivityTrackerAdapter;
import org.microproxy.FlowContext;
import org.microproxy.FlowTimings;
import org.microproxy.FullFlowContext;
import org.microproxy.ResponseSource;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;

/**
 * An {@link org.microproxy.ActivityTracker} that writes one access-log line per response, in one
 * of the {@link LogFormat}s. Add it with {@code bootstrap.plusActivityTracker(new
 * ActivityLogger(LogFormat.CLF))}.
 *
 * <p>A line is written when the response head is sent to the client. The byte count is the
 * response's {@code Content-Length} ({@code -} when the body is chunked or close-delimited) and the
 * duration is the time from receiving the request to sending the response head. Lines go to the
 * {@code System.Logger} named after this class at INFO, or to the sink passed to the constructor.
 *
 * <p>{@link LogFormat#JSON_EXTENDED} lines are written once the response is complete instead, so
 * they can carry the total time (see {@link FlowContext#timings()}); an exchange abandoned half-way
 * is logged when the client connection ends, with {@code "total_ms":null}.
 */
public class ActivityLogger extends ActivityTrackerAdapter {

    private static final System.Logger LOG = System.getLogger(ActivityLogger.class.getName());
    private static final DateTimeFormatter CLF_DATE = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.US);
    private static final DateTimeFormatter HAPROXY_DATE = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss.SSS", Locale.US);
    private static final DateTimeFormatter ISO_8601 = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.US);
    private static final DateTimeFormatter W3C_DATE = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.US);

    /** A request waiting for its line; for JSON_EXTENDED also its response, until it completes. */
    private static final class TimedRequest {
        final HttpRequest request;
        final long startMillis;
        ResponseSource source = ResponseSource.SERVER;
        HttpResponse response;
        long durationMillis;

        TimedRequest(HttpRequest request, long startMillis) {
            this.request = request;
            this.startMillis = startMillis;
        }
    }

    private final LogFormat logFormat;
    private final Consumer<String> sink;
    private final Clock clock;
    private final Map<FlowContext, TimedRequest> requests = new ConcurrentHashMap<>();
    private final Map<FlowContext, InetSocketAddress> servers = new ConcurrentHashMap<>();

    /**
     * Logs to the {@code System.Logger} named {@code org.microproxy.extras.ActivityLogger}.
     *
     * @param logFormat the access log format
     */
    public ActivityLogger(LogFormat logFormat) {
        this(logFormat, null, Clock.systemUTC());
    }

    /**
     * Logs each line to {@code sink}, e.g. a file writer.
     *
     * @param logFormat the access log format
     * @param sink the consumer receiving each formatted log entry
     */
    public ActivityLogger(LogFormat logFormat, Consumer<String> sink) {
        this(logFormat, sink, Clock.systemUTC());
    }

    /**
     * Creates an access logger with the supplied format, sink and clock.
     *
     * @param logFormat the access log format
     * @param sink the consumer receiving each formatted log entry
     * @param clock the clock used for log timestamps
     */
    public ActivityLogger(LogFormat logFormat, Consumer<String> sink, Clock clock) {
        this.logFormat = Objects.requireNonNull(logFormat);
        this.sink = sink;
        this.clock = Objects.requireNonNull(clock);
    }

    /** {@return the configured access log format} */
    public LogFormat getLogFormat() {
        return logFormat;
    }

    @Override
    public void requestReceivedFromClient(FlowContext flowContext, HttpRequest httpRequest) {
        requests.put(flowContext, new TimedRequest(httpRequest, clock.millis()));
    }

    @Override
    public void serverConnected(FullFlowContext flowContext, InetSocketAddress serverAddress) {
        if (serverAddress != null) {
            servers.put(flowContext, serverAddress);
        }
    }

    @Override
    public void responseSentToClient(FlowContext flowContext, HttpResponse httpResponse, ResponseSource source) {
        TimedRequest timed = requests.get(flowContext);
        if (timed != null) {
            timed.source = source;
        }
        responseSentToClient(flowContext, httpResponse);
    }

    @Override
    public void responseSentToClient(FlowContext flowContext, HttpResponse httpResponse) {
        if (logFormat == LogFormat.JSON_EXTENDED) {
            TimedRequest timed = requests.get(flowContext);
            if (timed != null) {
                timed.response = httpResponse;
                timed.durationMillis = clock.millis() - timed.startMillis;
            }
            return;
        }
        TimedRequest timed = requests.remove(flowContext);
        if (timed != null) {
            log(formatLogEntry(flowContext, timed.request, httpResponse, clock.millis() - timed.startMillis));
        }
    }

    @Override
    public void responseCompleted(FlowContext flowContext, HttpResponse httpResponse) {
        if (logFormat == LogFormat.JSON_EXTENDED) {
            logExtended(flowContext, requests.remove(flowContext), true);
        }
        forgetStream(flowContext);
    }

    @Override
    public void clientDisconnected(FlowContext flowContext, SSLSession sslSession) {
        abandoned(flowContext);
        servers.remove(flowContext);
    }

    @Override
    public void connectionTimedOut(FlowContext flowContext) {
        abandoned(flowContext);
    }

    @Override
    public void connectionExceptionCaught(FlowContext flowContext, Throwable cause) {
        abandoned(flowContext);
    }

    /** Forgets the request in progress, logging it if its response had started. */
    private void abandoned(FlowContext flowContext) {
        TimedRequest timed = requests.remove(flowContext);
        if (logFormat == LogFormat.JSON_EXTENDED) {
            logExtended(flowContext, timed, false);
        }
        forgetStream(flowContext);
    }

    /**
     * An HTTP/2 stream's exchange is over: its server address is not needed again (an HTTP/1
     * connection keeps its own until it closes, since the next exchange may reuse it).
     */
    private void forgetStream(FlowContext flowContext) {
        if (flowContext.getStreamId() != 0) {
            servers.remove(flowContext);
        }
    }

    private void logExtended(FlowContext ctx, TimedRequest timed, boolean complete) {
        if (timed == null || timed.response == null) {
            return;
        }
        String line = formatLogEntry(ctx, timed.request, timed.response, timed.durationMillis);
        FlowTimings timings = ctx.timings();
        OptionalInt upstream = ctx.upstreamStatus();
        log(line.substring(0, line.length() - 1)
                + ",\"source\":\"" + timed.source + "\""
                + ",\"upstream_status\":" + (upstream.isPresent() ? String.valueOf(upstream.getAsInt()) : "null")
                + ",\"ttfb_ms\":" + millis(timings.timeToFirstByte())
                + ",\"total_ms\":" + (complete ? millis(timings.total()) : "null")
                + ",\"dns_ms\":" + millis(timings.dnsLookup())
                + ",\"connect_ms\":" + millis(timings.connect())
                + ",\"tls_ms\":" + millis(timings.tlsHandshake()) + "}");
    }

    /** Milliseconds with microsecond precision, or {@code null}. */
    private static String millis(Optional<Duration> d) {
        return d.map(x -> String.format(Locale.ROOT, "%.3f", x.toNanos() / 1e6)).orElse("null");
    }

    /**
     * Writes a finished line. Override to send lines elsewhere.
     *
     * @param line the formatted log entry
     */
    protected void log(String line) {
        if (sink != null) {
            sink.accept(line);
        } else {
            LOG.log(Level.INFO, line);
        }
    }

    /**
     * Formats one line; visible for subclasses that want to post-process it.
     *
     * @param ctx the client connection or exchange context
     * @param request the request being handled
     * @param response the response being handled
     * @param durationMillis the exchange duration in milliseconds
     * @return the formatted access log line
     */
    protected String formatLogEntry(FlowContext ctx, HttpRequest request, HttpResponse response, long durationMillis) {
        ZonedDateTime now = ZonedDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        String client = clientIp(ctx);
        String user = valueOrDash(ctx.getClientDetails().getUserName());
        String url = getFullUrl(request, ctx);
        String requestLine = request.method() + " " + url + " " + request.protocolVersion();
        int status = response.status().code();
        String bytes = valueOrDash(response.headers().get(HttpHeaderNames.CONTENT_LENGTH));
        String userAgent = valueOrDash(request.headers().get(HttpHeaderNames.USER_AGENT));
        return switch (logFormat) {
            case CLF -> client + " - " + user + " [" + CLF_DATE.format(now) + "] \"" + requestLine + "\" "
                    + status + " " + bytes;
            case ELF -> client + " - " + user + " [" + CLF_DATE.format(now) + "] \"" + requestLine + "\" "
                    + status + " " + bytes + " \"" + valueOrDash(request.headers().get("Referer")) + "\" \""
                    + userAgent + "\"";
            case W3C -> W3C_DATE.format(now) + " " + client + " " + request.method() + " " + url + " "
                    + status + " " + bytes + " \"" + userAgent + "\"";
            case JSON, JSON_EXTENDED -> "{\"timestamp\":\"" + ISO_8601.format(now) + "\""
                    + ",\"client_ip\":\"" + json(client) + "\""
                    + ",\"user\":" + (ctx.getClientDetails().getUserName() == null ? "null"
                            : "\"" + json(ctx.getClientDetails().getUserName()) + "\"")
                    + ",\"method\":\"" + json(request.method().name()) + "\""
                    + ",\"uri\":\"" + json(url) + "\""
                    + ",\"protocol\":\"" + request.protocolVersion() + "\""
                    + ",\"status\":" + status
                    + ",\"bytes\":" + (bytes.equals("-") ? "null" : bytes)
                    + ",\"duration\":" + durationMillis
                    + ",\"user_agent\":\"" + json(userAgent) + "\"}";
            case LTSV -> "time:" + ISO_8601.format(now) + "\thost:" + ltsv(client) + "\tuser:" + ltsv(user)
                    + "\tmethod:" + request.method() + "\turi:" + ltsv(url) + "\tstatus:" + status
                    + "\tsize:" + bytes + "\tduration:" + durationMillis + "\tua:" + ltsv(userAgent);
            case CSV -> csv(ISO_8601.format(now)) + "," + csv(client) + "," + csv(request.method().name()) + ","
                    + csv(url) + "," + status + "," + bytes + "," + durationMillis + "," + csv(userAgent);
            case SQUID -> {
                long millis = now.toInstant().toEpochMilli();
                yield String.format(Locale.ROOT, "%d.%03d %6d %s TCP_MISS/%03d %s %s %s %s DIRECT/%s %s",
                        millis / 1000, millis % 1000, durationMillis, client, status, bytes,
                        request.method(), url, user, serverIp(ctx),
                        valueOrDash(response.headers().get(HttpHeaderNames.CONTENT_TYPE)).replace(' ', '_'));
            }
            case HAPROXY -> client + " [" + HAPROXY_DATE.format(now) + "] \"" + requestLine + "\" " + status
                    + " " + bytes + " " + durationMillis;
        };
    }

    /**
     * The absolute URL of a request: as received for absolute-form and CONNECT requests, otherwise
     * rebuilt from the Host header ({@code https} inside an intercepted TLS session).
     *
     * @param request the request being handled
     * @param ctx the client connection or exchange context
     * @return the absolute request URL
     */
    protected String getFullUrl(HttpRequest request, FlowContext ctx) {
        String uri = request.uri();
        String lower = uri.toLowerCase(Locale.ROOT);
        if (lower.startsWith("http://") || lower.startsWith("https://") || HttpMethod.CONNECT.equals(request.method())) {
            return uri;
        }
        String host = request.headers().get(HttpHeaderNames.HOST);
        if (host == null || host.isEmpty()) {
            return uri;
        }
        String scheme = ctx.getClientSslSession() != null ? "https" : "http";
        return scheme + "://" + host + (uri.startsWith("/") ? uri : "/" + uri);
    }

    private String serverIp(FlowContext ctx) {
        InetSocketAddress server = servers.get(ctx);
        if (server == null) return "-";
        return server.getAddress() != null ? server.getAddress().getHostAddress() : server.getHostString();
    }

    private static String clientIp(FlowContext ctx) {
        InetSocketAddress address = ctx.getClientAddress();
        if (address == null) return "-";
        return address.getAddress() != null ? address.getAddress().getHostAddress() : address.getHostString();
    }

    private static String valueOrDash(String value) {
        return value == null || value.isEmpty() ? "-" : value;
    }

    /** Escapes a string for inclusion in a JSON string literal. */
    static String json(String s) {
        return Json.escape(s);
    }

    /** Quotes a CSV field per RFC 4180. */
    static String csv(String s) {
        return "\"" + s.replace("\"", "\"\"") + "\"";
    }

    /** LTSV values may not contain tabs or newlines. */
    private static String ltsv(String s) {
        return s.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }
}
