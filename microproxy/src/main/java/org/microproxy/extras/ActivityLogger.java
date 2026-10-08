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
import org.microproxy.ActivityTrackerAdapter;
import org.microproxy.FlowContext;
import org.microproxy.FullFlowContext;
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
 */
public class ActivityLogger extends ActivityTrackerAdapter {

    private static final System.Logger LOG = System.getLogger(ActivityLogger.class.getName());
    private static final DateTimeFormatter CLF_DATE = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.US);
    private static final DateTimeFormatter HAPROXY_DATE = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss.SSS", Locale.US);
    private static final DateTimeFormatter ISO_8601 = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.US);
    private static final DateTimeFormatter W3C_DATE = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.US);

    private record TimedRequest(HttpRequest request, long startMillis) {}

    private final LogFormat logFormat;
    private final Consumer<String> sink;
    private final Clock clock;
    private final Map<FlowContext, TimedRequest> requests = new ConcurrentHashMap<>();
    private final Map<FlowContext, InetSocketAddress> servers = new ConcurrentHashMap<>();

    /** Logs to the {@code System.Logger} named {@code org.microproxy.extras.ActivityLogger}. */
    public ActivityLogger(LogFormat logFormat) {
        this(logFormat, null, Clock.systemUTC());
    }

    /** Logs each line to {@code sink}, e.g. a file writer. */
    public ActivityLogger(LogFormat logFormat, Consumer<String> sink) {
        this(logFormat, sink, Clock.systemUTC());
    }

    public ActivityLogger(LogFormat logFormat, Consumer<String> sink, Clock clock) {
        this.logFormat = Objects.requireNonNull(logFormat);
        this.sink = sink;
        this.clock = Objects.requireNonNull(clock);
    }

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
    public void responseSentToClient(FlowContext flowContext, HttpResponse httpResponse) {
        TimedRequest timed = requests.remove(flowContext);
        if (timed != null) {
            log(formatLogEntry(flowContext, timed.request(), httpResponse, clock.millis() - timed.startMillis()));
        }
    }

    @Override
    public void clientDisconnected(FlowContext flowContext, SSLSession sslSession) {
        requests.remove(flowContext);
        servers.remove(flowContext);
    }

    @Override
    public void connectionTimedOut(FlowContext flowContext) {
        requests.remove(flowContext);
    }

    @Override
    public void connectionExceptionCaught(FlowContext flowContext, Throwable cause) {
        requests.remove(flowContext);
    }

    /** Writes a finished line. Override to send lines elsewhere. */
    protected void log(String line) {
        if (sink != null) {
            sink.accept(line);
        } else {
            LOG.log(Level.INFO, line);
        }
    }

    /** Formats one line; visible for subclasses that want to post-process it. */
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
            case JSON -> "{\"timestamp\":\"" + ISO_8601.format(now) + "\""
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
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
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
