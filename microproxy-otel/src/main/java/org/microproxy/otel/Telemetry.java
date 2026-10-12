package org.microproxy.otel;

import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger.Level;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.microproxy.ActivityTracker;
import org.microproxy.FlowContext;
import org.microproxy.FlowRecord;
import org.microproxy.FlowTrace;
import org.microproxy.FlowTracer;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.extras.AccessLogFormat;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpRequest;
import org.microproxy.stats.StatsRegistry;

/**
 * OpenTelemetry for the proxy, with nothing but the JDK: context propagation (W3C Trace Context,
 * and B3 and Jaeger when configured), an {@code X-Request-Id} per request, a SERVER span per
 * exchange (HTTP/1, HTTP/2 and HTTP/3) with a CLIENT span per attempt to reach the server, an
 * INTERNAL span per tunnel or flow (CONNECT, SOCKS, WebSocket, CONNECT-UDP, QUIC), and the
 * export over OTLP/HTTP, as protobuf or JSON, of those spans, of the proxy's {@linkplain
 * StatsRegistry stats} as metrics, and of its access-log records as log records.
 *
 * <pre>{@code
 * Telemetry otel = Telemetry.fromEnvironment()          // OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_SERVICE_NAME, ...
 *         .serviceName("edge")
 *         .sampler(Sampler.parentBased(Sampler.traceIdRatio(0.1)))
 *         .build();
 * HttpProxyServer proxy = otel.install(MicroProxy.bootstrap().withPort(8080)).start();
 * }</pre>
 *
 * <p>Disabled ({@code OTEL_SDK_DISABLED=true}, {@link Builder#enabled(boolean) enabled(false)}),
 * {@link #install} leaves the proxy untouched, so it does no work at all. Enabled, a request whose
 * trace is not sampled costs its ids and the headers written upstream; only sampled exchanges
 * allocate spans. Spans and log records wait in bounded queues and are exported in batches by a
 * virtual thread per signal; when a queue is full they are dropped and counted ({@code
 * otel.spans_dropped}, {@code otel.logs_dropped}), never waited for.
 */
public final class Telemetry implements FlowTracer {

    private static final System.Logger LOG = System.getLogger(Telemetry.class.getName());

    /** The instrumentation scope of everything exported. */
    static final String SCOPE = "org.microproxy";

    /** The proxy's version, from the core jar. */
    static final String VERSION = version();

    /** How OTLP is sent: {@code http/protobuf} or {@code http/json}. */
    public enum Protocol {
        /** OTLP/HTTP with {@code application/x-protobuf} bodies. */
        HTTP_PROTOBUF("http/protobuf", "application/x-protobuf"),
        /** OTLP/HTTP with {@code application/json} bodies, ids in hex. */
        HTTP_JSON("http/json", "application/json");

        private final String id;
        private final String contentType;

        Protocol(String id, String contentType) {
            this.id = id;
            this.contentType = contentType;
        }

        /** {@return the name {@code OTEL_EXPORTER_OTLP_PROTOCOL} uses} */
        public String id() {
            return id;
        }

        /** {@return the content type of the requests} */
        public String contentType() {
            return contentType;
        }

        /**
         * The protocol named {@code name}.
         *
         * @param name {@code http/protobuf} or {@code http/json}
         * @return the protocol
         * @throws IllegalArgumentException for another name ({@code grpc} is not supported)
         */
        public static Protocol of(String name) {
            String n = name.strip().toLowerCase(Locale.ROOT);
            for (Protocol p : values()) {
                if (p.id.equals(n)) return p;
            }
            if (n.equals("grpc")) {
                throw new IllegalArgumentException("OTLP over gRPC is not supported; use http/protobuf (port 4318)");
            }
            throw new IllegalArgumentException("unknown OTLP protocol: " + name + " (http/protobuf or http/json)");
        }
    }

    /** What happens to a request's {@code X-Request-Id}. */
    public enum RequestIdMode {
        /** Keep the client's, or add a random UUID (version 4) when it has none. */
        KEEP,
        /** Always replace it with a random UUID. */
        REPLACE,
        /** Leave the header alone; {@code %UNIQUE_ID%} stays a random UUID of its own. */
        OFF
    }

    /**
     * What goes upstream when the proxy strips tracing headers ({@link
     * HttpProxyServerBootstrap#withoutTracingHeadersUpstream()}).
     */
    public enum WhenStripped {
        /** The proxy's own span context, in the configured propagators' headers, without the client's {@code tracestate}. */
        OWN,
        /** No trace context at all: the server never learns of the trace. */
        NONE
    }

    final boolean enabled;
    final List<Propagator> propagators;
    final Sampler sampler;
    final SpanLimits limits;
    final RequestIdMode requestIdMode;
    final String forceTraceHeader;
    final WhenStripped whenStripped;
    final boolean trustIncoming;
    final boolean traces;
    final boolean metrics;
    final boolean logs;
    final Attrs resource;
    final AccessLogFormat logFormat;
    final String metricPrefix;
    private final Duration metricInterval;
    private final Duration exportTimeout;
    private final String description;
    private final HttpClient client;
    private final ExecutorService clientExecutor;
    final BatchProcessor<OtlpData.Span> spans;
    final BatchProcessor<OtlpData.Log> logRecords;
    private final OtlpHttpExporter spanExporter;
    private final OtlpHttpExporter metricExporter;
    private final OtlpHttpExporter logExporter;
    private final Protocol protocol;
    private final ActivityTracker accessLog;
    final AtomicLong metricExports = new AtomicLong();
    final AtomicLong metricFailures = new AtomicLong();
    private volatile StatsRegistry registry = StatsRegistry.NOOP;
    private volatile long metricStartNanos = epochNanos();
    private final CountDownLatch stopMetrics = new CountDownLatch(1);
    private volatile Thread metricThread;
    private volatile boolean closed;

    private Telemetry(Builder b) {
        this.enabled = b.enabled;
        this.propagators = List.copyOf(b.propagators);
        this.sampler = b.sampler;
        this.limits = b.limits;
        this.requestIdMode = b.requestIdMode;
        this.forceTraceHeader = b.forceTraceHeader;
        this.whenStripped = b.whenStripped;
        this.trustIncoming = b.trustIncoming;
        this.traces = b.enabled && b.traces;
        this.metrics = b.enabled && b.metrics;
        this.logs = b.enabled && b.logs;
        this.logFormat = b.logFormat;
        this.metricPrefix = b.metricPrefix;
        this.metricInterval = b.metricInterval;
        this.exportTimeout = b.timeout;
        this.protocol = b.protocol;
        this.resource = resource(b);
        URI base = URI.create(b.endpoint);
        URI tracesUri = b.tracesEndpoint != null ? URI.create(b.tracesEndpoint) : signal(base, "traces");
        URI metricsUri = b.metricsEndpoint != null ? URI.create(b.metricsEndpoint) : signal(base, "metrics");
        URI logsUri = b.logsEndpoint != null ? URI.create(b.logsEndpoint) : signal(base, "logs");
        if (enabled && (traces || metrics || logs)) {
            clientExecutor = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name("microproxy-otel-http-", 0).factory());
            client = HttpClient.newBuilder()
                    .executor(clientExecutor)
                    .connectTimeout(b.timeout)
                    // Plain HTTP/1.1 to a collector on http:// (no h2c upgrade); HTTP/2 over TLS.
                    .version(base.getScheme() != null && base.getScheme().equals("https") ? HttpClient.Version.HTTP_2
                            : HttpClient.Version.HTTP_1_1)
                    .build();
        } else {
            clientExecutor = null;
            client = null;
        }
        String agent = "MicroProxy-OTLP-Exporter/" + VERSION;
        spanExporter = traces ? exporter(b, tracesUri, agent) : null;
        metricExporter = metrics ? exporter(b, metricsUri, agent) : null;
        logExporter = logs ? exporter(b, logsUri, agent) : null;
        spans = traces ? new BatchProcessor<>("spans", b.spanQueue, b.spanBatch, b.spanDelay, this::exportSpans) : null;
        logRecords = logs ? new BatchProcessor<>("logs", b.logQueue, b.logBatch, b.logDelay, this::exportLogs) : null;
        accessLog = logs ? new AccessLogExporter() : null;
        StringBuilder d = new StringBuilder();
        if (!enabled) {
            d.append("disabled");
        } else {
            List<String> signals = new ArrayList<>();
            if (traces) signals.add("traces to " + tracesUri);
            if (metrics) signals.add("metrics to " + metricsUri + " every " + metricInterval.toMillis() / 1000.0 + " s");
            if (logs) signals.add("access logs to " + logsUri);
            d.append(signals.isEmpty() ? "propagation only" : String.join(", ", signals))
                    .append(" (").append(protocol.id()).append(b.gzip ? ", gzip" : "").append(")")
                    .append("; service ").append(resource.get("service.name"))
                    .append("; sampler ").append(sampler.description())
                    .append("; propagators ").append(propagators.isEmpty() ? "none"
                            : String.join(",", propagators.stream().map(Propagator::name).toList()));
        }
        this.description = d.toString();
    }

    private OtlpHttpExporter exporter(Builder b, URI uri, String agent) {
        return new OtlpHttpExporter(client, uri, protocol.contentType(), b.headers, b.gzip, b.timeout, b.maxAttempts,
                b.initialBackoff, b.maxBackoff, agent);
    }

    /** {@code <base>/v1/<signal>}, as {@code OTEL_EXPORTER_OTLP_ENDPOINT} is used. */
    static URI signal(URI base, String signal) {
        String s = base.toString();
        return URI.create((s.endsWith("/") ? s : s + "/") + "v1/" + signal);
    }

    /** {@return a builder with the defaults: everything exported to {@code http://localhost:4318}} */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder configured from the process's environment ({@code OTEL_*} variables, see {@link
     * #fromEnvironment(Map)}).
     *
     * @return the builder
     * @throws IllegalArgumentException if a variable has a bad value
     */
    public static Builder fromEnvironment() {
        return fromEnvironment(System.getenv());
    }

    /**
     * A builder configured from {@code env}, OpenTelemetry's environment variables: {@code
     * OTEL_SDK_DISABLED}, {@code OTEL_SERVICE_NAME}, {@code OTEL_RESOURCE_ATTRIBUTES}, {@code
     * OTEL_EXPORTER_OTLP_ENDPOINT} and {@code OTEL_EXPORTER_OTLP_{TRACES,METRICS,LOGS}_ENDPOINT},
     * {@code OTEL_EXPORTER_OTLP_PROTOCOL}, {@code OTEL_EXPORTER_OTLP_HEADERS}, {@code
     * OTEL_EXPORTER_OTLP_COMPRESSION}, {@code OTEL_EXPORTER_OTLP_TIMEOUT}, {@code
     * OTEL_{TRACES,METRICS,LOGS}_EXPORTER} ({@code otlp} or {@code none}), {@code
     * OTEL_TRACES_SAMPLER} and {@code OTEL_TRACES_SAMPLER_ARG}, {@code OTEL_PROPAGATORS}, {@code
     * OTEL_METRIC_EXPORT_INTERVAL}, {@code OTEL_BSP_*} and {@code OTEL_BLRP_*} ({@code
     * SCHEDULE_DELAY}, {@code MAX_QUEUE_SIZE}, {@code MAX_EXPORT_BATCH_SIZE}), and the span limits
     * ({@code OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT}, {@code OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT},
     * {@code OTEL_SPAN_EVENT_COUNT_LIMIT}, {@code OTEL_EVENT_ATTRIBUTE_COUNT_LIMIT}).
     *
     * @param env the environment
     * @return the builder
     * @throws IllegalArgumentException if a variable has a bad value
     */
    public static Builder fromEnvironment(Map<String, String> env) {
        Builder b = new Builder();
        String disabled = get(env, "OTEL_SDK_DISABLED");
        if (disabled != null && disabled.equalsIgnoreCase("true")) b.enabled(false);
        String endpoint = get(env, "OTEL_EXPORTER_OTLP_ENDPOINT");
        if (endpoint != null) b.endpoint(endpoint);
        String v;
        if ((v = get(env, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")) != null) b.tracesEndpoint(v);
        if ((v = get(env, "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")) != null) b.metricsEndpoint(v);
        if ((v = get(env, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")) != null) b.logsEndpoint(v);
        if ((v = get(env, "OTEL_EXPORTER_OTLP_PROTOCOL")) != null) b.protocol(Protocol.of(v));
        if ((v = get(env, "OTEL_EXPORTER_OTLP_HEADERS")) != null) parseList(v, "OTEL_EXPORTER_OTLP_HEADERS").forEach(b::header);
        if ((v = get(env, "OTEL_EXPORTER_OTLP_COMPRESSION")) != null) b.compression(compression(v));
        if ((v = get(env, "OTEL_EXPORTER_OTLP_TIMEOUT")) != null) b.timeout(millis(v, "OTEL_EXPORTER_OTLP_TIMEOUT"));
        if ((v = get(env, "OTEL_RESOURCE_ATTRIBUTES")) != null) {
            parseList(v, "OTEL_RESOURCE_ATTRIBUTES").forEach(b::resourceAttribute);
        }
        if ((v = get(env, "OTEL_SERVICE_NAME")) != null) b.serviceName(v);
        if ((v = get(env, "OTEL_TRACES_EXPORTER")) != null) b.traces(exporter(v, "OTEL_TRACES_EXPORTER"));
        if ((v = get(env, "OTEL_METRICS_EXPORTER")) != null) b.metrics(exporter(v, "OTEL_METRICS_EXPORTER"));
        if ((v = get(env, "OTEL_LOGS_EXPORTER")) != null) b.logs(exporter(v, "OTEL_LOGS_EXPORTER"));
        String sampler = get(env, "OTEL_TRACES_SAMPLER");
        String arg = get(env, "OTEL_TRACES_SAMPLER_ARG");
        if (sampler != null || arg != null) b.sampler(Sampler.of(sampler, arg));
        if ((v = get(env, "OTEL_PROPAGATORS")) != null) b.propagators(Propagators.parse(v));
        if ((v = get(env, "OTEL_METRIC_EXPORT_INTERVAL")) != null) {
            b.metricInterval(millis(v, "OTEL_METRIC_EXPORT_INTERVAL"));
        }
        b.spanQueue(integer(env, "OTEL_BSP_MAX_QUEUE_SIZE", b.spanQueue), integer(env, "OTEL_BSP_MAX_EXPORT_BATCH_SIZE",
                b.spanBatch), (v = get(env, "OTEL_BSP_SCHEDULE_DELAY")) != null ? millis(v, "OTEL_BSP_SCHEDULE_DELAY")
                : b.spanDelay);
        b.logQueue(integer(env, "OTEL_BLRP_MAX_QUEUE_SIZE", b.logQueue), integer(env, "OTEL_BLRP_MAX_EXPORT_BATCH_SIZE",
                b.logBatch), (v = get(env, "OTEL_BLRP_SCHEDULE_DELAY")) != null ? millis(v, "OTEL_BLRP_SCHEDULE_DELAY")
                : b.logDelay);
        int attributes = integer(env, "OTEL_ATTRIBUTE_COUNT_LIMIT", SpanLimits.DEFAULT.maxAttributes());
        int length = integer(env, "OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT", SpanLimits.DEFAULT.maxAttributeValueLength());
        b.spanLimits(new SpanLimits(integer(env, "OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT", attributes),
                integer(env, "OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT", length),
                integer(env, "OTEL_SPAN_EVENT_COUNT_LIMIT", SpanLimits.DEFAULT.maxEvents()),
                integer(env, "OTEL_EVENT_ATTRIBUTE_COUNT_LIMIT", SpanLimits.DEFAULT.maxAttributesPerEvent())));
        return b;
    }

    /** Whether {@code env} asks for OTLP export: an endpoint is set and the SDK is not disabled. */
    static boolean configuredBy(Map<String, String> env) {
        String disabled = get(env, "OTEL_SDK_DISABLED");
        if (disabled != null && disabled.equalsIgnoreCase("true")) return false;
        return get(env, "OTEL_EXPORTER_OTLP_ENDPOINT") != null || get(env, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != null
                || get(env, "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") != null
                || get(env, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT") != null;
    }

    private static String get(Map<String, String> env, String name) {
        String v = env.get(name);
        return v == null || v.isBlank() ? null : v.strip();
    }

    private static int integer(Map<String, String> env, String name, int otherwise) {
        String v = get(env, name);
        if (v == null) return otherwise;
        try {
            return Integer.parseInt(v);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(name + " is not a number: " + v);
        }
    }

    private static Duration millis(String v, String name) {
        try {
            return Duration.ofMillis(Long.parseLong(v.strip()));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(name + " is not a number of milliseconds: " + v);
        }
    }

    private static boolean exporter(String v, String name) {
        return switch (v.strip().toLowerCase(Locale.ROOT)) {
            case "otlp" -> true;
            case "none" -> false;
            default -> throw new IllegalArgumentException(name + " must be otlp or none, not " + v);
        };
    }

    static boolean compression(String v) {
        return switch (v.strip().toLowerCase(Locale.ROOT)) {
            case "gzip" -> true;
            case "none", "" -> false;
            default -> throw new IllegalArgumentException("compression must be gzip or none, not " + v);
        };
    }

    /**
     * Parses {@code key=value,key=value} as the OpenTelemetry variables write it, values
     * percent-decoded (W3C Baggage's format).
     */
    static Map<String, String> parseList(String list, String what) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String member : list.split(",")) {
            if (member.isBlank()) continue;
            int eq = member.indexOf('=');
            if (eq <= 0) throw new IllegalArgumentException(what + ": not key=value: " + member.strip());
            String key = member.substring(0, eq).strip();
            String value = member.substring(eq + 1).strip();
            try {
                value = URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(what + ": bad percent-encoding in " + key);
            }
            out.put(key, value);
        }
        return out;
    }

    private static Attrs resource(Builder b) {
        Attrs a = new Attrs(256, 4096);
        Map<String, String> custom = b.resourceAttributes;
        String service = b.serviceName != null ? b.serviceName : custom.getOrDefault("service.name", "microproxy");
        a.put("service.name", service);
        a.put("service.version", custom.getOrDefault("service.version", VERSION));
        a.put("host.name", Host.NAME);
        a.put("process.pid", ProcessHandle.current().pid());
        a.put("process.runtime.name", System.getProperty("java.runtime.name", "Java"));
        a.put("process.runtime.version", System.getProperty("java.runtime.version", Runtime.version().toString()));
        a.put("process.runtime.description", System.getProperty("java.vm.vendor", "") + " "
                + System.getProperty("java.vm.name", "") + " " + System.getProperty("java.vm.version", ""));
        a.put("telemetry.sdk.name", "microproxy-otel");
        a.put("telemetry.sdk.language", "java");
        a.put("telemetry.sdk.version", VERSION);
        custom.forEach((k, v) -> {
            if (!k.equals("service.name") || b.serviceName == null) a.put(k, v);
        });
        return a;
    }

    /** This host's name, looked up once. */
    private static final class Host {
        static final String NAME = hostName();
    }

    private static String hostName() {
        String env = System.getenv("HOSTNAME");
        if (env != null && !env.isBlank()) return env.strip();
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (IOException e) {
            return "localhost";
        }
    }

    private static String version() {
        try (InputStream in = FlowTracer.class.getResourceAsStream("/org/microproxy/version.properties")) {
            if (in == null) return "unknown";
            Properties p = new Properties();
            p.load(in);
            String v = p.getProperty("version", "unknown");
            return v.startsWith("${") ? "unknown" : v;
        } catch (IOException e) {
            return "unknown";
        }
    }

    /** {@return the wall clock in nanoseconds since the epoch} */
    static long epochNanos() {
        Instant now = Instant.now();
        return now.getEpochSecond() * 1_000_000_000L + now.getNano();
    }

    /** {@return whether this telemetry does anything: {@code false} once the SDK is disabled} */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Wires this telemetry into {@code bootstrap}: its tracer ({@link
     * HttpProxyServerBootstrap#withTracer}), metrics turned on when they are exported, and the
     * access-log exporter as an {@link ActivityTracker} when logs are. Disabled, it changes
     * nothing.
     *
     * @param bootstrap the proxy's configuration
     * @return {@code bootstrap}
     */
    public HttpProxyServerBootstrap install(HttpProxyServerBootstrap bootstrap) {
        if (!enabled) return bootstrap;
        bootstrap.withTracer(this);
        if (metrics && !bootstrap.getStats().enabled()) bootstrap.withMetrics(true);
        if (accessLog != null) bootstrap.plusActivityTracker(accessLog);
        return bootstrap;
    }

    /** {@return the access-log exporter, which {@link #install} adds as a tracker; {@code null} without log export} */
    public ActivityTracker accessLogExporter() {
        return accessLog;
    }

    // ---------------------------------------------------------------------------------------
    // Tracing

    @Override
    public FlowTrace startExchange(FlowContext flow, HttpRequest request) {
        if (!enabled) return FlowTrace.NONE;
        HttpHeaders headers = request.headers();
        String requestId = requestId(headers);
        if (!traces && propagators.isEmpty()) return requestId == null ? FlowTrace.NONE : new RequestIdOnly(requestId);
        SpanContext parent = trustIncoming ? extract(headers) : null;
        long high;
        long low;
        if (parent != null) {
            high = parent.traceIdHigh();
            low = parent.traceIdLow();
        } else {
            ThreadLocalRandom random = ThreadLocalRandom.current();
            do {
                high = random.nextLong();
                low = random.nextLong();
            } while (high == 0 && low == 0);
        }
        boolean sampled = forceTraceHeader != null && headers.contains(forceTraceHeader)
                || sampler.shouldSample(parent, high, low);
        long spanId = SpanContext.randomSpanId();
        if (sampled && traces) {
            return new RecordingSpan(this, high, low, spanId, parent, requestId, Semconv.RequestInfo.of(request, flow));
        }
        return new PropagatedTrace(this, high, low, spanId, sampled, parent == null ? "" : parent.traceState(), requestId);
    }

    /** The context the first propagator finds, or {@code null}. */
    SpanContext extract(HttpHeaders headers) {
        for (Propagator p : propagators) {
            SpanContext c = p.extract(headers);
            if (c != null) return c;
        }
        return null;
    }

    private String requestId(HttpHeaders headers) {
        switch (requestIdMode) {
            case OFF -> {
                return null;
            }
            case KEEP -> {
                String id = headers.get("x-request-id");
                if (id != null && !id.isBlank() && id.length() <= 256) return id;
            }
            case REPLACE -> { }
        }
        String id = randomUuid();
        headers.set("X-Request-Id", id);
        return id;
    }

    /** A version 4 UUID from the thread's random generator (request ids need no secure randomness). */
    static String randomUuid() {
        ThreadLocalRandom r = ThreadLocalRandom.current();
        long msb = (r.nextLong() & ~0xF000L) | 0x4000L;
        long lsb = (r.nextLong() & 0x3FFFFFFFFFFFFFFFL) | 0x8000000000000000L;
        return new UUID(msb, lsb).toString();
    }

    @Override
    public void flowEnded(FlowRecord record) {
        if (!traces) return;
        if (record.trace() instanceof RecordingSpan span) {
            if (span.telemetry == this) span.finish(record);
        } else if (record.trace() == FlowTrace.NONE) {
            standalone(record);
        }
    }

    /**
     * The span of a flow that had no trace of its own: a relayed transparent QUIC flow, or a request
     * a transport answered itself; a child of the context its request carried, if any.
     */
    private void standalone(FlowRecord record) {
        HttpRequest request = record.request();
        SpanContext parent = trustIncoming && request != null ? extract(request.headers()) : null;
        ThreadLocalRandom random = ThreadLocalRandom.current();
        long high = parent != null ? parent.traceIdHigh() : random.nextLong();
        long low = parent != null ? parent.traceIdLow() : random.nextLong() | 1;
        if (!sampler.shouldSample(parent, high, low)) return;
        long start = record.startEpochMillis() > 0 ? record.startEpochMillis() * 1_000_000L : epochNanos();
        long end = record.durationNanos() >= 0 ? start + record.durationNanos() : Math.max(start, epochNanos());
        Semconv.RequestInfo info = request == null ? null : Semconv.RequestInfo.of(request, record.context());
        Attrs a = new Attrs(limits.maxAttributes(), limits.maxAttributeValueLength());
        if (info != null) {
            Semconv.request(a, info);
        } else {
            Semconv.client(a, record.context().getClientAddress());
        }
        Semconv.outcome(a, record);
        boolean http = record.kind().isHttp();
        boolean error = Semconv.isError(record);
        String name = http ? (info == null ? "HTTP" : RecordingSpan.spanName(info.method()))
                : Semconv.flowName(record.kind(), info);
        int flags = SpanContext.SAMPLED | OtlpData.FLAG_HAS_IS_REMOTE | (parent != null ? OtlpData.FLAG_IS_REMOTE : 0);
        export(new OtlpData.Span(high, low, SpanContext.randomSpanId(), parent == null ? 0 : parent.spanId(),
                parent == null ? "" : parent.traceState(), flags, name,
                http ? OtlpData.KIND_SERVER : OtlpData.KIND_INTERNAL, start, end, a, List.of(), 0,
                error ? OtlpData.STATUS_ERROR : OtlpData.STATUS_UNSET, error ? record.responseCodeDetails() : null));
    }

    void export(OtlpData.Span span) {
        BatchProcessor<OtlpData.Span> s = spans;
        if (s != null) s.offer(span);
    }

    private boolean exportSpans(List<OtlpData.Span> batch) {
        byte[] body = protocol == Protocol.HTTP_JSON ? OtlpJson.traces(resource, SCOPE, VERSION, batch)
                : OtlpProto.traces(resource, SCOPE, VERSION, batch);
        return spanExporter.export(body);
    }

    private boolean exportLogs(List<OtlpData.Log> batch) {
        byte[] body = protocol == Protocol.HTTP_JSON ? OtlpJson.logs(resource, SCOPE, VERSION, batch)
                : OtlpProto.logs(resource, SCOPE, VERSION, batch);
        return logExporter.export(body);
    }

    // ---------------------------------------------------------------------------------------
    // Metrics and lifecycle

    @Override
    public void proxyStarted(HttpProxyServer server) {
        StatsRegistry stats = server.getStats();
        registry = stats;
        metricStartNanos = epochNanos();
        if (stats.enabled()) register(stats);
        if (metrics && metricThread == null) {
            if (!stats.enabled()) {
                LOG.log(Level.WARNING, "OTLP metrics need the proxy's metrics on (withMetrics, --metrics); none exported");
            } else {
                metricThread = Thread.ofVirtual().name("microproxy-otel-metrics").start(this::metricLoop);
            }
        }
    }

    /** Counts the exporters' work in the proxy's stats, as {@code otel.*}. */
    private void register(StatsRegistry stats) {
        if (spans != null) {
            stats.counter("otel.spans_exported", "Spans the collector accepted", spans.exported::get);
            stats.counter("otel.spans_dropped", "Spans dropped because the export queue was full", spans.dropped::get);
            stats.counter("otel.spans_failed", "Spans whose export failed after its retries", spans.failed::get);
            stats.gauge("otel.spans_queued", "Spans waiting to be exported", spans::queued);
            stats.counter("otel.spans_export_retries", "Span exports sent again", spanExporter.retries::get);
        }
        if (logRecords != null) {
            stats.counter("otel.logs_exported", "Log records the collector accepted", logRecords.exported::get);
            stats.counter("otel.logs_dropped", "Log records dropped because the export queue was full",
                    logRecords.dropped::get);
            stats.counter("otel.logs_failed", "Log records whose export failed after its retries", logRecords.failed::get);
            stats.gauge("otel.logs_queued", "Log records waiting to be exported", logRecords::queued);
            stats.counter("otel.logs_export_retries", "Log exports sent again", logExporter.retries::get);
        }
        if (metrics) {
            stats.counter("otel.metrics_exports", "Metric exports the collector accepted", metricExports::get);
            stats.counter("otel.metrics_failed", "Metric exports that failed after their retries", metricFailures::get);
        }
    }

    private void metricLoop() {
        try {
            while (!stopMetrics.await(metricInterval.toNanos(), TimeUnit.NANOSECONDS)) {
                exportMetrics();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Exports the registry's metrics now; returns whether the collector accepted them. */
    boolean exportMetrics() {
        StatsRegistry stats = registry;
        if (metricExporter == null || !stats.enabled()) return false;
        List<OtlpData.Metric> data = StatsMetrics.collect(stats, metricPrefix != null ? metricPrefix : stats.prefix(),
                metricStartNanos, epochNanos(), limits);
        if (data.isEmpty()) return true;
        byte[] body = protocol == Protocol.HTTP_JSON ? OtlpJson.metrics(resource, SCOPE, VERSION, data)
                : OtlpProto.metrics(resource, SCOPE, VERSION, data);
        boolean ok;
        try {
            ok = metricExporter.export(body);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "OTLP metrics export failed", e);
            ok = false;
        }
        (ok ? metricExports : metricFailures).incrementAndGet();
        return ok;
    }

    /**
     * Exports what is queued now (spans, log records) and the metrics, waiting up to {@code
     * timeout} for each.
     *
     * @param timeout how long to wait for each signal
     * @return whether everything was sent in time
     */
    public boolean flush(Duration timeout) {
        boolean ok = true;
        if (spans != null) ok &= spans.flush(timeout);
        if (logRecords != null) ok &= logRecords.flush(timeout);
        if (metrics && registry.enabled()) ok &= exportMetrics();
        return ok;
    }

    /** Exports what is left, then stops the exporters; the proxy calls it once it has stopped. */
    @Override
    public void close() {
        if (closed) return;
        closed = true;
        stopMetrics.countDown();
        Thread t = metricThread;
        if (t != null) {
            try {
                t.join(exportTimeout);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            exportMetrics();
        }
        if (spans != null) spans.shutdown(exportTimeout.plusSeconds(5));
        if (logRecords != null) logRecords.shutdown(exportTimeout.plusSeconds(5));
        if (client != null) {
            client.shutdownNow();
            clientExecutor.shutdownNow();
        }
    }

    @Override
    public String toString() {
        return "Telemetry[" + description + "]";
    }

    /** {@return what this telemetry exports, and where} */
    public String description() {
        return description;
    }

    /** The trace of an exchange when only request ids are on. */
    private record RequestIdOnly(String requestId) implements FlowTrace {}

    /** Exports access-log records as OTLP log records: an {@link ActivityTracker}, as an access logger is. */
    private final class AccessLogExporter implements ActivityTracker {
        @Override
        public void flowEnded(FlowRecord record) {
            BatchProcessor<OtlpData.Log> queue = logRecords;
            if (queue == null) return;
            Attrs a = new Attrs(limits.maxAttributes(), limits.maxAttributeValueLength());
            HttpRequest request = record.request();
            if (request != null) {
                Semconv.request(a, Semconv.RequestInfo.of(request, record.context()));
            } else {
                Semconv.client(a, record.context().getClientAddress());
            }
            Semconv.outcome(a, record);
            if (record.durationNanos() >= 0) a.put("microproxy.duration_ms", record.durationNanos() / 1_000_000.0);
            a.put("guid:x-request-id", record.uniqueId());
            int status = record.responseCode();
            boolean error = Semconv.isError(record);
            int severity = error ? OtlpData.SEVERITY_ERROR : status >= 400 ? OtlpData.SEVERITY_WARN : OtlpData.SEVERITY_INFO;
            String text = severity == OtlpData.SEVERITY_ERROR ? "ERROR" : severity == OtlpData.SEVERITY_WARN ? "WARN" : "INFO";
            long now = epochNanos();
            long time = record.startEpochMillis() > 0 ? record.startEpochMillis() * 1_000_000L : now;
            long high = 0;
            long low = 0;
            long span = 0;
            int flags = 0;
            if (record.trace() instanceof PropagatedTrace t) {
                high = t.traceIdHigh;
                low = t.traceIdLow;
                span = t.spanId;
                flags = t.sampled ? SpanContext.SAMPLED : 0;
            }
            queue.offer(new OtlpData.Log(time, now, severity, text, logFormat.format(record), a, high, low, span, flags));
        }

        @Override
        public String toString() {
            return "Telemetry.AccessLogExporter";
        }
    }

    /** Configures a {@link Telemetry}; every setting has OpenTelemetry's default. */
    public static final class Builder {
        boolean enabled = true;
        String endpoint = "http://localhost:4318";
        String tracesEndpoint;
        String metricsEndpoint;
        String logsEndpoint;
        Protocol protocol = Protocol.HTTP_PROTOBUF;
        final Map<String, String> headers = new LinkedHashMap<>();
        boolean gzip;
        Duration timeout = Duration.ofSeconds(10);
        String serviceName;
        final Map<String, String> resourceAttributes = new LinkedHashMap<>();
        Sampler sampler = Sampler.parentBased(Sampler.alwaysOn());
        List<Propagator> propagators = List.of(Propagators.TRACE_CONTEXT);
        boolean traces = true;
        boolean metrics = true;
        boolean logs = true;
        Duration metricInterval = Duration.ofSeconds(60);
        int spanQueue = 2048;
        int spanBatch = 512;
        Duration spanDelay = Duration.ofSeconds(5);
        int logQueue = 2048;
        int logBatch = 512;
        Duration logDelay = Duration.ofSeconds(1);
        SpanLimits limits = SpanLimits.DEFAULT;
        RequestIdMode requestIdMode = RequestIdMode.KEEP;
        String forceTraceHeader;
        WhenStripped whenStripped = WhenStripped.OWN;
        boolean trustIncoming = true;
        AccessLogFormat logFormat = AccessLogFormat.envoy(AccessLogFormat.ENVOY_DEFAULT);
        String metricPrefix;
        int maxAttempts = 5;
        Duration initialBackoff = Duration.ofSeconds(1);
        Duration maxBackoff = Duration.ofSeconds(5);

        private Builder() {}

        /**
         * Turns everything on (the default) or off; off, {@link #install} changes nothing.
         *
         * @param enabled whether to trace and export
         * @return this builder
         */
        public Builder enabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        /**
         * The collector's OTLP/HTTP base URL; each signal goes to {@code <endpoint>/v1/<signal>}.
         *
         * @param endpoint such as {@code http://otel-collector:4318}
         * @return this builder
         */
        public Builder endpoint(String endpoint) {
            this.endpoint = checkUrl(endpoint);
            return this;
        }

        /**
         * The URL spans go to, as it is ({@code OTEL_EXPORTER_OTLP_TRACES_ENDPOINT}).
         *
         * @param url the full URL, such as {@code http://collector:4318/v1/traces}
         * @return this builder
         */
        public Builder tracesEndpoint(String url) {
            this.tracesEndpoint = checkUrl(url);
            return this;
        }

        /**
         * The URL metrics go to, as it is.
         *
         * @param url the full URL
         * @return this builder
         */
        public Builder metricsEndpoint(String url) {
            this.metricsEndpoint = checkUrl(url);
            return this;
        }

        /**
         * The URL log records go to, as it is.
         *
         * @param url the full URL
         * @return this builder
         */
        public Builder logsEndpoint(String url) {
            this.logsEndpoint = checkUrl(url);
            return this;
        }

        private static String checkUrl(String url) {
            URI uri = URI.create(url.strip());
            if (!"http".equals(uri.getScheme()) && !"https".equals(uri.getScheme()) || uri.getHost() == null) {
                throw new IllegalArgumentException("not an http(s) URL: " + url);
            }
            return uri.toString();
        }

        /**
         * How OTLP is sent: protobuf (the default) or JSON.
         *
         * @param protocol the protocol
         * @return this builder
         */
        public Builder protocol(Protocol protocol) {
            this.protocol = Objects.requireNonNull(protocol);
            return this;
        }

        /**
         * Adds a header to every export, such as {@code authorization}.
         *
         * @param name the header's name
         * @param value its value
         * @return this builder
         */
        public Builder header(String name, String value) {
            headers.put(Objects.requireNonNull(name), Objects.requireNonNull(value));
            return this;
        }

        /**
         * Gzips the exports ({@code OTEL_EXPORTER_OTLP_COMPRESSION=gzip}).
         *
         * @param gzip whether to compress
         * @return this builder
         */
        public Builder compression(boolean gzip) {
            this.gzip = gzip;
            return this;
        }

        /**
         * How long one export attempt may take, connecting included (10 seconds by default).
         *
         * @param timeout the timeout
         * @return this builder
         */
        public Builder timeout(Duration timeout) {
            if (timeout.isNegative() || timeout.isZero()) throw new IllegalArgumentException("timeout must be positive");
            this.timeout = timeout;
            return this;
        }

        /**
         * How failed exports are retried: attempts in all (5 by default), and the backoff between
         * them, growing by half each time from {@code initial} (1 s) up to {@code max} (5 s), with
         * jitter, and never shorter than a {@code Retry-After}.
         *
         * @param maxAttempts the attempts per batch, at least 1
         * @param initial the first wait
         * @param max the longest wait
         * @return this builder
         */
        public Builder retry(int maxAttempts, Duration initial, Duration max) {
            if (maxAttempts < 1) throw new IllegalArgumentException("at least one attempt");
            this.maxAttempts = maxAttempts;
            this.initialBackoff = initial;
            this.maxBackoff = max;
            return this;
        }

        /**
         * {@code service.name} ({@code OTEL_SERVICE_NAME}); {@code microproxy} by default.
         *
         * @param name the service's name
         * @return this builder
         */
        public Builder serviceName(String name) {
            this.serviceName = Objects.requireNonNull(name);
            return this;
        }

        /**
         * A resource attribute ({@code OTEL_RESOURCE_ATTRIBUTES}), besides {@code service.*}, {@code
         * host.name}, {@code process.*} and {@code telemetry.sdk.*}, which it may override.
         *
         * @param key the attribute
         * @param value its value
         * @return this builder
         */
        public Builder resourceAttribute(String key, String value) {
            resourceAttributes.put(Objects.requireNonNull(key), Objects.requireNonNull(value));
            return this;
        }

        /**
         * The sampler; {@code parentbased_always_on} by default.
         *
         * @param sampler the sampler
         * @return this builder
         */
        public Builder sampler(Sampler sampler) {
            this.sampler = Objects.requireNonNull(sampler);
            return this;
        }

        /**
         * Samples every request that has {@code header}, whatever the sampler says (Envoy's {@code
         * x-envoy-force-trace}); none by default.
         *
         * @param header the header's name, or {@code null} for none
         * @return this builder
         */
        public Builder forceTraceHeader(String header) {
            this.forceTraceHeader = header == null || header.isBlank() ? null : header.strip();
            return this;
        }

        /**
         * The propagators: the first that finds a context in a request gives the parent, and all
         * write the proxy's context upstream; W3C Trace Context by default.
         *
         * @param propagators the propagators, possibly none
         * @return this builder
         */
        public Builder propagators(List<Propagator> propagators) {
            this.propagators = List.copyOf(propagators);
            return this;
        }

        /**
         * Whether to continue the traces clients send (the default), or start a new trace for every
         * request, as a trust boundary.
         *
         * @param trust whether to read the clients' trace context
         * @return this builder
         */
        public Builder trustIncoming(boolean trust) {
            this.trustIncoming = trust;
            return this;
        }

        /**
         * What goes upstream when the proxy strips tracing headers: the proxy's own context (the
         * default) or nothing.
         *
         * @param mode the mode
         * @return this builder
         */
        public Builder whenStripped(WhenStripped mode) {
            this.whenStripped = Objects.requireNonNull(mode);
            return this;
        }

        /**
         * What happens to {@code X-Request-Id}: kept, or made when missing (the default), always
         * made, or left alone.
         *
         * @param mode the mode
         * @return this builder
         */
        public Builder requestId(RequestIdMode mode) {
            this.requestIdMode = Objects.requireNonNull(mode);
            return this;
        }

        /**
         * Whether spans are exported ({@code OTEL_TRACES_EXPORTER}); without them the proxy still
         * propagates.
         *
         * @param on whether to export spans
         * @return this builder
         */
        public Builder traces(boolean on) {
            this.traces = on;
            return this;
        }

        /**
         * Whether the proxy's stats are exported as metrics ({@code OTEL_METRICS_EXPORTER}).
         *
         * @param on whether to export metrics
         * @return this builder
         */
        public Builder metrics(boolean on) {
            this.metrics = on;
            return this;
        }

        /**
         * Whether access-log records are exported as log records ({@code OTEL_LOGS_EXPORTER}).
         *
         * @param on whether to export logs
         * @return this builder
         */
        public Builder logs(boolean on) {
            this.logs = on;
            return this;
        }

        /**
         * How often metrics are exported ({@code OTEL_METRIC_EXPORT_INTERVAL}, 60 s).
         *
         * @param interval the interval
         * @return this builder
         */
        public Builder metricInterval(Duration interval) {
            if (interval.isNegative() || interval.isZero()) throw new IllegalArgumentException("interval must be positive");
            this.metricInterval = interval;
            return this;
        }

        /**
         * The prefix of exported metric names; the registry's ({@code envoy}) by default.
         *
         * @param prefix the prefix, or an empty string for none
         * @return this builder
         */
        public Builder metricPrefix(String prefix) {
            this.metricPrefix = prefix;
            return this;
        }

        /**
         * The span queue ({@code OTEL_BSP_*}): its size (2048), the largest batch (512) and how long
         * a span waits for its batch to fill (5 s).
         *
         * @param maxQueue spans waiting at most; more are dropped
         * @param maxBatch spans per export at most
         * @param delay the wait
         * @return this builder
         */
        public Builder spanQueue(int maxQueue, int maxBatch, Duration delay) {
            checkQueue(maxQueue, maxBatch, delay);
            this.spanQueue = maxQueue;
            this.spanBatch = maxBatch;
            this.spanDelay = delay;
            return this;
        }

        /**
         * The log record queue ({@code OTEL_BLRP_*}): 2048, 512 and 1 s by default.
         *
         * @param maxQueue log records waiting at most; more are dropped
         * @param maxBatch log records per export at most
         * @param delay the wait
         * @return this builder
         */
        public Builder logQueue(int maxQueue, int maxBatch, Duration delay) {
            checkQueue(maxQueue, maxBatch, delay);
            this.logQueue = maxQueue;
            this.logBatch = maxBatch;
            this.logDelay = delay;
            return this;
        }

        private static void checkQueue(int maxQueue, int maxBatch, Duration delay) {
            if (maxQueue <= 0 || maxBatch <= 0 || delay.isNegative()) {
                throw new IllegalArgumentException("queue and batch sizes must be positive");
            }
        }

        /**
         * The span limits.
         *
         * @param limits the limits
         * @return this builder
         */
        public Builder spanLimits(SpanLimits limits) {
            this.limits = Objects.requireNonNull(limits);
            return this;
        }

        /**
         * The body of exported log records: an access-log format; Envoy's default by default.
         *
         * @param format the format
         * @return this builder
         */
        public Builder logFormat(AccessLogFormat format) {
            this.logFormat = Objects.requireNonNull(format);
            return this;
        }

        /** {@return the telemetry; its exporters' threads start now} */
        public Telemetry build() {
            return new Telemetry(this);
        }
    }
}
