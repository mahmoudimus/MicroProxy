package org.microproxy.otel;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import org.microproxy.ChainedProxy;
import org.microproxy.ChainedProxyAdapter;
import org.microproxy.FlowRecord;
import org.microproxy.http.HttpHeaders;

/**
 * The trace of a sampled exchange: the proxy's SERVER span for it (INTERNAL for a tunnel or a
 * flow), and a CLIENT span for each attempt to reach the server. What the request said is read
 * when it arrives; the rest comes from the exchange's {@link FlowRecord} when it is over, and the
 * spans are queued for export then. Attributes and events that filters and scripts add are kept
 * within the {@link SpanLimits}.
 */
final class RecordingSpan extends PropagatedTrace {

    /** Attempts beyond this many are not recorded (a long route of chained proxies). */
    private static final int MAX_ATTEMPTS = 32;

    private final long parentSpanId;
    private final boolean parentRemote;
    private final Semconv.RequestInfo request;
    private final long startEpochNanos;
    private final long startNanoTime;
    private final ReentrantLock lock = new ReentrantLock();
    private final Attrs custom;
    private final List<OtlpData.Event> events = new ArrayList<>(0);
    private int droppedEvents;
    private final List<Attempt> attempts = new ArrayList<>(2);
    private int droppedAttempts;
    private Attempt current;
    private boolean finished;

    /** One attempt to reach the server: its CLIENT span. */
    private static final class Attempt {
        final long spanId = SpanContext.randomSpanId();
        final long startNanoTime = System.nanoTime();
        final String hostAndPort;
        final String chainedProxy;
        final int index;
        long endNanoTime;
        int status;
        String errorType;
        boolean ended;

        Attempt(String hostAndPort, String chainedProxy, int index) {
            this.hostAndPort = hostAndPort;
            this.chainedProxy = chainedProxy;
            this.index = index;
        }
    }

    RecordingSpan(Telemetry telemetry, long traceIdHigh, long traceIdLow, long spanId, SpanContext parent,
            String requestId, Semconv.RequestInfo request) {
        super(telemetry, traceIdHigh, traceIdLow, spanId, true, parent == null ? "" : parent.traceState(), requestId);
        this.parentSpanId = parent == null ? 0 : parent.spanId();
        this.parentRemote = parent != null && parent.remote();
        this.request = request;
        this.startEpochNanos = Telemetry.epochNanos();
        this.startNanoTime = System.nanoTime();
        this.custom = new Attrs(telemetry.limits.maxAttributes(), telemetry.limits.maxAttributeValueLength());
    }

    private long epoch(long nanoTime) {
        return startEpochNanos + (nanoTime - startNanoTime);
    }

    @Override
    public void setAttribute(String key, Object value) {
        lock.lock();
        try {
            if (!finished) custom.put(key, value);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void addEvent(String name, Map<String, ?> attributes) {
        long now = Telemetry.epochNanos();
        lock.lock();
        try {
            if (finished) return;
            if (events.size() >= telemetry.limits.maxEvents()) {
                droppedEvents++;
                return;
            }
            Attrs a = new Attrs(telemetry.limits.maxAttributesPerEvent(), telemetry.limits.maxAttributeValueLength());
            if (attributes != null) attributes.forEach(a::put);
            events.add(new OtlpData.Event(now, name, a));
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void attemptStarted(String hostAndPort, ChainedProxy chainedProxy) {
        String via = chainedProxy == null || chainedProxy == ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION
                || chainedProxy.getChainedProxyAddress() == null ? null
                : Semconv.address(chainedProxy.getChainedProxyAddress());
        lock.lock();
        try {
            if (finished) return;
            if (current != null) end(current, 0, null);
            if (attempts.size() >= MAX_ATTEMPTS) {
                droppedAttempts++;
                current = null;
                return;
            }
            current = new Attempt(hostAndPort, via, attempts.size() + droppedAttempts);
            attempts.add(current);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void injectUpstream(HttpHeaders headers, boolean tracingHeadersStripped) {
        Attempt attempt;
        lock.lock();
        try {
            attempt = current;
        } finally {
            lock.unlock();
        }
        // The server's parent is the attempt's CLIENT span (the SERVER span's, outside an attempt).
        inject(headers, tracingHeadersStripped, attempt == null ? spanId : attempt.spanId);
    }

    @Override
    public void attemptEnded(int status, String errorType) {
        lock.lock();
        try {
            if (current != null) end(current, status, errorType);
            current = null;
        } finally {
            lock.unlock();
        }
    }

    private static void end(Attempt a, int status, String errorType) {
        if (a.ended) return;
        a.ended = true;
        a.endNanoTime = System.nanoTime();
        a.status = status;
        a.errorType = errorType;
    }

    /** Ends the spans with what {@code record} says, and queues them; once. */
    void finish(FlowRecord record) {
        List<Attempt> tried;
        List<OtlpData.Event> added;
        int dropped;
        Attrs user;
        lock.lock();
        try {
            if (finished) return;
            finished = true;
            tried = List.copyOf(attempts);
            added = List.copyOf(events);
            dropped = droppedEvents;
            user = custom;
        } finally {
            lock.unlock();
        }
        SpanLimits limits = telemetry.limits;
        long duration = record.durationNanos();
        // The record's times run from the request's first byte, a few microseconds before this span
        // started: the span ends no earlier than its attempts, and its events fall inside it.
        long measured = duration >= 0 ? startEpochNanos + duration : Telemetry.epochNanos();
        for (Attempt attempt : tried) {
            if (attempt.ended) measured = Math.max(measured, epoch(attempt.endNanoTime));
        }
        long end = Math.max(startEpochNanos, measured);
        boolean http = record.kind().isHttp();

        Attrs a = new Attrs(limits.maxAttributes(), limits.maxAttributeValueLength());
        Semconv.request(a, request);
        Semconv.outcome(a, record);
        if (requestId() != null) a.put("guid:x-request-id", requestId());
        for (int i = 0; i < user.size(); i++) a.put(user.key(i), user.value(i));
        a.addDropped(user.dropped());

        List<OtlpData.Event> spanEvents = new ArrayList<>(added.size() + 6);
        int[] droppedTotal = {dropped};
        Semconv.timingEvents((time, name, key, nanos) -> {
            if (spanEvents.size() + added.size() >= limits.maxEvents()) {
                droppedTotal[0]++;
                return;
            }
            Attrs ea = new Attrs(limits.maxAttributesPerEvent(), limits.maxAttributeValueLength());
            if (key != null) ea.put(key, nanos / 1_000_000.0);
            spanEvents.add(new OtlpData.Event(Math.min(end, Math.max(startEpochNanos, time)), name, ea));
        }, record.timings(), startEpochNanos);
        spanEvents.addAll(added);
        spanEvents.sort((x, y) -> Long.compare(x.timeNanos(), y.timeNanos()));

        boolean error = Semconv.isError(record);
        int flags = SpanContext.SAMPLED | OtlpData.FLAG_HAS_IS_REMOTE | (parentRemote ? OtlpData.FLAG_IS_REMOTE : 0);
        String name = http ? (request.isConnect() ? "CONNECT" : spanName(request.method()))
                : Semconv.flowName(record.kind(), request);
        telemetry.export(new OtlpData.Span(traceIdHigh, traceIdLow, spanId, parentSpanId, traceState, flags, name,
                http ? OtlpData.KIND_SERVER : OtlpData.KIND_INTERNAL, startEpochNanos, end, a,
                List.copyOf(spanEvents), droppedTotal[0], error ? OtlpData.STATUS_ERROR : OtlpData.STATUS_UNSET,
                error ? record.responseCodeDetails() : null));

        for (Attempt attempt : tried) {
            telemetry.export(clientSpan(attempt, record, end));
        }
    }

    private OtlpData.Span clientSpan(Attempt attempt, FlowRecord record, long serverEnd) {
        SpanLimits limits = telemetry.limits;
        boolean open = !attempt.ended;
        long start = epoch(attempt.startNanoTime);
        long end = open ? serverEnd : epoch(attempt.endNanoTime);
        // An attempt still open when the exchange ended carried it to the end: a tunnel's connection.
        int status = open ? record.responseCode() : attempt.status;
        String errorType = attempt.errorType;
        if (open && errorType == null && Semconv.isError(record)) errorType = Semconv.errorType(record);
        Attrs a = new Attrs(limits.maxAttributes(), limits.maxAttributeValueLength());
        a.put("http.request.method", Semconv.method(request.method()));
        String url = Semconv.upstreamUrl(request, attempt.hostAndPort);
        if (url != null) a.put("url.full", url);
        a.put("server.address", Semconv.hostOf(attempt.hostAndPort));
        long port = Semconv.portOf(attempt.hostAndPort, -1);
        if (port > 0) a.put("server.port", port);
        a.put("upstream_cluster", attempt.chainedProxy != null ? attempt.chainedProxy : attempt.hostAndPort);
        if (attempt.chainedProxy != null) a.put("microproxy.chained_proxy", attempt.chainedProxy);
        if (attempt.index > 0) a.put("http.request.resend_count", (long) attempt.index);
        if (status > 0) a.put("http.response.status_code", (long) status);
        boolean httpError = !request.isConnect() && status >= 400;
        if (errorType == null && httpError) errorType = Integer.toString(status);
        if (errorType != null) a.put("error.type", errorType);
        boolean error = errorType != null;
        int flags = SpanContext.SAMPLED | OtlpData.FLAG_HAS_IS_REMOTE;
        return new OtlpData.Span(traceIdHigh, traceIdLow, attempt.spanId, spanId, traceState, flags,
                spanName(request.method()), OtlpData.KIND_CLIENT, start, Math.max(start, end), a, List.of(), 0,
                error ? OtlpData.STATUS_ERROR : OtlpData.STATUS_UNSET, error ? errorType : null);
    }

    /** The name of an HTTP span: its method, or {@code HTTP} for one the conventions do not name. */
    static String spanName(String method) {
        String m = Semconv.method(method);
        return m.equals("_OTHER") ? "HTTP" : m;
    }
}
