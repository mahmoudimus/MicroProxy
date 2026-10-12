package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.ChainTestSupport.always;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.extras.AccessLogFormat;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpRequest;

/**
 * The core's tracing hooks ({@link FlowTracer}, {@link FlowTrace}): a trace per exchange made
 * before anything sees the request, an attempt per connection tried and per request sent, the
 * trace's headers on what goes upstream after the stripped ones are removed, and the record of
 * the finished exchange.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class FlowTracerTest {

    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private final RecordedFlows flows = new RecordedFlows();
    private final Recording tracer = new Recording();
    private HttpServer origin;

    @AfterEach
    void tearDown() {
        proxies.close();
        if (origin != null) origin.stop(0);
    }

    @Test
    void anExchangeIsTracedFromItsRequestToItsRecord() {
        origin = TestSupport.origin(TestSupport.echo());
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withTracer(tracer).plusActivityTracker(flows));
        assertEquals(1, tracer.started.get());
        String body = get(client(proxy), TestSupport.url(origin, "/traced")).body();
        // The tracer's request id reached the server, and its context replaced the client's.
        assertEquals(List.of("req-1"), TestSupport.echoedHeader(body, "x-request-id"));
        assertEquals(List.of("00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"),
                TestSupport.echoedHeader(body, "traceparent"));
        FlowRecord record = flows.await(FlowRecord.Kind.HTTP1);
        Trace trace = tracer.traces.getFirst();
        assertSame(trace, record.trace());
        assertEquals("req-1", record.uniqueId());
        assertEquals(List.of("start 127.0.0.1:" + origin.getAddress().getPort() + " direct tls=false",
                "request tls=false HTTP/1.1", "inject stripped=false", "end 200 null"), trace.events);
        TestSupport.eventually("the tracer's record", () -> tracer.ended.contains(record));
        assertEquals("0af7651916cd43dd8448eb211c80319c 00f067aa0ba902b7 req-1",
                AccessLogFormat.envoy("%TRACE_ID% %SPAN_ID% %UNIQUE_ID%").format(record));
        proxy.stop();
        assertEquals(1, tracer.closed.get());
    }

    @Test
    void strippedTracingHeadersAreGoneBeforeTheTraceInjects() {
        origin = TestSupport.origin(TestSupport.echo());
        tracer.inject = false;
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withTracer(tracer).withoutTracingHeadersUpstream());
        String body = TestSupport.send(client(proxy), java.net.http.HttpRequest.newBuilder(
                java.net.URI.create(TestSupport.url(origin, "/stripped")))
                .header("traceparent", "00-11111111111111111111111111111111-2222222222222222-01").build()).body();
        assertEquals(List.of(), TestSupport.echoedHeader(body, "traceparent"));
        assertEquals("inject stripped=true", tracer.traces.getFirst().events.get(2));
    }

    @Test
    void eachChainedProxyTriedIsAnAttempt() throws Exception {
        origin = TestSupport.origin(TestSupport.fixed(200, "ok"));
        try (Socket refusing = TestSupport.refusingPort()) {
            ChainedProxy dead = ChainTestSupport.http((InetSocketAddress) refusing.getLocalSocketAddress());
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withTracer(tracer)
                    .withChainProxyManager(always(dead, ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION)));
            assertEquals(200, get(client(proxy), TestSupport.url(origin, "/failover")).statusCode());
            TestSupport.eventually("the record", () -> tracer.ended.size() == 1);
            String server = "127.0.0.1:" + origin.getAddress().getPort();
            assertEquals(List.of("start " + server + " " + dead.getChainedProxyAddress() + " tls=false",
                    "end 0 connect_failed", "start " + server + " direct tls=false", "request tls=false HTTP/1.1",
                    "inject stripped=false", "end 200 null"),
                    tracer.traces.getFirst().events);
        }
    }

    @Test
    void aFailingTracerTracesNothing() {
        origin = TestSupport.origin(TestSupport.fixed(200, "ok"));
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withTracer(new FlowTracer() {
            @Override
            public FlowTrace startExchange(FlowContext flow, HttpRequest request) {
                throw new IllegalStateException("broken tracer");
            }
        }).plusActivityTracker(flows));
        assertEquals(200, get(client(proxy), TestSupport.url(origin, "/")).statusCode());
        assertSame(FlowTrace.NONE, flows.await(FlowRecord.Kind.HTTP1).trace());
    }

    /** Records what the proxy tells it. */
    static final class Recording implements FlowTracer {
        final List<Trace> traces = new CopyOnWriteArrayList<>();
        final List<FlowRecord> ended = new CopyOnWriteArrayList<>();
        final AtomicInteger started = new AtomicInteger();
        final AtomicInteger closed = new AtomicInteger();
        volatile boolean inject = true;

        @Override
        public FlowTrace startExchange(FlowContext flow, HttpRequest request) {
            request.headers().set("x-request-id", "req-" + (traces.size() + 1));
            Trace trace = new Trace(inject);
            assertSame(FlowTrace.NONE, flow.trace());
            traces.add(trace);
            return trace;
        }

        @Override
        public void flowEnded(FlowRecord record) {
            assertSame(record.trace(), record.context().trace());
            ended.add(record);
        }

        @Override
        public void proxyStarted(HttpProxyServer server) {
            started.incrementAndGet();
        }

        @Override
        public void close() {
            closed.incrementAndGet();
        }
    }

    static final class Trace implements FlowTrace {
        final List<String> events = new CopyOnWriteArrayList<>();
        final boolean inject;

        Trace(boolean inject) {
            this.inject = inject;
        }

        @Override
        public String traceId() {
            return "0af7651916cd43dd8448eb211c80319c";
        }

        @Override
        public String spanId() {
            return "00f067aa0ba902b7";
        }

        @Override
        public String requestId() {
            return "req-1";
        }

        @Override
        public void addEvent(String name, Map<String, ?> attributes) {
            events.add(name);
        }

        @Override
        public void attemptStarted(String hostAndPort, ChainedProxy chainedProxy, boolean tls) {
            events.add("start " + hostAndPort + " " + (chainedProxy == null ? "direct" : chainedProxy.getChainedProxyAddress())
                    + " tls=" + tls);
        }

        @Override
        public void upstreamRequest(boolean tls, org.microproxy.http.HttpVersion version) {
            events.add("request tls=" + tls + " " + version);
        }

        @Override
        public void injectUpstream(HttpHeaders headers, boolean tracingHeadersStripped) {
            events.add("inject stripped=" + tracingHeadersStripped);
            if (inject) headers.set("traceparent", "00-" + traceId() + "-" + spanId() + "-01");
        }

        @Override
        public void attemptEnded(int status, String errorType) {
            events.add("end " + status + " " + errorType);
        }
    }
}
