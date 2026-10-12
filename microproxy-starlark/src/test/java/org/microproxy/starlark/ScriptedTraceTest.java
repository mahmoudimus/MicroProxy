package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.FlowContext;
import org.microproxy.FlowTrace;
import org.microproxy.FlowTracer;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.http.HttpHeaders;
import org.microproxy.otel.Telemetry;

/**
 * Scripts and the exchange's trace: {@code ctx.trace_id} and {@code ctx.span_id}, and the {@code
 * trace} module's attributes and events on the exchange's span, with a recording tracer and with
 * OpenTelemetry exporting them.
 */
class ScriptedTraceTest {

    static final String SCRIPT = """
            def on_request(req, ctx):
                req.headers["x-trace-id"] = ctx.trace_id or "none"
                req.headers["x-span-id"] = ctx.span_id or "none"
                trace.set_attribute("tenant", req.headers.get("x-tenant", "unknown"))
                trace.set_attribute("weights", [1, 2.5, True, "x"])
                trace.set_attribute("big", 1 << 70)
                if trace.is_recording():
                    trace.add_event("rule.matched", {"rule": "r1", "score": 7})

            def on_response(req, res, ctx):
                trace.set_attribute("status_seen", res.status)
                res.headers["x-recording"] = str(trace.is_recording())
            """;

    /** The documented example. */
    static final String README = """
            def on_request(req, ctx):
                trace.set_attribute("tenant", req.headers.get("x-tenant", "none"))
                if trace.is_recording() and req.path.startswith("/admin"):
                    trace.add_event("admin.access", {"user": ctx.user or "anonymous"})
                req.headers["X-Trace-Id"] = ctx.trace_id or "untraced"
            """;

    private HttpServer origin;
    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.stop();
        if (origin != null) origin.stop(0);
    }

    /** A trace that records what scripts tell it. */
    static final class Recorded implements FlowTrace {
        final List<String> calls = new CopyOnWriteArrayList<>();

        @Override
        public String traceId() {
            return "0af7651916cd43dd8448eb211c80319c";
        }

        @Override
        public String spanId() {
            return "00f067aa0ba902b7";
        }

        @Override
        public boolean isSampled() {
            return true;
        }

        @Override
        public void setAttribute(String key, Object value) {
            calls.add(key + "=" + value + " (" + (value instanceof List ? "List" : value.getClass().getSimpleName()) + ")");
        }

        @Override
        public void addEvent(String name, Map<String, ?> attributes) {
            calls.add("event " + name + " " + attributes);
        }

        @Override
        public void injectUpstream(HttpHeaders headers, boolean tracingHeadersStripped) {}
    }

    @Test
    void scriptsReadTheIdsAndAddToTheSpan() throws Exception {
        origin = origin(echo());
        List<Recorded> traces = new CopyOnWriteArrayList<>();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withFiltersSource(ScriptedProxy.builder(SCRIPT, "trace.star").build())
                .withTracer(new FlowTracer() {
                    @Override
                    public FlowTrace startExchange(FlowContext flow, org.microproxy.http.HttpRequest request) {
                        Recorded r = new Recorded();
                        traces.add(r);
                        return r;
                    }
                })
                .start();
        HttpResponse<String> response = TestSupport.send(client(proxy),
                HttpRequest.newBuilder(URI.create(url(origin, "/traced"))).header("X-Tenant", "acme").build());
        assertEquals(List.of("0af7651916cd43dd8448eb211c80319c"), TestSupport.echoedHeader(response.body(), "x-trace-id"));
        assertEquals(List.of("00f067aa0ba902b7"), TestSupport.echoedHeader(response.body(), "x-span-id"));
        assertEquals("True", response.headers().firstValue("x-recording").orElseThrow());
        assertEquals(List.of("tenant=acme (String)", "weights=[1, 2.5, true, x] (List)",
                "big=1180591620717411303424 (String)", "event rule.matched {rule=r1, score=7}",
                "status_seen=200 (Long)"), traces.getFirst().calls);
    }

    @Test
    void theReadmesExampleRuns() throws Exception {
        origin = origin(echo());
        List<Recorded> traces = new CopyOnWriteArrayList<>();
        proxy = MicroProxy.bootstrap().withPort(0)
                .withFiltersSource(ScriptedProxy.builder(ScriptedReadmeTest.inDocs(README), "readme.star").build())
                .withTracer((flow, request) -> {
                    Recorded r = new Recorded();
                    traces.add(r);
                    return r;
                })
                .start();
        HttpResponse<String> response = get(client(proxy), url(origin, "/admin/users"));
        assertEquals(List.of("0af7651916cd43dd8448eb211c80319c"), TestSupport.echoedHeader(response.body(), "x-trace-id"));
        assertEquals(List.of("tenant=none (String)", "event admin.access {user=anonymous}"), traces.getFirst().calls);
    }

    @Test
    void withoutATracerTheIdsAreNoneAndTheCallsDoNothing() throws Exception {
        origin = origin(echo());
        proxy = MicroProxy.bootstrap().withPort(0)
                .withFiltersSource(ScriptedProxy.builder(SCRIPT, "trace.star").build()).start();
        HttpResponse<String> response = get(client(proxy), url(origin, "/untraced"));
        assertEquals(200, response.statusCode());
        assertEquals(List.of("none"), TestSupport.echoedHeader(response.body(), "x-trace-id"));
        assertEquals("False", response.headers().firstValue("x-recording").orElseThrow());
    }

    @Test
    void attributesReachTheExportedSpan() throws Exception {
        List<String> bodies = new CopyOnWriteArrayList<>();
        HttpServer collector = HttpServer.create(new InetSocketAddress(TestSupport.LOOPBACK, 0), 0);
        collector.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        collector.createContext("/v1/traces", exchange -> {
            bodies.add(new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        collector.start();
        try {
            origin = origin(echo());
            Telemetry telemetry = Telemetry.builder().endpoint("http://127.0.0.1:" + collector.getAddress().getPort())
                    .protocol(Telemetry.Protocol.HTTP_JSON).metrics(false).logs(false)
                    .spanQueue(64, 64, Duration.ofMillis(10)).build();
            proxy = telemetry.install(MicroProxy.bootstrap().withPort(0)
                    .withFiltersSource(ScriptedProxy.builder(SCRIPT, "trace.star").build())).start();
            HttpResponse<String> response = TestSupport.send(client(proxy),
                    HttpRequest.newBuilder(URI.create(url(origin, "/exported"))).header("X-Tenant", "acme").build());
            String traceId = TestSupport.echoedHeader(response.body(), "x-trace-id").getFirst();
            TestSupport.eventually("the exported span", () -> bodies.stream().anyMatch(b -> b.contains("\"rule.matched\"")));
            String body = String.join("\n", bodies);
            assertTrue(body.contains("\"traceId\":\"" + traceId + "\""), body);
            assertTrue(body.contains("{\"key\":\"tenant\",\"value\":{\"stringValue\":\"acme\"}}"), body);
            assertTrue(body.contains("{\"key\":\"status_seen\",\"value\":{\"intValue\":\"200\"}}"), body);
            assertTrue(body.contains("{\"key\":\"score\",\"value\":{\"intValue\":\"7\"}}"), body);
        } finally {
            collector.stop(0);
        }
    }
}
