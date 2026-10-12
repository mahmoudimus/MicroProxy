package org.microproxy.otel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.starlark.ScriptedProxy;
import org.microproxy.starlark.StarlarkScript;

/**
 * Hook calls as spans: each call into a script for a sampled exchange is an INTERNAL span {@code
 * starlark <hook>}, a child of the exchange's span (of the tunnel's, for TCP hooks), with the
 * script's measures; {@code trace.set_attribute} and {@code trace.add_event} stay on the
 * exchange's span; nothing is made for an exchange that is not sampled.
 */
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class ScriptSpansTest {

    static final String TRACE = "0af7651916cd43dd8448eb211c80319c";
    static final String PARENT = "b7ad6b7169203331";
    static final int INTERNAL = 1;
    static final int SERVER = 2;

    static final String HOOKS = """
            def on_request(req, ctx):
                trace.set_attribute("tenant", "acme")
                trace.add_event("rule.matched", {"rule": "r1"})
                if req.path == "/hog":
                    s = "x"
                    for i in range(40):
                        s = s + s
                if req.path == "/fail":
                    fail("refused by a broken script")
                ctx.vars["seen"] = [i for i in range(20)]

            def on_response(req, res, ctx):
                res.headers["X-Hooked"] = "yes"
            """;

    private TestCollector collector;
    private HttpServer origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() throws Exception {
        collector = new TestCollector();
        origin = TestSupport.origin(TestSupport.echo());
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.stop();
        origin.stop(0);
        collector.close();
    }

    private Telemetry telemetry() {
        return Telemetry.builder().endpoint(collector.endpoint()).metrics(false).logs(false)
                .spanQueue(2048, 512, Duration.ofMillis(20)).build();
    }

    private HttpProxyServer start(HttpProxyServerBootstrap bootstrap) {
        proxy = telemetry().install(bootstrap.withPort(0)).start();
        return proxy;
    }

    private HttpResponse<String> get(String path, String flags) {
        return TestSupport.send(TestSupport.client(proxy), HttpRequest.newBuilder(URI.create(TestSupport.url(origin, path)))
                .header("traceparent", "00-" + TRACE + "-" + PARENT + "-" + flags).timeout(Duration.ofSeconds(30)).build());
    }

    private static TestCollector.Span named(List<TestCollector.Span> spans, String name) {
        return spans.stream().filter(s -> s.name().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError(name + " in " + spans));
    }

    private static ScriptedProxy script(StarlarkScript.Limits limits) throws Exception {
        return ScriptedProxy.builder(HOOKS, "hooks.star").limits(limits).build();
    }

    @Test
    void eachHookCallIsAChildOfTheExchangesSpan() throws Exception {
        start(MicroProxy.bootstrap().withFiltersSource(script(StarlarkScript.Limits.DEFAULT)));
        assertEquals("yes", get("/ok", "01").headers().firstValue("x-hooked").orElseThrow());
        List<TestCollector.Span> spans = collector.awaitSpans("the exchange's and its hooks' spans",
                s -> s.stream().anyMatch(x -> x.kind() == SERVER) && s.stream().filter(x -> x.kind() == INTERNAL).count() >= 2);
        TestCollector.Span server = spans.stream().filter(s -> s.kind() == SERVER).findFirst().orElseThrow();
        for (String hook : List.of("on_request", "on_response")) {
            TestCollector.Span span = named(spans, "starlark " + hook);
            assertEquals(INTERNAL, span.kind());
            assertEquals(TRACE, span.traceId());
            assertEquals(server.spanId(), span.parentSpanId(), "a child of the exchange's span");
            assertEquals(hook, span.attr("starlark.hook"));
            assertEquals("hooks", span.attr("starlark.script"));
            assertTrue(((Number) span.attr("starlark.steps")).longValue() > 0, span.toString());
            // on_request makes a list; on_response sets a header to a literal, which makes nothing.
            long alloc = ((Number) span.attr("starlark.alloc_bytes")).longValue();
            assertTrue(hook.equals("on_request") ? alloc > 0 : alloc >= 0, span.toString());
            assertNull(span.attr("starlark.budget_exceeded"));
            assertEquals(0, span.statusCode(), "unset");
            assertTrue(span.start() >= server.start() && span.end() <= server.end(), span + " within " + server);
        }
        // What the script notes about the exchange is on the exchange's span, not the hook's.
        assertEquals("acme", server.attr("tenant"));
        assertTrue(server.event("rule.matched") != null, server.toString());
        TestCollector.Span onRequest = named(spans, "starlark on_request");
        assertNull(onRequest.attr("tenant"));
        assertTrue(onRequest.events().isEmpty());
    }

    @Test
    void aFailedCallHasAnErrorStatusAndItsExhaustedBudget() throws Exception {
        start(MicroProxy.bootstrap().withFiltersSource(script(StarlarkScript.Limits.DEFAULT.withMaxAllocBytes(1 << 20))));
        assertEquals(500, get("/hog", "01").statusCode());
        TestCollector.Span hog = collector.awaitSpan("the hog's span", s -> s.name().equals("starlark on_request"));
        assertEquals(2, hog.statusCode(), "error");
        assertTrue(hog.statusMessage().startsWith("memory budget exceeded"), hog.statusMessage());
        assertEquals("memory", hog.attr("starlark.budget_exceeded"));
        collector.spans.clear();
        assertEquals(500, get("/fail", "01").statusCode());
        TestCollector.Span failed = collector.awaitSpan("the failed span", s -> s.name().equals("starlark on_request"));
        assertEquals(2, failed.statusCode());
        assertEquals("refused by a broken script", failed.statusMessage());
        assertNull(failed.attr("starlark.budget_exceeded"));
    }

    @Test
    void anExchangeThatIsNotSampledGetsNoHookSpans() throws Exception {
        start(MicroProxy.bootstrap().withFiltersSource(script(StarlarkScript.Limits.DEFAULT)));
        assertEquals(200, get("/unsampled", "00").statusCode());
        assertEquals(200, get("/sampled", "01").statusCode());
        collector.awaitSpans("the sampled exchange's spans",
                s -> s.stream().filter(x -> x.name().startsWith("starlark ")).count() >= 2);
        assertEquals(2, collector.spans.stream().filter(s -> s.name().startsWith("starlark ")).count(),
                collector.spans.toString());
    }

    @Test
    void tcpHookCallsAreChildrenOfTheTunnelsSpan() throws Exception {
        TestSupport.RawServer server = TestSupport.rawServer(s -> {
            OutputStream out = s.getOutputStream();
            out.write("220 ready\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();
            s.getInputStream().read();
        });
        try (server) {
            ScriptedProxy script = ScriptedProxy.builder("""
                    def on_tcp_start(ctx):
                        trace.set_attribute("tunnel.note", "started")

                    def on_tcp_message(msg, ctx):
                        return None
                    """, "tunnel.star").build();
            start(MicroProxy.bootstrap().withTcpInterceptor(script.tcpInterceptor()));
            try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
                s.setSoTimeout(20_000);
                TestSupport.write(s.getOutputStream(), "CONNECT 127.0.0.1:" + server.port() + " HTTP/1.1\r\nHost: x\r\n"
                        + "traceparent: 00-" + TRACE + "-" + PARENT + "-01\r\n\r\n");
                assertTrue(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 200"));
                assertEquals("220 ready\r\n", TestSupport.readUntil(s.getInputStream(), "\r\n"));
                TestSupport.write(s.getOutputStream(), "QUIT\r\n");
            } catch (IOException e) {
                throw new AssertionError(e);
            }
            List<TestCollector.Span> spans = collector.awaitSpans("the tunnel's and its hooks' spans",
                    s -> s.stream().anyMatch(x -> x.name().equals("starlark on_tcp_start"))
                            && s.stream().anyMatch(x -> x.name().equals("starlark on_tcp_message"))
                            && s.stream().anyMatch(x -> x.attr("tunnel.note") != null));
            TestCollector.Span tunnel = spans.stream().filter(x -> x.attr("tunnel.note") != null).findFirst().orElseThrow();
            for (String hook : List.of("on_tcp_start", "on_tcp_message")) {
                TestCollector.Span span = named(spans, "starlark " + hook);
                assertEquals(tunnel.spanId(), span.parentSpanId(), hook + " under " + tunnel);
                assertEquals("tunnel", span.attr("starlark.script"));
            }
        }
    }
}
