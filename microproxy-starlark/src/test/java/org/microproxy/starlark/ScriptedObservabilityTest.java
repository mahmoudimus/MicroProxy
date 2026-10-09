package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersChain;
import org.microproxy.HttpFiltersSource;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.WebSocketTestSupport;
import org.microproxy.cache.HttpCache;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.WebSocketFrame;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;

/** {@code res.source}, {@code res.upstream_status} and {@code ctx.timings}. */
class ScriptedObservabilityTest {

    private HttpServer origin;
    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.stop(0);
    }

    private static ScriptedProxy script(String source) throws Exception {
        return ScriptedProxy.builder(source, "observe.star").build();
    }

    private static final String TAG_SOURCE = """
            def on_response(req, res, ctx):
                res.headers["X-Source"] = str(res.source)
                res.headers["X-Upstream"] = str(res.upstream_status)
                if req.path == "/restatus":
                    res.status = 299  # source and upstream_status describe what the hook received
                    res.headers["X-After"] = "%s %s" % (res.source, res.upstream_status)
            """;

    private static String header(HttpResponse<?> response, String name) {
        return response.headers().firstValue(name).orElse("<missing>");
    }

    @Test
    void serverResponses() throws Exception {
        origin = origin(echo());
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(script(TAG_SOURCE)).start();
        HttpResponse<String> plain = get(client(proxy), url(origin, "/"));
        assertEquals("server", header(plain, "x-source"));
        assertEquals("200", header(plain, "x-upstream"));

        HttpResponse<String> changed = get(client(proxy), url(origin, "/restatus"));
        assertEquals(299, changed.statusCode());
        assertEquals("server 200", header(changed, "x-after"));
    }

    @Test
    void theConnectResponseIsTheProxys() throws Exception {
        origin = origin(echo());
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(script(TAG_SOURCE)).start();
        try (RawHttp http = new RawHttp(proxy.getListenAddress())) {
            RawHttp.Response connect = http.send("CONNECT", "127.0.0.1:" + origin.getAddress().getPort());
            assertEquals(200, connect.status());
            assertEquals("proxy", connect.header("x-source"));
            assertEquals("None", connect.header("x-upstream"));
        }
    }

    @Test
    void earlierFiltersAndTheCache() throws Exception {
        origin = origin(exchange -> {
            boolean revalidating = "\"v1\"".equals(exchange.getRequestHeaders().getFirst("If-None-Match"));
            exchange.getResponseHeaders().set("ETag", "\"v1\"");
            exchange.getResponseHeaders().set("Cache-Control", "no-cache");
            if (revalidating) {
                exchange.sendResponseHeaders(304, -1);
            } else {
                byte[] body = "hello".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "text/plain");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
            }
            exchange.close();
        });
        HttpFilters teapot = HttpFilters.builder().onResponse(res -> {
            res.setStatus(HttpResponseStatus.valueOf(418));
            return res;
        }).build();
        HttpFiltersSource teapotOnly = (request, flow) -> request.uri().endsWith("/teapot") ? teapot : null;
        // The cache first, so the script sees its answers.
        proxy = MicroProxy.bootstrap().withPort(0)
                .withFiltersSource(HttpFiltersChain.of(teapotOnly, HttpCache.builder().build(), script(TAG_SOURCE)))
                .start();
        HttpClient client = client(proxy);

        HttpResponse<String> first = get(client, url(origin, "/cached"));
        assertEquals("server", header(first, "x-source"));
        HttpResponse<String> revalidated = get(client, url(origin, "/cached"));
        assertEquals(200, revalidated.statusCode());
        assertEquals("hello", revalidated.body());
        assertEquals("cache", header(revalidated, "x-source"));
        assertEquals("304", header(revalidated, "x-upstream"), "the server said 304; the cache answered");

        HttpResponse<String> changed = get(client, url(origin, "/teapot"));
        assertEquals(418, changed.statusCode());
        assertEquals("filter", header(changed, "x-source"));
        assertEquals("200", header(changed, "x-upstream"));
    }

    @Test
    void scriptMadeResponsesAreTheFilters() throws Exception {
        StarlarkScript script = StarlarkScript.compile("""
                def made():
                    r = response(204)
                    return [r.source, r.upstream_status]
                """, "made.star", StarlarkScript.Limits.DEFAULT);
        try (Mutability mu = Mutability.create("test")) {
            assertEquals("[\"filter\", None]", Starlark.repr(script.call("made", mu), StarlarkSemantics.DEFAULT));
        }
    }

    @Test
    void timings() throws Exception {
        origin = origin(echo());
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(script("""
                def known(t):
                    return [f for f in ["dns_ms", "connect_ms", "tls_ms", "client_tls_ms", "ttfb_ms", "total_ms"]
                            if getattr(t, f) != None]

                def on_request(req, ctx):
                    ctx.vars["before"] = known(ctx.timings)

                def on_response(req, res, ctx):
                    t = ctx.timings
                    res.headers["X-Before"] = ",".join(ctx.vars["before"])
                    res.headers["X-Known"] = ",".join(known(t))
                    res.headers["X-Ttfb-Type"] = type(t.ttfb_ms)
                    res.headers["X-Ttfb-Positive"] = str(t.ttfb_ms > 0)
                """)).start();
        HttpClient client = client(proxy);
        HttpResponse<String> first = get(client, url(origin, "/1"));
        assertEquals("", header(first, "x-before"), "nothing has happened in on_request");
        assertTrue(header(first, "x-known").contains("connect_ms,"), header(first, "x-known"));
        assertTrue(header(first, "x-known").endsWith("ttfb_ms"), "no total before the response is sent");
        assertEquals("float", header(first, "x-ttfb-type"));
        assertEquals("True", header(first, "x-ttfb-positive"));

        HttpResponse<String> reused = get(client, url(origin, "/2"));
        assertEquals("ttfb_ms", header(reused, "x-known"), "a reused connection has no connect phase");
    }

    @Test
    void timingsAreReadOnly() throws Exception {
        StarlarkScript script = StarlarkScript.compile("""
                def change(ctx):
                    ctx.timings.ttfb_ms = 1.0
                """, "ro.star", StarlarkScript.Limits.DEFAULT);
        try (Mutability mu = Mutability.create("test")) {
            ScriptContext ctx = new ScriptContext(null, null, 1, false, mu);
            EvalException e = assertThrows(EvalException.class, () -> script.call("change", mu, ctx));
            assertTrue(e.getMessage().contains("timings value does not support field assignment"), e.getMessage());
        }
    }

    @Test
    void typedScriptsSeeTheNewFields() throws Exception {
        StarlarkScript.compile("""
                def on_response(req: Request, res: Response, ctx: Context) -> None:
                    source: str | None = res.source
                    upstream: int | None = res.upstream_status
                    t: Timings = ctx.timings
                    ms: float | None = t.ttfb_ms
                    if ms != None:
                        res.headers["X-Ttfb"] = str(int(cast(float, ms)))
                    if source == "server" and upstream != None:
                        res.headers["X-Upstream"] = str(upstream)
                """, "typed.star", StarlarkScript.Limits.DEFAULT);
        for (String bad : List.of(
                "def f(ctx: Context) -> float:\n    return ctx.timings.ttfb_ms\n",
                "def f(ctx: Context):\n    return ctx.timings.ttfb\n",
                "def f(res: Response) -> str:\n    return res.source\n",
                "def f(res: Response) -> int:\n    return res.upstream_status\n")) {
            assertThrows(ScriptException.class, () -> StarlarkScript.compile(bad, "typed.star", StarlarkScript.Limits.DEFAULT),
                    bad);
        }
    }

    @Test
    void webSocketFramesSeeTheUpgradeTimings() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(script("""
                def on_websocket_frame(req, frame, ctx):
                    if frame.type == "text" and frame.from_client:
                        t = ctx.timings
                        frame.text = "ping %s %s" % (t.ttfb_ms != None, t.total_ms != None)  # the origin echoes pings
                """)).start();
        try (WebSocketTestSupport.EchoServer server = new WebSocketTestSupport.EchoServer();
                var s = WebSocketTestSupport.connect(proxy, server.raw())) {
            WebSocketTestSupport.sendFromClient(s.getOutputStream(), WebSocketFrame.text("ping"));
            assertEquals("echo:ping True True", WebSocketTestSupport.readFrame(s.getInputStream()).payloadAsText());
        }
    }

    @Test
    void contextsWithoutAConnectionHaveNoTimings() throws Exception {
        try (Mutability mu = Mutability.create("test")) {
            ScriptContext ctx = new ScriptContext(null, null, -1, false, mu);
            ScriptTimings t = (ScriptTimings) ctx.getValue("timings");
            for (String field : t.getFieldNames()) {
                assertEquals(Starlark.NONE, t.getValue(field), field);
            }
        }
    }
}
