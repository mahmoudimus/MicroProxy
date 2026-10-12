package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.extras.AccessLogFormat;
import org.microproxy.extras.ActivityLogger;
import org.microproxy.stats.Counter;
import org.microproxy.stats.StatsRegistry;

/** Budgets, exchange totals and the observer with a running proxy. */
class ScriptedBudgetTest {

    private HttpServer origin;
    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.stop(0);
    }

    private static final String SOURCE = """
            def on_request(req, ctx):
                if req.path == "/hog":
                    s = "x"
                    for i in range(40):
                        s = s + s
                ctx.vars["seen"] = [i for i in range(100)]

            def on_response(req, res, ctx):
                res.headers["X-Script-Calls"] = str(ctx.script_stats.calls)
                res.headers["X-Script-Steps"] = str(ctx.script_stats.steps)
            """;

    /** The access-log lines {@code sink} has, once it has {@code count}. */
    private static List<String> await(List<String> sink, int count) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (sink.size() < count && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        assertEquals(count, sink.size(), "access log: " + sink);
        return sink;
    }

    @Test
    void anExchangesScriptTotalsReachItsAccessLogAndTheScript() throws Exception {
        origin = origin(echo());
        List<String> log = new CopyOnWriteArrayList<>();
        ScriptedProxy script = ScriptedProxy.builder(SOURCE, "totals.star").build();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(script)
                .plusActivityTracker(new ActivityLogger(AccessLogFormat.envoy(
                        "%MP_SCRIPT_CALLS% %MP_SCRIPT_STEPS% %MP_SCRIPT_ALLOC% %MP_SCRIPT_TIME%"), log::add))
                .start();
        HttpClient client = client(proxy);
        HttpResponse<String> first = get(client, url(origin, "/a"));
        assertEquals(200, first.statusCode());
        // on_response sees what on_request added up to.
        assertEquals("1", first.headers().firstValue("x-script-calls").orElseThrow());
        assertTrue(Long.parseLong(first.headers().firstValue("x-script-steps").orElseThrow()) > 100);
        get(client, url(origin, "/b"));
        for (String line : await(log, 2)) {
            String[] f = line.strip().split(" ");
            assertEquals("2", f[0], line);
            assertTrue(Long.parseLong(f[1]) > 100, line);
            assertTrue(Long.parseLong(f[2]) > 0, line);
            assertTrue(f[3].matches("\\d+\\.\\d{3}"), line);
        }
    }

    @Test
    void aHookPastItsMemoryBudgetFailsAsAFailingHookDoes() throws Exception {
        origin = origin(echo());
        StatsRegistry registry = StatsRegistry.create();
        ScriptedProxy script = ScriptedProxy.builder(SOURCE, "hog.star").stats(registry)
                .limits(StarlarkScript.Limits.DEFAULT.withMaxAllocBytes(1 << 20)).build();
        proxy = MicroProxy.bootstrap().withPort(0).withStats(registry).withFiltersSource(script).start();
        HttpClient client = client(proxy);
        HttpResponse<String> hog = get(client, url(origin, "/hog"));
        assertEquals(500, hog.statusCode());
        assertEquals("Proxy script error\n", hog.body());
        assertEquals(200, get(client, url(origin, "/fine")).statusCode());
        assertEquals(1, ((Counter) registry.get("hooks.starlark.hog.on_request.budget_exceeded.memory")).value());
        assertEquals(1, ((Counter) registry.get("hooks.starlark.hog.on_request.errors")).value());
        assertEquals(2, ((Counter) registry.get("hooks.starlark.hog.on_request.invocations")).value());
    }

    @Test
    void theLauncherPassesItsBudgetsNameAndObserverToTheScript(@TempDir Path dir) throws Exception {
        origin = origin(echo());
        Path file = dir.resolve("launched.star");
        Files.writeString(file, SOURCE, StandardCharsets.UTF_8);
        ScriptBudgetTest.Recorder recorder = new ScriptBudgetTest.Recorder();
        StatsRegistry registry = StatsRegistry.create();
        HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap().withPort(0).withStats(registry)
                .withScriptCallObserver(recorder);
        StarlarkLauncherExtension extension = new StarlarkLauncherExtension();
        ArrayDeque<String> args = new ArrayDeque<>(List.of(file.toString(), "edge", "1m", "2s", "500000"));
        assertTrue(extension.parseOption("--script", args));
        assertTrue(extension.parseOption("--script-name", args));
        assertTrue(extension.parseOption("--script-max-alloc", args));
        assertTrue(extension.parseOption("--script-max-time", args));
        assertTrue(extension.parseOption("--script-max-steps", args));
        assertFalse(extension.parseOption("--not-a-script-option", args));
        extension.configure(bootstrap, new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8));
        proxy = bootstrap.start();
        HttpClient client = client(proxy);
        assertEquals(200, get(client, url(origin, "/a")).statusCode());
        assertEquals(500, get(client, url(origin, "/hog")).statusCode(), "1 MiB is too little for the hog");
        assertEquals(1, ((Counter) registry.get("hooks.starlark.edge.on_request.budget_exceeded.memory")).value());
        ScriptBudgetTest.Call call = recorder.calls.stream().filter(c -> c.hook().equals("on_request")).findFirst()
                .orElseThrow();
        assertEquals("edge", call.script());
        assertNotNull(call.flow(), "an HTTP hook's call has its exchange");
        assertTrue(recorder.calls.stream().anyMatch(c -> "memory".equals(c.budget())), recorder.calls.toString());
    }
}
