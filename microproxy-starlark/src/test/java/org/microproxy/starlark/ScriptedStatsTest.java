package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.stats.Counter;
import org.microproxy.stats.Gauge;
import org.microproxy.stats.Histogram;
import org.microproxy.stats.StatsFormatter;
import org.microproxy.stats.StatsRegistry;

/** A script's own metrics: {@code stats.counter}, {@code stats.gauge} and {@code stats.histogram}. */
class ScriptedStatsTest {

    private HttpServer origin;
    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.stop(0);
    }

    private static final String SOURCE = """
            BLOCKED = stats.counter("blocked")
            SEEN = stats.counter("requests.seen")
            IN_FLIGHT = stats.gauge("in_flight")
            SIZES = stats.histogram("path_length")

            def on_request(req, ctx):
                SEEN.inc()
                IN_FLIGHT.inc()
                SIZES.record(len(req.path))
                if req.path.startswith("/blocked"):
                    BLOCKED.inc()
                    IN_FLIGHT.dec()
                    return response(403, "no")
                stats.counter("by_name").inc(2)

            def on_response(req, res, ctx):
                IN_FLIGHT.dec()
            """;

    @Test
    void scriptStatsCountIntoTheProxysRegistryUnderScript() throws Exception {
        origin = origin(echo());
        StatsRegistry registry = StatsRegistry.create();
        ScriptedProxy script = ScriptedProxy.builder(SOURCE, "stats.star").stats(registry).build();
        proxy = MicroProxy.bootstrap().withPort(0).withStats(registry).withFiltersSource(script).start();
        HttpClient client = client(proxy);
        assertEquals(200, get(client, url(origin, "/a")).statusCode());
        assertEquals(403, get(client, url(origin, "/blocked")).statusCode());
        assertEquals(200, get(client, url(origin, "/abc")).statusCode());
        assertEquals(1, ((Counter) registry.get("script.blocked")).value());
        assertEquals(3, ((Counter) registry.get("script.requests.seen")).value());
        assertEquals(4, ((Counter) registry.get("script.by_name")).value());
        assertEquals(0, ((Gauge) registry.get("script.in_flight")).value());
        Histogram.Snapshot sizes = ((Histogram) registry.get("script.path_length")).snapshot();
        assertEquals(3, sizes.count());
        assertEquals(2 + 8 + 4, sizes.sum(), 1e-9);
        String scrape = StatsFormatter.prometheus(registry);
        assertTrue(scrape.contains("# TYPE envoy_script_blocked counter\nenvoy_script_blocked 1\n"), scrape);
        assertTrue(scrape.contains("envoy_script_requests_seen 3\n"), scrape);
        // The proxy's own stats are there too.
        assertEquals(3, ((Counter) registry.get("http.MicroProxy.downstream_rq_total")).value());
    }

    @Test
    void withoutMetricsScriptStatsCountNothing() throws Exception {
        origin = origin(echo());
        ScriptedProxy script = ScriptedProxy.builder(SOURCE, "stats.star").build();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(script).start();
        assertEquals(403, get(client(proxy), url(origin, "/blocked")).statusCode());
        assertEquals(200, get(client(proxy), url(origin, "/x")).statusCode());
    }

    @Test
    void scriptStatsAreBounded() throws Exception {
        origin = origin(echo());
        StatsRegistry registry = StatsRegistry.builder().maxScriptStats(3).build();
        ScriptedProxy script = ScriptedProxy.builder("""
                def on_request(req, ctx):
                    stats.counter("path" + req.path.replace("/", "_")).inc()
                """, "bounded.star").stats(registry).build();
        proxy = MicroProxy.bootstrap().withPort(0).withStats(registry).withFiltersSource(script).start();
        HttpClient client = client(proxy);
        for (String path : List.of("/a", "/b", "/c", "/d", "/e", "/a")) {
            assertEquals(200, get(client, url(origin, path)).statusCode(), "past the limit, requests still go on");
        }
        assertEquals(2, ((Counter) registry.get("script.path_a")).value());
        assertEquals(1, ((Counter) registry.get("script.path_c")).value());
        assertNull(registry.get("script.path_d"));
        assertNull(registry.get("script.path_e"));
        assertEquals(3, registry.metrics().stream().filter(m -> m.name().startsWith("script.")).count());
    }

    @Test
    void badNamesAndValuesAreScriptErrors() {
        StatsRegistry registry = StatsRegistry.create();
        ScriptException bad = assertThrows(ScriptException.class,
                () -> ScriptedProxy.builder("stats.counter(\"has space\")", "bad.star").stats(registry).build());
        assertTrue(bad.getMessage().contains("not a stat name"), bad.getMessage());
        ScriptException negative = assertThrows(ScriptException.class,
                () -> ScriptedProxy.builder("stats.counter(\"c\").inc(-1)", "neg.star").stats(registry).build());
        assertTrue(negative.getMessage().contains("only goes up"), negative.getMessage());
        ScriptException kind = assertThrows(ScriptException.class, () -> ScriptedProxy.builder(
                "stats.counter(\"k\")\nstats.gauge(\"k\")", "kind.star").stats(registry).build());
        assertTrue(kind.getMessage().contains("is a counter, not a gauge"), kind.getMessage());
    }

    @Test
    void theLauncherGivesScriptsTheProxysRegistry(@TempDir Path dir) throws Exception {
        origin = origin(echo());
        Path file = dir.resolve("count.star");
        Files.writeString(file, """
                def on_request(req, ctx):
                    stats.counter("launched").inc()
                """);
        HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap().withPort(0).withMetrics(true);
        StarlarkLauncherExtension extension = new StarlarkLauncherExtension();
        assertTrue(extension.parseOption("--script", new java.util.ArrayDeque<>(List.of(file.toString()))));
        extension.configure(bootstrap, new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
        proxy = bootstrap.start();
        assertEquals(200, get(client(proxy), url(origin, "/")).statusCode());
        assertEquals(1, ((Counter) proxy.getStats().get("script.launched")).value());
    }
}
