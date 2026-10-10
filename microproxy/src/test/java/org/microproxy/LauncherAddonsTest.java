package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.extras.AntiCache;
import org.microproxy.extras.BlockList;
import org.microproxy.extras.HarRecorder;
import org.microproxy.extras.MapLocal;
import org.microproxy.extras.MapRemote;
import org.microproxy.extras.ModifyBody;
import org.microproxy.extras.ModifyHeaders;
import org.microproxy.extras.RecordedExchange;
import org.microproxy.extras.ServerReplay;
import org.microproxy.extras.StickyCookie;
import org.microproxy.impl.BootstrapView;

/** The addon, HAR and replay flags of the {@link Launcher}. */
class LauncherAddonsTest {

    @TempDir
    Path dir;
    private final ByteArrayOutputStream console = new ByteArrayOutputStream();
    private final List<HttpProxyServer> servers = new ArrayList<>();
    private final List<AutoCloseable> closeables = new ArrayList<>();
    private HttpServer origin;
    private final AtomicInteger hits = new AtomicInteger();

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(exchange -> {
            hits.incrementAndGet();
            echo().handle(exchange);
        });
    }

    @AfterEach
    void tearDown() throws Exception {
        servers.forEach(HttpProxyServer::abort);
        for (AutoCloseable c : closeables) c.close();
        origin.stop(0);
    }

    private PrintStream out() {
        return new PrintStream(console, true, StandardCharsets.UTF_8);
    }

    private Launcher.Parsed parse(String... args) throws IOException {
        Launcher.Parsed parsed = Launcher.parse(args, out());
        if (parsed != null) closeables.addAll(parsed.resources());
        return parsed;
    }

    private HttpProxyServer launch(String... args) throws IOException {
        HttpProxyServer server = Launcher.start(args, out());
        servers.add(server);
        return server;
    }

    private List<Class<?>> chain(Launcher.Parsed parsed) {
        HttpFiltersSource source = BootstrapView.of(parsed.bootstrap()).filtersSource();
        List<HttpFiltersSource> sources = source instanceof HttpFiltersChain c ? c.sources() : List.of(source);
        return sources.stream().<Class<?>>map(Object::getClass).toList();
    }

    @Test
    void helpListsTheAddonFlags() throws IOException {
        assertNull(Launcher.parse(new String[] {"--help"}, out()));
        String usage = console.toString(StandardCharsets.UTF_8);
        for (String flag : List.of("--map-local", "--map-remote", "--modify-body", "--modify-headers", "--block-list",
                "--anticache", "--stickycookie", "--save-har", "--save-har-filter", "--save-har-stream",
                "--save-har-max-body", "--server-replay", "--server-replay-reuse", "--server-replay-extra",
                "--server-replay-kill-extra", "--server-replay-no-refresh", "--server-replay-ignore-content",
                "--server-replay-ignore-host", "--server-replay-ignore-port", "--server-replay-ignore-params",
                "--server-replay-ignore-payload-params", "--server-replay-use-headers", "--client-replay",
                "--client-replay-concurrency", "--keepserving")) {
            assertTrue(usage.contains(flag + " "), "usage lacks " + flag);
        }
    }

    @Test
    void addonsAreInstalledInMitmproxysOrder() throws IOException {
        Path har = dir.resolve("a.har");
        Path recorded = dir.resolve("r.har");
        Files.writeString(recorded, "{\"log\":{\"version\":\"1.2\",\"entries\":[]}}");
        Launcher.Parsed parsed = parse("--port", "0", "--save-har", har.toString(),
                "--map-local", "|/x|" + dir, "--map-remote", "|a|b", "--modify-body", "|a|b",
                "--modify-headers", "|X-A|1", "--block-list", "|~d ads|404", "--anticache", "--stickycookie", "~all",
                "--server-replay", recorded.toString(), "--server-replay-reuse", "--server-replay-ignore-params", "a,b");
        assertEquals(List.of(HarRecorder.class, BlockList.class, AntiCache.class, ServerReplay.class, MapRemote.class,
                MapLocal.class, ModifyBody.class, ModifyHeaders.class, StickyCookie.class), chain(parsed));
        assertInstanceOf(HarRecorder.class, parsed.resources().getFirst());
    }

    @Test
    void invalidSpecsAndLoneOptionsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> parse("--map-remote", "|only-one-part"));
        assertThrows(IllegalArgumentException.class, () -> parse("--block-list", "|~nope x|404"));
        assertThrows(IllegalArgumentException.class, () -> parse("--map-local", "|x|/no/such/dir/at/all"));
        assertThrows(IllegalArgumentException.class, () -> parse("--server-replay-reuse"));
        assertThrows(IllegalArgumentException.class, () -> parse("--save-har-stream"));
        assertThrows(IllegalArgumentException.class, () -> parse("--keepserving"));
        assertThrows(IllegalArgumentException.class, () -> parse("--client-replay-concurrency", "0"));
        assertThrows(IllegalArgumentException.class, () -> parse("--stickycookie", "~u ("));
    }

    @Test
    void addonFlagsWorkEndToEnd() throws IOException {
        HttpProxyServer proxy = launch("--port", "0", "--map-remote", "|/old/|/new/",
                "--modify-headers", "|~q|X-Flag|on", "--block-list", "|~u /ads|403");
        HttpClient client = client(proxy);
        HttpResponse<String> moved = get(client, url(origin, "/old/page"));
        assertEquals("/new/page", echoedUri(moved.body()));
        assertEquals(List.of("on"), echoedHeader(moved.body(), "X-Flag"));
        assertEquals(403, get(client, url(origin, "/ads")).statusCode());
    }

    @Test
    void saveHarThenServerReplayThenClientReplay() throws Exception {
        Path har = dir.resolve("flows.har");
        HttpProxyServer recording = launch("--port", "0", "--save-har", har.toString());
        assertEquals(200, get(client(recording), url(origin, "/recorded?q=1")).statusCode());
        recording.stop();
        assertEquals(1, RecordedExchange.load(har).size(), "written when the server stopped");
        assertEquals(1, hits.get());

        HttpProxyServer replaying = launch("--port", "0", "--server-replay", har.toString(),
                "--server-replay-extra", "404");
        HttpClient client = client(replaying);
        assertEquals("/recorded?q=1", echoedUri(get(client, url(origin, "/recorded?q=1")).body()));
        assertEquals(404, get(client, url(origin, "/recorded?q=1")).statusCode(), "used up");
        assertEquals(1, hits.get(), "no server was contacted");
        assertTrue(console.toString(StandardCharsets.UTF_8).contains("Replaying 1 recorded responses"));

        HttpProxyServer replayed = launch("--port", "0", "--client-replay", har.toString());
        assertEquals(2, hits.get(), "the recorded request was sent again");
        assertTrue(console.toString(StandardCharsets.UTF_8).contains("Client replay done: 1 sent, 0 failed"));
        assertThrows(java.io.UncheckedIOException.class, () -> get(client(replayed), url(origin, "/after")),
                "the proxy stopped after replaying");

        HttpProxyServer kept = launch("--port", "0", "--client-replay", har.toString(), "--keepserving",
                "--client-replay-concurrency", "2");
        assertEquals(3, hits.get());
        assertEquals(200, get(client(kept), url(origin, "/after")).statusCode(), "still serving");
    }
}
