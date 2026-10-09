package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.readUntil;
import static org.microproxy.TestSupport.url;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.UnknownHostException;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpFilters;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;

/**
 * The README's examples for {@code on_failure}, {@code authenticate}, constants and timings, run
 * as written: each script is checked to appear verbatim in the README.
 */
public class ScriptedReadmeTest {

    static final String TIMINGS = """
            def on_response(req, res, ctx):
                t = ctx.timings
                if t.ttfb_ms == None:
                    return None
                if t.ttfb_ms > 1000:
                    log.warn("%s: first byte after %d ms (dns %s, connect %s, tls %s), %s from the %s" % (
                        req.url, t.ttfb_ms, t.dns_ms, t.connect_ms, t.tls_ms, res.upstream_status, res.source))
                res.headers["Server-Timing"] = "upstream;dur=%d" % t.ttfb_ms
                return None
            """;

    static final String FAILURES = """
            def on_failure(req, failure, ctx):
                if failure.kind in ["unresolved_host", "connect_failed"]:
                    return response(502, "%s is unreachable: %s\\n" % (failure.host, failure.message),
                                    headers={"Retry-After": "30"})
                if failure.kind == "server_timeout":
                    return response(504, json.encode({"error": "timeout", "host": failure.host}),
                                    content_type="application/json")
                return None  # the FailureResponder's answer, or the proxy's default
            """;

    /** Also run from the command line by {@code LauncherScriptTest}. */
    public static final String BEARER = """
            # TOKENS = "alice:<sha256 of alice's token>,bob:<sha256 of bob's token>", from --script-var(-file)
            USERS = [entry.split(":") for entry in TOKENS.split(",")]

            def authenticate(req, ctx):
                value = req.headers.get("Proxy-Authorization", "")
                if value.startswith("Bearer "):
                    presented = digest.sha256(value[len("Bearer "):].strip())
                    for user, expected in USERS:
                        if digest.equal(presented, expected):
                            return user
                return response(407, "a valid token is required\\n",
                                headers={"Proxy-Authenticate": 'Bearer realm="proxy"'})
            """;

    private HttpProxyServer proxy;
    private HttpServer origin;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.stop(0);
    }

    /** Fails unless the README shows {@code example} as it is. */
    public static String inReadme(String example) throws IOException {
        Path readme = Path.of("README.md");
        if (!Files.exists(readme)) readme = Path.of("..", "README.md");
        String text = Files.readString(readme, StandardCharsets.UTF_8);
        assertTrue(text.contains(example), "README.md does not show this example as tested:\n" + example);
        return example;
    }

    public static String sha256(String s) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void timingsExample() throws Exception {
        List<String> warnings = new CopyOnWriteArrayList<>();
        Logger logger = Logger.getLogger("microproxy.script");
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
                    warnings.add(java.text.MessageFormat.format(record.getMessage(), record.getParameters()));
                }
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        };
        logger.addHandler(handler);
        try {
            origin = origin(exchange -> {
                if (exchange.getRequestURI().getPath().equals("/slow")) {
                    try {
                        Thread.sleep(1_100);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                echo().handle(exchange);
            });
            proxy = MicroProxy.bootstrap().withPort(0)
                    .withFiltersSource(ScriptedProxy.builder(inReadme(TIMINGS), "timings.star").build()).start();
            HttpResponse<String> fast = get(client(proxy), url(origin, "/fast"));
            assertTrue(fast.headers().firstValue("server-timing").orElseThrow().matches("upstream;dur=\\d+"),
                    fast.headers().toString());
            assertTrue(warnings.isEmpty(), warnings.toString());

            get(client(proxy), url(origin, "/slow"));
            assertEquals(1, warnings.size(), warnings.toString());
            assertTrue(warnings.getFirst().contains(url(origin, "/slow") + ": first byte after 1"), warnings.toString());
            assertTrue(warnings.getFirst().endsWith(", 200 from the server"), warnings.toString());
        } finally {
            logger.removeHandler(handler);
        }
    }

    private void startFailures(HttpProxyServerBootstrap bootstrap) throws Exception {
        ScriptedProxy script = ScriptedProxy.builder(inReadme(FAILURES), "failures.star").build();
        proxy = bootstrap.withPort(0).withFiltersSource(script).withChainProxyManager(script).start();
    }

    @Test
    void failureExampleUnreachable() throws Exception {
        int port;
        try (ServerSocket s = new ServerSocket(0, 1, TestSupport.LOOPBACK)) {
            port = s.getLocalPort();
        }
        startFailures(MicroProxy.bootstrap());
        HttpResponse<String> refused = get(client(proxy), "http://127.0.0.1:" + port + "/");
        assertEquals(502, refused.statusCode());
        assertTrue(refused.body().startsWith("127.0.0.1 is unreachable: "), refused.body());
        assertEquals("30", refused.headers().firstValue("retry-after").orElseThrow());

        proxy.abort();
        startFailures(MicroProxy.bootstrap().withServerResolver((host, p) -> {
            throw new UnknownHostException(host + ": Name or service not known");
        }));
        HttpResponse<String> unresolved = get(client(proxy), "http://nowhere.test/");
        assertEquals("nowhere.test is unreachable: nowhere.test: Name or service not known\n", unresolved.body());
    }

    @Test
    void failureExampleTimeoutAndDefault() throws Exception {
        try (TestSupport.RawServer server = TestSupport.rawServer(s -> {
            String head = readUntil(s.getInputStream(), "\r\n\r\n");
            if (head.startsWith("GET /garbage")) {
                write(s.getOutputStream(), "not HTTP\r\n\r\n");
            } else {
                Thread.sleep(5_000);
            }
        })) {
            startFailures(MicroProxy.bootstrap().withIdleConnectionTimeout(Duration.ofMillis(300)));
            HttpResponse<String> timeout = get(client(proxy), "http://127.0.0.1:" + server.port() + "/slow");
            assertEquals(504, timeout.statusCode());
            assertEquals("application/json", timeout.headers().firstValue("content-type").orElseThrow());
            assertEquals("{\"error\":\"timeout\",\"host\":\"127.0.0.1\"}", timeout.body());

            HttpResponse<String> garbage = get(client(proxy), "http://127.0.0.1:" + server.port() + "/garbage");
            assertEquals(502, garbage.statusCode());
            assertEquals("Bad Gateway", garbage.body().strip(), "the proxy's default");
        }
    }

    @Test
    void bearerTokenExample() throws Exception {
        origin = origin(echo());
        String tokens = "alice:" + sha256("alice-token") + ",bob:" + sha256("bob-token");
        // As in the README's Java snippet: constants, then the script as authenticator too.
        ScriptedProxy script = ScriptedProxy.builder(inReadme(BEARER), "auth.star")
                .constants(Map.of("TOKENS", tokens, "MAX_BODY", 1 << 20, "ALLOWED", List.of("example.com", "example.org")))
                .build();
        List<String> users = new CopyOnWriteArrayList<>();
        HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap().withPort(0).withFiltersSource(script)
                .withChainProxyManager(script);
        if (script.definesAuthenticate()) bootstrap.withProxyAuthenticator(script);
        proxy = bootstrap.plusFiltersSource((request, flow) -> {
            users.add(String.valueOf(flow.getClientDetails().getUserName()));
            return HttpFilters.builder().build();
        }).start();

        for (String token : List.of("alice-token", "bob-token")) {
            try (RawHttp http = new RawHttp(proxy.getListenAddress())) {
                assertEquals(200, http.send("GET", url(origin, "/"), "Proxy-Authorization: Bearer " + token).status());
            }
        }
        assertEquals(List.of("alice", "bob"), users);
        for (String header : List.of("Proxy-Authorization: Bearer mallory-token", "Proxy-Authorization: Basic YTpi",
                "X-None: 1")) {
            try (RawHttp http = new RawHttp(proxy.getListenAddress())) {
                RawHttp.Response r = http.send("GET", url(origin, "/"), header);
                assertEquals(407, r.status(), header);
                assertEquals("Bearer realm=\"proxy\"", r.header("proxy-authenticate"));
                assertEquals("a valid token is required\n", r.body());
            }
        }
    }
}
