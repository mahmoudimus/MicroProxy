package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;

class ScriptedProxyTest {

    private HttpServer origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() {
        origin = origin(echo());
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private void start(ScriptedProxy script) {
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(script).withChainProxyManager(script).start();
    }

    private void start(String source) throws Exception {
        start(ScriptedProxy.builder(source, "test.star").build());
    }

    @Test
    void onRequestCanAnswerDirectly() throws Exception {
        start("""
                def on_request(req, ctx):
                    if req.path == "/blocked":
                        return response(403, "blocked " + req.host, headers={"X-Why": "policy"})
                """);
        HttpResponse<String> blocked = get(client(proxy), url(origin, "/blocked?x=1"));
        assertEquals(403, blocked.statusCode());
        assertEquals("blocked 127.0.0.1", blocked.body());
        assertEquals("policy", blocked.headers().firstValue("x-why").orElseThrow());
        assertEquals(200, get(client(proxy), url(origin, "/open")).statusCode());
    }

    @Test
    void onRequestRewritesHeadersAndTarget() throws Exception {
        start("""
                def on_request(req, ctx):
                    req.headers["X-Script"] = req.method + " " + req.path + "?" + req.query
                    req.headers.remove("X-Secret")
                    req.uri = req.uri.replace("/old/", "/new/")
                """);
        HttpResponse<String> response = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/old/a?q=1")))
                .header("X-Secret", "s3cret").build());
        assertEquals("/new/a?q=1", echoedUri(response.body()));
        assertEquals(List.of("GET /old/a?q=1"), echoedHeader(response.body(), "x-script"));
        assertEquals(List.of(), echoedHeader(response.body(), "x-secret"));
    }

    @Test
    void onResponseRewritesBufferedBodiesAndSeesRequestVars() throws Exception {
        start("""
                def on_request(req, ctx):
                    ctx.vars["seen"] = req.url

                def on_response(req, res, ctx):
                    res.headers["X-Seen"] = ctx.vars["seen"]
                    res.text = res.text.upper()
                    res.status = 299
                """);
        String target = url(origin, "/lower");
        HttpResponse<String> response = get(client(proxy), target);
        assertEquals(299, response.statusCode());
        assertTrue(response.body().startsWith("METHOD: GET"), response.body());
        assertEquals(target, response.headers().firstValue("x-seen").orElseThrow());
    }

    @Test
    void onResponseCanReplaceTheResponse() throws Exception {
        start("""
                def on_response(req, res, ctx):
                    return response(410, json.encode({"was": res.status}), content_type="application/json")
                """);
        HttpResponse<String> response = get(client(proxy), url(origin, "/x"));
        assertEquals(410, response.statusCode());
        assertEquals("{\"was\":200}", response.body());
    }

    @Test
    void bufferRequestExposesRequestBodies() throws Exception {
        start("""
                def buffer_request(req, ctx):
                    return req.method == "POST"

                def on_request(req, ctx):
                    if req.body != None:
                        req.text = req.text.upper() + " (" + str(len(req.body)) + ")"
                """);
        HttpResponse<String> response = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/p")))
                .POST(HttpRequest.BodyPublishers.ofString("shout")).build());
        assertEquals("SHOUT (5)", echoedBody(response.body()));
    }

    @Test
    void upstreamChoosesTheRoute() throws Exception {
        start("""
                def upstream(req, ctx):
                    if req.path == "/dead":
                        return "http://127.0.0.1:1"
                    if req.path == "/retry":
                        return ["http://127.0.0.1:1", "DIRECT"]
                    return None
                """);
        assertEquals(200, get(client(proxy), url(origin, "/ok")).statusCode());
        assertEquals(502, get(client(proxy), url(origin, "/dead")).statusCode());
        assertEquals(200, get(client(proxy), url(origin, "/retry")).statusCode());
    }

    @Test
    void failingHooksAnswer500AndDoNotLeakDetails() throws Exception {
        start("""
                def on_request(req, ctx):
                    if req.path == "/boom":
                        x = {}["missing secret key"]
                """);
        HttpResponse<String> response = get(client(proxy), url(origin, "/boom"));
        assertEquals(500, response.statusCode());
        assertTrue(!response.body().contains("secret"), response.body());
        assertEquals(200, get(client(proxy), url(origin, "/fine")).statusCode());
    }

    @Test
    void runawayScriptsAreStopped() throws Exception {
        start(ScriptedProxy.builder("""
                def on_request(req, ctx):
                    n = 0
                    for i in range(1000000000):
                        n += i
                """, "loop.star").limits(new StarlarkScript.Limits(100_000, Duration.ofSeconds(30))).build());
        assertEquals(500, get(client(proxy), url(origin, "/")).statusCode());
    }

    @Test
    void scriptFilesReloadWhenChanged(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("proxy.star");
        Files.writeString(file, "def on_request(req, ctx):\n    req.headers['X-Version'] = '1'\n");
        start(ScriptedProxy.builder(file).build());
        assertEquals(List.of("1"), echoedHeader(get(client(proxy), url(origin, "/")).body(), "x-version"));

        Files.writeString(file, "def on_request(req, ctx):\n    req.headers['X-Version'] = '2'\n");
        Files.setLastModifiedTime(file, FileTime.from(Instant.now().plusSeconds(5)));
        assertEquals("2", awaitVersion());

        // A broken edit keeps the last good version.
        Files.writeString(file, "def on_request(req, ctx)\n");
        Files.setLastModifiedTime(file, FileTime.from(Instant.now().plusSeconds(10)));
        Thread.sleep(1_100);
        assertEquals(List.of("2"), echoedHeader(get(client(proxy), url(origin, "/")).body(), "x-version"));
    }

    private String awaitVersion() throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        List<String> seen = List.of();
        while (System.nanoTime() < deadline) {
            seen = echoedHeader(get(client(proxy), url(origin, "/")).body(), "x-version");
            if (seen.equals(List.of("2"))) return "2";
            Thread.sleep(100);
        }
        return seen.toString();
    }

    @Test
    void brokenScriptsFailAtStartup(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("bad.star");
        Files.writeString(file, "def on_request(req ctx):\n    pass\n");
        ScriptException e = assertThrows(ScriptException.class, () -> ScriptedProxy.builder(file).build());
        assertTrue(e.getMessage().contains("bad.star:1"), e.getMessage());
    }

    @Test
    void readOnlyFieldsAndBadValuesAreScriptErrors() throws Exception {
        start("""
                def on_request(req, ctx):
                    if req.path == "/host":
                        req.host = "evil"
                    if req.path == "/inject":
                        req.headers["X-A"] = "a\\r\\nX-B: b"
                """);
        assertEquals(500, get(client(proxy), url(origin, "/host")).statusCode());
        assertEquals(500, get(client(proxy), url(origin, "/inject")).statusCode());
    }
}
