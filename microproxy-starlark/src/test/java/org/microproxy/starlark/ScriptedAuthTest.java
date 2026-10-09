package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
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
import org.microproxy.TestSupport;

/** The {@code authenticate} hook, with the script installed as the proxy authenticator. */
class ScriptedAuthTest {

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
        assertTrue(script.definesAuthenticate());
        proxy = MicroProxy.bootstrap().withPort(0)
                .withFiltersSource(script).withChainProxyManager(script).withProxyAuthenticator(script).start();
    }

    private void start(String source) throws Exception {
        start(ScriptedProxy.builder(source, "auth.star").build());
    }

    private RawHttp.Response get(String path, String... headers) throws Exception {
        try (RawHttp http = new RawHttp(proxy.getListenAddress())) {
            return http.send("GET", url(origin, path), headers);
        }
    }

    private static final String BEARER = """
            def authenticate(req, ctx):
                value = req.headers.get("Proxy-Authorization", "")
                if value == "Bearer good":
                    return "alice"
                if value == "Bearer anonymous":
                    return True
                if value == "Bearer forbidden":
                    return response(403, "not for you\\n")
                if value == "Bearer none":
                    return None
                if value.startswith("Bearer "):
                    return response(407, "invalid token\\n",
                                    headers={"Proxy-Authenticate": 'Bearer realm="proxy", error="invalid_token"'})
                return False

            def on_request(req, ctx):
                req.headers["X-User"] = str(ctx.user)
                req.headers["X-Saw-Credentials"] = str("Proxy-Authorization" in req.headers)
            """;

    @Test
    void acceptedUsersReachTheOtherHooksAndCredentialsAreNotForwarded() throws Exception {
        start(BEARER);
        RawHttp.Response alice = get("/a", "Proxy-Authorization: Bearer good", "Connection: close");
        assertEquals(200, alice.status());
        assertEquals(List.of("alice"), echoedHeader(alice.body(), "x-user"));
        assertEquals(List.of("False"), echoedHeader(alice.body(), "x-saw-credentials"));
        assertEquals(List.of(), echoedHeader(alice.body(), "proxy-authorization"));

        RawHttp.Response anonymous = get("/a", "Proxy-Authorization: Bearer anonymous", "Connection: close");
        assertEquals(200, anonymous.status());
        assertEquals(List.of("None"), echoedHeader(anonymous.body(), "x-user"));
    }

    @Test
    void rejections() throws Exception {
        start(BEARER);
        RawHttp.Response missing = get("/", "Connection: close");
        assertEquals(407, missing.status());
        assertTrue(missing.header("proxy-authenticate").startsWith("Basic"), missing.headers().toString());

        RawHttp.Response none = get("/", "Proxy-Authorization: Bearer none", "Connection: close");
        assertEquals(407, none.status());

        RawHttp.Response invalid = get("/", "Proxy-Authorization: Bearer bad", "Connection: close");
        assertEquals(407, invalid.status());
        assertEquals("Bearer realm=\"proxy\", error=\"invalid_token\"", invalid.header("proxy-authenticate"));
        assertEquals("invalid token\n", invalid.body());

        RawHttp.Response forbidden = get("/", "Proxy-Authorization: Bearer forbidden", "Connection: close");
        assertEquals(403, forbidden.status());
        assertEquals("not for you\n", forbidden.body());
    }

    @Test
    void failuresRejectTheRequest() throws Exception {
        start(ScriptedProxy.builder("""
                def authenticate(req, ctx):
                    if req.path == "/boom":
                        fail("boom")
                    if req.path == "/number":
                        return 42
                    if req.path == "/empty":
                        return ""
                    if req.path == "/loop":
                        n = 0
                        for i in range(1000000000):
                            n += i
                    return "ok"
                """, "closed.star").limits(new StarlarkScript.Limits(100_000, Duration.ofSeconds(30))).build());
        for (String path : List.of("/boom", "/number", "/empty", "/loop")) {
            RawHttp.Response r = get(path, "Connection: close");
            assertEquals(407, r.status(), path);
            assertTrue(r.header("proxy-authenticate").startsWith("Basic"), path);
        }
        assertEquals(200, get("/fine", "Connection: close").status());
    }

    @Test
    void oncePerConnectionByDefault() throws Exception {
        start(BEARER);
        try (RawHttp http = new RawHttp(proxy.getListenAddress())) {
            assertEquals(200, http.send("GET", url(origin, "/1"), "Proxy-Authorization: Bearer good").status());
            RawHttp.Response second = http.send("GET", url(origin, "/2"));
            assertEquals(200, second.status());
            assertEquals(List.of("alice"), echoedHeader(second.body(), "x-user"));
        }
    }

    @Test
    void everyRequestWhenTheScriptSaysSo() throws Exception {
        start("""
                AUTHENTICATE_EVERY_REQUEST = True

                def authenticate(req, ctx):
                    value = req.headers.get("Proxy-Authorization", "")
                    if value.startswith("Bearer "):
                        # ctx.user is whoever this connection authenticated as before, if anyone.
                        return value[len("Bearer "):] + " after " + str(ctx.user)
                    return False

                def on_request(req, ctx):
                    req.headers["X-User"] = str(ctx.user)
                """);
        try (RawHttp http = new RawHttp(proxy.getListenAddress())) {
            RawHttp.Response first = http.send("GET", url(origin, "/1"), "Proxy-Authorization: Bearer alice");
            assertEquals(List.of("alice after None"), echoedHeader(first.body(), "x-user"));
            RawHttp.Response second = http.send("GET", url(origin, "/2"), "Proxy-Authorization: Bearer bob");
            assertEquals(List.of("bob after alice after None"), echoedHeader(second.body(), "x-user"));
            assertEquals(407, http.send("GET", url(origin, "/3")).status());
        }
    }

    @Test
    void connectIsAuthenticated() throws Exception {
        start(BEARER);
        String target = "127.0.0.1:" + origin.getAddress().getPort();
        try (RawHttp http = new RawHttp(proxy.getListenAddress())) {
            assertEquals(407, http.send("CONNECT", target, "Proxy-Authorization: Bearer bad").status());
        }
        try (RawHttp http = new RawHttp(proxy.getListenAddress())) {
            assertEquals(200, http.send("CONNECT", target, "Proxy-Authorization: Bearer good").status());
            // Through the tunnel, straight to the origin.
            TestSupport.write(http.socket.getOutputStream(), "GET /tunnelled HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
            RawHttp.Response inside = RawHttp.read(http.socket.getInputStream(), false);
            assertEquals(200, inside.status());
            assertTrue(inside.body().contains("uri: /tunnelled"), inside.body());
        }
    }

    @Test
    void theContextComesFromTheConnection() throws Exception {
        start("""
                def authenticate(req, ctx):
                    ctx.vars["seen"] = True
                    return response(403, "%s %s %s %s %s" % (
                        ctx.client_ip, ctx.connection_id > 0, ctx.tls, ctx.user, ctx.vars["seen"]))
                """);
        assertEquals("127.0.0.1 True False None True", get("/", "Connection: close").body());
    }

    @Test
    void theRequestIsReadOnly() throws Exception {
        start("""
                def authenticate(req, ctx):
                    req.headers["X-Injected"] = "1"
                    return "alice"
                """);
        assertEquals(407, get("/", "Connection: close").status());
    }

    @Test
    void reloadsApplyToAuthentication(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("auth.star");
        Files.writeString(file, "def authenticate(req, ctx):\n    return req.path == '/one'\n");
        start(ScriptedProxy.builder(file).build());
        assertEquals(200, get("/one", "Connection: close").status());
        assertEquals(407, get("/two", "Connection: close").status());

        Files.writeString(file, "def authenticate(req, ctx):\n    return req.path == '/two'\n");
        Files.setLastModifiedTime(file, FileTime.from(Instant.now().plusSeconds(5)));
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (get("/two", "Connection: close").status() != 200 && System.nanoTime() < deadline) {
            Thread.sleep(100);
        }
        assertEquals(200, get("/two", "Connection: close").status());
        assertEquals(407, get("/one", "Connection: close").status());

        // A version without authenticate() rejects everyone rather than letting everyone in.
        Files.writeString(file, "def on_request(req, ctx):\n    pass\n");
        Files.setLastModifiedTime(file, FileTime.from(Instant.now().plusSeconds(10)));
        deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (get("/two", "Connection: close").status() != 407 && System.nanoTime() < deadline) {
            Thread.sleep(100);
        }
        assertEquals(407, get("/two", "Connection: close").status());
    }
}
