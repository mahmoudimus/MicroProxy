package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.readUntil;
import static org.microproxy.TestSupport.send;

import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.FailureResponder;
import org.microproxy.HttpProxyServer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.MicroProxy;
import org.microproxy.ProxyFailure;
import org.microproxy.TestSupport;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/** The {@code on_failure} hook: answers to the proxy's own failures, and falling through. */
class ScriptedFailureTest {

    private HttpProxyServer proxy;
    private final List<ProxyFailure> responderSaw = new CopyOnWriteArrayList<>();

    /** A Java responder behind the script: answers 599 with the failure's class. */
    private final FailureResponder responder = (request, failure) -> {
        responderSaw.add(failure);
        return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, new HttpResponseStatus(599, "Java"),
                "java " + failure.getClass().getSimpleName());
    };

    @AfterEach
    void tearDown() throws IOException {
        if (proxy != null) proxy.abort();
        for (Socket s : refusing) s.close();
    }

    private HttpProxyServer start(String source, HttpProxyServerBootstrap bootstrap) throws Exception {
        ScriptedProxy script = ScriptedProxy.builder(source, "failure.star").build();
        proxy = bootstrap.withPort(0).withFiltersSource(script).withChainProxyManager(script).start();
        return proxy;
    }

    /** Reserved until the test ends, so the proxy started afterwards cannot be given the same port. */
    private final List<Socket> refusing = new ArrayList<>();

    private int closedPort() {
        Socket s = TestSupport.refusingPort();
        refusing.add(s);
        return s.getLocalPort();
    }

    private static final String DESCRIBE = """
            def on_failure(req, failure, ctx):
                return response(failure.status + 1, "%s %s %d %s for %s" % (
                    failure.kind, failure.host, failure.status, failure.message, req.url))
            """;

    @Test
    void unresolvedHost() throws Exception {
        start(DESCRIBE, MicroProxy.bootstrap().withServerResolver((host, port) -> {
            throw new UnknownHostException(host);
        }));
        HttpResponse<String> response = get(client(proxy), "http://Nowhere.test/x");
        assertEquals(503, response.statusCode());
        // host is lower-cased like req.host; message is the cause's, as the resolver wrote it.
        assertEquals("unresolved_host nowhere.test 502 Nowhere.test for http://Nowhere.test/x", response.body());
    }

    @Test
    void refusedPort() throws Exception {
        int port = closedPort();
        start(DESCRIBE, MicroProxy.bootstrap());
        HttpResponse<String> response = get(client(proxy), "http://127.0.0.1:" + port + "/r");
        assertEquals(503, response.statusCode());
        assertTrue(response.body().startsWith("connect_failed 127.0.0.1 502 "), response.body());
        assertTrue(response.body().contains("refused"), response.body());
        assertTrue(!response.body().contains("\tat "), "no stack trace: " + response.body());
    }

    @Test
    void serverTimeout() throws Exception {
        try (TestSupport.RawServer silent = TestSupport.rawServer(s -> {
            readUntil(s.getInputStream(), "\r\n\r\n");
            Thread.sleep(5_000);
        })) {
            start("""
                    def on_failure(req, failure, ctx):
                        if failure.kind == "server_timeout":
                            return response(504, "the site is slow\\n", headers={"Retry-After": "5"})
                    """, MicroProxy.bootstrap().withIdleConnectionTimeout(Duration.ofMillis(300)));
            HttpResponse<String> response = get(client(proxy), "http://127.0.0.1:" + silent.port() + "/");
            assertEquals(504, response.statusCode());
            assertEquals("the site is slow\n", response.body());
            assertEquals("5", response.headers().firstValue("retry-after").orElseThrow());
        }
    }

    @Test
    void noneFallsThroughToTheFailureResponder() throws Exception {
        int port = closedPort();
        start("""
                def on_failure(req, failure, ctx):
                    if req.path == "/script":
                        return response(503, "script")
                    return None
                """, MicroProxy.bootstrap().withFailureResponder(responder));
        assertEquals("script", get(client(proxy), "http://127.0.0.1:" + port + "/script").body());
        assertTrue(responderSaw.isEmpty());
        HttpResponse<String> java = get(client(proxy), "http://127.0.0.1:" + port + "/other");
        assertEquals(599, java.statusCode());
        assertEquals("java ConnectFailed", java.body());
    }

    @Test
    void aFailingHookFallsThroughInsteadOfAnswering500() throws Exception {
        int port = closedPort();
        start("""
                def on_failure(req, failure, ctx):
                    if req.path == "/wrong-type":
                        return "not a response"
                    fail("boom")
                """, MicroProxy.bootstrap().withFailureResponder(responder));
        assertEquals(599, get(client(proxy), "http://127.0.0.1:" + port + "/boom").statusCode());
        assertEquals(599, get(client(proxy), "http://127.0.0.1:" + port + "/wrong-type").statusCode());

        proxy.abort();
        start("def on_failure(req, failure, ctx):\n    fail('boom')\n", MicroProxy.bootstrap());
        HttpResponse<String> fallback = get(client(proxy), "http://127.0.0.1:" + port + "/");
        assertEquals(502, fallback.statusCode(), "the proxy's default, not a script error");
    }

    @Test
    void tooLargeRequestsSeeTheOriginalRequest() throws Exception {
        ScriptedProxy script = ScriptedProxy.builder("""
                def buffer_request(req, ctx):
                    return True

                def on_failure(req, failure, ctx):
                    return response(failure.status, "%s %s %s %s" % (failure.kind, req.method, req.path, failure.host))
                """, "large.star").maxBodySize(10).build();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(script).start();
        HttpResponse<String> response = send(client(proxy), HttpRequest.newBuilder(URI.create("http://127.0.0.1:1/upload"))
                .POST(HttpRequest.BodyPublishers.ofString("x".repeat(1000))).build());
        assertEquals(413, response.statusCode());
        assertEquals("request_too_large POST /upload None", response.body());
    }

    @Test
    void typedFailures() throws Exception {
        int port = closedPort();
        start("""
                def on_failure(req: Request, failure: Failure, ctx: Context) -> Response | None:
                    host: str | None = failure.host
                    code: int = failure.status
                    if failure.kind == "connect_failed" and host != None:
                        return response(code, "down: " + cast(str, host))
                    return None
                """, MicroProxy.bootstrap());
        assertEquals("down: 127.0.0.1", get(client(proxy), "http://127.0.0.1:" + port + "/").body());

        String error = assertThrows(ScriptException.class, () -> StarlarkScript.compile("""
                def on_failure(req: Request, failure: Failure, ctx: Context):
                    return failure.knd
                """, "typed.star", StarlarkScript.Limits.DEFAULT)).getMessage();
        assertTrue(error.contains("'failure' of type 'Failure' does not have field 'knd'"), error);
        error = assertThrows(ScriptException.class, () -> StarlarkScript.compile("""
                def describe(failure: Failure) -> str:
                    return failure.host
                """, "typed.star", StarlarkScript.Limits.DEFAULT)).getMessage();
        assertTrue(error.contains("declares return type 'str' but may return 'str | None'"), error);
    }

    @Test
    void failureFieldsForEachKind() {
        IOException cause = new IOException("first line\nsecond line");
        assertEquals(List.of("unresolved_host", "connect_failed", "tls_failed", "server_timeout", "bad_server_response",
                        "no_route", "no_connection_available", "bad_request", "request_too_large"),
                List.of(new ProxyFailure.UnresolvedHost("a:1", new UnknownHostException("a")),
                                new ProxyFailure.ConnectFailed("a:1", cause), new ProxyFailure.TlsFailed("a:1", cause),
                                new ProxyFailure.ServerTimeout("a:1", cause),
                                new ProxyFailure.BadServerResponse("a:1", cause), new ProxyFailure.NoRoute(null),
                                new ProxyFailure.NoConnectionAvailable("a:1"), new ProxyFailure.BadRequest("why"),
                                new ProxyFailure.RequestTooLarge(5))
                        .stream().map(ScriptFailure::kind).toList());
        assertEquals("first line", ScriptFailure.message(new ProxyFailure.ConnectFailed("a:1", cause)));
        assertEquals("IOException", ScriptFailure.message(new ProxyFailure.ConnectFailed("a:1", new IOException())));
        assertEquals("the request names no host", ScriptFailure.message(new ProxyFailure.NoRoute(null)));
        assertEquals("why", ScriptFailure.message(new ProxyFailure.BadRequest("why")));
        assertEquals("::1", ScriptFailure.host("[::1]:8080"));
        assertEquals("example.com", ScriptFailure.host("Example.COM:443"));
    }
}
