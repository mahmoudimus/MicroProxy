package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/**
 * {@link ProtocolPolicy#generatedResponses()}: what {@code proxyToClientResponse} may do with the
 * proxy's own error responses, a {@link FailureResponder}'s, and filters' short-circuit responses;
 * and {@link FlowContext#responseSource()} inside the hooks.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class GeneratedResponsesTest {

    private HttpProxyServer proxy;
    private HttpServer origin;
    /** A port nothing listens on, kept for the test. */
    private Socket refusing;
    /** What proxyToClientResponse was handed: "<status> <source>". */
    private final List<String> hooked = new CopyOnWriteArrayList<>();
    /** What proxyToClientResponseSent and the trackers were told was sent. */
    private final List<String> sent = new CopyOnWriteArrayList<>();
    private final List<String> tracked = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.stop(0);
        if (refusing != null) refusing.close();
    }

    /** What the response filter does with what it is handed. */
    enum Action {
        /** Returns a {@code 418} of its own. */
        REPLACE,
        /** Adds a header and sets status 299 in place, then returns a new {@code 418} anyway. */
        EDIT_THEN_REPLACE,
        /** Returns {@code null}. */
        DROP
    }

    private static final String SHORT_CIRCUIT = "/short-circuit";

    /**
     * A proxy whose filter answers {@link #SHORT_CIRCUIT} itself with a {@code 403}, and acts on
     * every response it sees in {@code proxyToClientResponse}.
     */
    private HttpProxyServerBootstrap proxy(Action action, UnaryOperator<HttpProxyServerBootstrap> policy) {
        if (proxy != null) proxy.abort();
        hooked.clear();
        sent.clear();
        tracked.clear();
        return policy.apply(MicroProxy.bootstrap().withPort(0).withHttp2Cleartext(true)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void responseSentToClient(FlowContext ctx, HttpResponse response, ResponseSource source) {
                        tracked.add(response.status().code() + " " + source);
                    }
                })
                .withFiltersSource((original, ctx) -> new HttpFilters() {
                    @Override
                    public HttpResponse clientToProxyRequest(HttpObject o) {
                        if (o instanceof HttpRequest r && r.uri().endsWith(SHORT_CIRCUIT)) {
                            return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN,
                                    "no".getBytes(StandardCharsets.UTF_8));
                        }
                        return null;
                    }

                    @Override
                    public HttpObject proxyToClientResponse(HttpObject o) {
                        if (!(o instanceof HttpResponse r)) return o;
                        hooked.add(r.status().code() + " " + ctx.responseSource().map(Enum::name).orElse("?"));
                        return switch (action) {
                            case REPLACE -> teapot();
                            case EDIT_THEN_REPLACE -> {
                                r.headers().set("X-Edited", "yes");
                                r.setStatus(new HttpResponseStatus(299, "Edited"));
                                yield teapot();
                            }
                            case DROP -> null;
                        };
                    }

                    @Override
                    public void proxyToClientResponseSent(HttpResponse response, ResponseSource source) {
                        sent.add(response.status().code() + " " + source);
                    }
                }));
    }

    private static HttpResponse teapot() {
        return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, new HttpResponseStatus(418, "Teapot"),
                "teapot".getBytes(StandardCharsets.UTF_8));
    }

    private static UnaryOperator<HttpProxyServerBootstrap> forAll(GeneratedResponses mode) {
        return b -> b.onAllProtocols(p -> p.generatedResponses(mode));
    }

    private String originUrl(String path) {
        if (origin == null) origin = TestSupport.origin(TestSupport.fixed(200, "ok"));
        return "http://127.0.0.1:" + origin.getAddress().getPort() + path;
    }

    /** A URL whose server refuses connections: the proxy answers 502. */
    private String unreachable() {
        if (refusing == null) refusing = TestSupport.refusingPort();
        return "http://127.0.0.1:" + refusing.getLocalPort() + "/";
    }

    /** The answer to a GET of {@code url} over HTTP/1.1, or "" if the connection closed without one. */
    private String http1(String url) throws IOException {
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            s.setSoTimeout(20_000);
            write(s.getOutputStream(), "GET " + url + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            return new String(s.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
        }
    }

    @Test
    void replaceableByDefault() throws Exception {
        proxy = proxy(Action.REPLACE, UnaryOperator.identity()).start();
        assertEquals(Optional.of(GeneratedResponses.REPLACEABLE),
                proxy.getProtocolPolicy(HttpVersion.HTTP_1_1).generatedResponses());
        assertTrue(http1(unreachable()).startsWith("HTTP/1.1 418"));
        assertTrue(http1(originUrl(SHORT_CIRCUIT)).startsWith("HTTP/1.1 418"));
        assertTrue(http1(originUrl("/")).startsWith("HTTP/1.1 418"), "the server's response too");
        assertEquals(List.of("502 PROXY", "403 FILTER", "200 SERVER"), hooked);
        TestSupport.eventually("three sent", () -> sent.size() == 3);
        assertEquals(List.of("418 FILTER", "418 FILTER", "418 FILTER"), sent);
    }

    @Test
    void inPlaceKeepsTheGeneratedResponseWithItsEdits() throws Exception {
        proxy = proxy(Action.EDIT_THEN_REPLACE, forAll(GeneratedResponses.IN_PLACE)).start();
        String error = http1(unreachable());
        assertTrue(error.startsWith("HTTP/1.1 299 Edited"), error);
        assertTrue(error.contains("X-Edited: yes"), error);
        assertFalse(error.contains("teapot"), error);
        String shortCircuit = http1(originUrl(SHORT_CIRCUIT));
        assertTrue(shortCircuit.startsWith("HTTP/1.1 299"), shortCircuit);
        assertTrue(shortCircuit.endsWith("no"), shortCircuit);
        // The server's responses are not generated: a replacement is sent.
        assertTrue(http1(originUrl("/")).startsWith("HTTP/1.1 418"));
        TestSupport.eventually("three sent", () -> sent.size() == 3);
        // (An in-place status change makes the response the filter's.)
        assertEquals(List.of("299 FILTER", "299 FILTER", "418 FILTER"), sent);
    }

    @Test
    void inPlaceAndReplaceableBothDropOnNull() throws Exception {
        for (GeneratedResponses mode : List.of(GeneratedResponses.REPLACEABLE, GeneratedResponses.IN_PLACE)) {
            proxy = proxy(Action.DROP, forAll(mode)).start();
            assertEquals("", http1(unreachable()), mode + ": closed without an answer");
            assertEquals("", http1(originUrl(SHORT_CIRCUIT)), mode.toString());
            assertEquals(List.of(), sent, mode.toString());
        }
    }

    @Test
    void skipKeepsGeneratedResponsesFromTheHook() throws Exception {
        proxy = proxy(Action.DROP, forAll(GeneratedResponses.SKIP)).start();
        assertTrue(http1(unreachable()).startsWith("HTTP/1.1 502"));
        assertTrue(http1(originUrl(SHORT_CIRCUIT)).startsWith("HTTP/1.1 403"));
        assertEquals(List.of(), hooked, "the hook saw neither");
        assertEquals("", http1(originUrl("/")), "the server's response still goes through it");
        assertEquals(List.of("200 SERVER"), hooked);
        TestSupport.eventually("two sent", () -> sent.size() == 2 && tracked.size() == 2);
        assertEquals(List.of("502 PROXY", "403 FILTER"), sent);
        assertEquals(List.of("502 PROXY", "403 FILTER"), tracked);
    }

    @Test
    void aFailureRespondersAnswerIsGeneratedToo() throws Exception {
        proxy = proxy(Action.REPLACE, forAll(GeneratedResponses.IN_PLACE))
                .withFailureResponder((request, failure) -> new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                        HttpResponseStatus.SERVICE_UNAVAILABLE, "branded".getBytes(StandardCharsets.UTF_8)))
                .start();
        String answer = http1(unreachable());
        assertTrue(answer.startsWith("HTTP/1.1 503"), answer);
        assertTrue(answer.endsWith("branded"), answer);
        assertEquals(List.of("503 PROXY"), hooked);
    }

    @Test
    void littleProxysPresetReplacesAsLittleProxy29Does() throws Exception {
        proxy = proxy(Action.REPLACE, HttpProxyServerBootstrap::withLittleProxyCompatibility).start();
        assertTrue(http1(unreachable()).startsWith("HTTP/1.1 418"));
        // LittleProxy 1.x and its forks: the preset with one field changed.
        proxy = proxy(Action.REPLACE, b -> b.onHttp1(p -> p.preset(ProtocolPolicy.littleProxy())
                .generatedResponses(GeneratedResponses.IN_PLACE))).start();
        assertTrue(http1(unreachable()).startsWith("HTTP/1.1 502"));
    }

    @Test
    void eachClientProtocolHasItsOwnMode() throws Exception {
        proxy = proxy(Action.REPLACE, b -> b.onHttp1(p -> p.generatedResponses(GeneratedResponses.IN_PLACE))).start();
        String target = unreachable().substring("http://".length()).replace("/", "");
        assertTrue(http1(unreachable()).startsWith("HTTP/1.1 502"), "HTTP/1: in place");
        try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), target).handshake()) {
            c.get(1, "/");
            assertEquals(418, c.response(1).status(), "HTTP/2: replaceable");
        }
    }

    @Test
    void theResponseSourceIsKnownInsideTheHooks() throws Exception {
        List<String> seen = new CopyOnWriteArrayList<>();
        origin = TestSupport.origin(TestSupport.fixed(200, "ok"));
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource((original, ctx) -> new HttpFilters() {
            @Override
            public HttpObject serverToProxyResponse(HttpObject o) {
                if (o instanceof HttpResponse r) {
                    seen.add("s2p " + ctx.responseSource().orElse(null));
                    if (original.uri().endsWith("/replace")) return teapot();
                }
                return o;
            }

            @Override
            public HttpObject proxyToClientResponse(HttpObject o) {
                if (o instanceof HttpResponse) seen.add("p2c " + ctx.responseSource().orElse(null));
                return o;
            }

            @Override
            public void proxyToServerRequestSending() {
                seen.add("request " + ctx.responseSource().orElse(null));
            }
        }).start();
        assertTrue(http1(originUrl("/")).startsWith("HTTP/1.1 200"));
        assertEquals(List.of("request null", "s2p SERVER", "p2c SERVER"), seen);
        seen.clear();
        assertTrue(http1(originUrl("/replace")).startsWith("HTTP/1.1 418"));
        assertEquals(List.of("request null", "s2p SERVER", "p2c FILTER"), seen);
        seen.clear();
        assertTrue(http1(unreachable()).startsWith("HTTP/1.1 502"));
        assertEquals(List.of("p2c PROXY"), seen);
        assertNull(new FlowContext(1, () -> null, () -> null, new ClientDetails()).responseSource().orElse(null));
    }
}
