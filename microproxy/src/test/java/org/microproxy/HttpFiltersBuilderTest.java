package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpFiltersBuilder.Body;
import org.microproxy.WebSocketTestSupport.EchoServer;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.http.LastHttpContent;
import org.microproxy.http.WebSocketFrame;

class HttpFiltersBuilderTest {

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

    private void start(HttpFilters filters) {
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource((request, ctx) -> filters).start();
    }

    private static org.microproxy.http.HttpResponse forbidden() {
        return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN,
                "no".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void lambdasShortCircuitAndRewriteHeads() {
        start(HttpFilters.builder()
                .onRequest(req -> req.uri().endsWith("/blocked") ? forbidden() : null)
                .beforeSending(req -> {
                    req.headers().set("X-Sent-By", "builder");
                    return null;
                })
                .onResponse(res -> {
                    res.headers().set("X-Proxy", "micro");
                    return res;
                })
                .build());
        var client = client(proxy);
        HttpResponse<String> blocked = get(client, url(origin, "/blocked"));
        assertEquals(403, blocked.statusCode());
        assertEquals("no", blocked.body());
        HttpResponse<String> ok = get(client, url(origin, "/ok"));
        assertEquals("micro", ok.headers().firstValue("x-proxy").orElseThrow());
        assertEquals(List.of("builder"), TestSupport.echoedHeader(ok.body(), "x-sent-by"));
    }

    @Test
    void repeatedHooksRunInOrder() {
        start(HttpFilters.builder()
                .onRequest(req -> null)
                .onRequest(req -> req.uri().endsWith("/second") ? forbidden() : null)
                .onResponse(res -> {
                    res.headers().add("X-Order", "1");
                    return res;
                })
                .onResponse(res -> {
                    res.headers().add("X-Order", "2");
                    return res;
                })
                .build());
        assertEquals(403, get(client(proxy), url(origin, "/second")).statusCode());
        HttpResponse<String> ok = get(client(proxy), url(origin, "/"));
        assertEquals(List.of("1", "2"), ok.headers().allValues("x-order"));
    }

    @Test
    void bodyHooksSeeEveryPiece() {
        List<String> requestPieces = new CopyOnWriteArrayList<>();
        HttpFiltersBuilder.Built filters = HttpFilters.builder()
                .onRequestBody(piece -> requestPieces.add(
                        (piece instanceof LastHttpContent ? "last:" : "") + piece.contentAsString()))
                .onResponseBody(piece -> {
                    piece.setContent(piece.contentAsString().toUpperCase().getBytes(StandardCharsets.UTF_8));
                    return piece;
                })
                .build();
        start(filters);
        HttpResponse<String> response = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/up")))
                .POST(HttpRequest.BodyPublishers.ofString("hello body")).build());
        assertTrue(response.body().startsWith("METHOD: POST"), response.body());
        assertEquals("HELLO BODY", echoedBody(response.body()));
        assertEquals("hello body", String.join("", requestPieces).replace("last:", ""));
        assertTrue(requestPieces.getLast().startsWith("last:"), requestPieces.toString());
    }

    @Test
    void bufferedResponsesArriveWhole() {
        List<Object> seen = new CopyOnWriteArrayList<>();
        start(HttpFilters.builder()
                .bufferResponses(1 << 20)
                .onResponse(res -> {
                    seen.add(res);
                    ((FullHttpResponse) res).setContent("replaced".getBytes(StandardCharsets.UTF_8));
                    return res;
                })
                .build());
        assertEquals("replaced", get(client(proxy), url(origin, "/")).body());
        assertInstanceOf(FullHttpResponse.class, seen.getFirst());
    }

    @Test
    void onlyRegisteredBodyHooksTurnOffTheFastPath() {
        HttpFiltersBuilder.Built headsOnly = HttpFilters.builder().onRequest(r -> null).onResponse(r -> r).build();
        assertFalse(headsOnly.sees(Body.REQUEST));
        assertFalse(headsOnly.sees(Body.RESPONSE));
        assertFalse(headsOnly.sees(Body.WEBSOCKET_FRAMES));
        HttpFiltersBuilder.Built bodies = HttpFilters.builder().onRequestBody(p -> {}).onResponseBody(p -> p)
                .onWebSocketFrame((f, c) -> f).build();
        assertTrue(bodies.sees(Body.REQUEST));
        assertTrue(bodies.sees(Body.RESPONSE));
        assertTrue(bodies.sees(Body.WEBSOCKET_FRAMES));

        // A head-only filter relays a large body untouched (through the fast path).
        start(headsOnly);
        String big = "x".repeat(300_000);
        HttpResponse<String> response = send(client(proxy), HttpRequest.newBuilder(URI.create(url(origin, "/big")))
                .POST(HttpRequest.BodyPublishers.ofString(big)).build());
        assertEquals(big, echoedBody(response.body()));
    }

    @Test
    void webSocketFramesCanBeRewrittenAndDropped() throws Exception {
        start(HttpFilters.builder()
                .onWebSocketFrame((frame, fromClient) -> {
                    if (!frame.isText()) return frame;
                    String text = frame.payloadAsText();
                    if (text.startsWith("secret")) return null;
                    return fromClient ? frame.withText(text.toUpperCase()) : frame;
                })
                .build());
        try (EchoServer server = new EchoServer(); Socket s = WebSocketTestSupport.connect(proxy, server.raw())) {
            WebSocketTestSupport.sendFromClient(s.getOutputStream(), WebSocketFrame.text("secret"));
            WebSocketTestSupport.sendFromClient(s.getOutputStream(), WebSocketFrame.text("ping"));
            assertEquals("echo:PING", WebSocketTestSupport.readFrame(s.getInputStream()).payloadAsText());
            assertEquals(List.of("PING"), server.received.stream().map(WebSocketFrame::payloadAsText).toList());
        }
    }
}
