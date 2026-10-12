package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.MetricsAssertions.awaitAtLeast;
import static org.microproxy.MetricsAssertions.awaitValue;
import static org.microproxy.MetricsAssertions.value;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.WebSocketFrame;
import org.microproxy.http.WebSocketMessage;
import org.microproxy.stats.StatsRegistry;

/**
 * WebSocket sessions, {@code websocket.*}, and the hooks that see them: the HTTP filters' ({@code
 * hooks.http_filters.*}) on the upgrade, and the frame and message hooks' ({@code
 * hooks.websocket_frame.*}, {@code hooks.websocket_message.*}).
 */
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class WebSocketStatsTest {

    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
    }

    private StatsRegistry start(HttpFilters filters) {
        proxy = MicroProxy.bootstrap().withPort(0).withMetrics(true).withFiltersSource(new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                return filters;
            }
        }).start();
        return proxy.getStats();
    }

    @Test
    void framesMessagesCloseCodesAndTheHooksAreCounted() throws Exception {
        StatsRegistry r = start(new HttpFilters() {
            @Override
            public void webSocketFrameReceived(WebSocketFrame frame, boolean fromClient) {}

            @Override
            public WebSocketMessage filterWebSocketMessage(WebSocketMessage message, boolean fromClient) {
                if (message.isBinary()) return null;
                if (fromClient) return message.withText(message.text().toUpperCase());
                return message;
            }
        });
        String big = "ping " + "a".repeat(2000);
        try (WebSocketPeer.Server server = new WebSocketPeer.Server("permessage-deflate");
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), "permessage-deflate")) {
            client.sendMessage(WebSocketFrame.OPCODE_BINARY, new byte[] {1, 2, 3}, true, 1);
            client.sendMessage(WebSocketFrame.OPCODE_TEXT, big.getBytes(StandardCharsets.UTF_8), true, 2);
            assertEquals("echo:" + big.toUpperCase(), client.readMessage().text());
            assertEquals(1, value(r, "websocket.sessions_active"));
            client.send(WebSocketFrame.of(true, 0, WebSocketFrame.OPCODE_CLOSE, new byte[] {0x03, (byte) 0xe8}));
            awaitAtLeast(r, "websocket.close_codes.1000", 1);
        }
        awaitValue(r, "websocket.sessions_active", 0);
        assertEquals(1, value(r, "websocket.sessions_total"));
        // The client's two messages and the server's echo were joined for the message hook
        assertEquals(3, value(r, "websocket.messages_rx"));
        assertEquals(2, value(r, "websocket.messages_tx"));
        assertEquals(3, value(r, "hooks.websocket_message.invocations"));
        assertEquals(1, value(r, "hooks.websocket_message.drops"));
        assertEquals(1, value(r, "hooks.websocket_message.rewrites"));
        assertEquals(3, value(r, "hooks.websocket_message.latency_us"));
        assertTrue(value(r, "hooks.websocket_frame.invocations") >= 4, "every frame read");
        assertEquals(0, value(r, "hooks.websocket_frame.drops"));
        assertTrue(value(r, "websocket.frames_rx") >= 4);
        assertTrue(value(r, "websocket.frames_tx") >= 2);
        // The upper-cased message was compressed again by the proxy: 2000 letters take far fewer bytes
        assertTrue(value(r, "websocket.deflate_bytes_saved") > 1000, "saved " + value(r, "websocket.deflate_bytes_saved"));
        // The upgrade went through the HTTP filters' head hooks
        assertTrue(value(r, "hooks.http_filters.invocations") >= 4);
        assertEquals(0, value(r, "hooks.http_filters.errors"));
        assertEquals(0, value(r, "tunnel.active"));
    }

    @Test
    void httpFilterAnswersAndThrowsAreCounted() throws Exception {
        StatsRegistry r = start(new HttpFilters() {
            @Override
            public org.microproxy.http.HttpResponse clientToProxyRequest(org.microproxy.http.HttpObject object) {
                if (object instanceof HttpRequest req && req.uri().endsWith("/answer")) {
                    return new org.microproxy.http.DefaultFullHttpResponse(org.microproxy.http.HttpVersion.HTTP_1_1,
                            org.microproxy.http.HttpResponseStatus.valueOf(204));
                }
                if (object instanceof HttpRequest req && req.uri().endsWith("/throw")) {
                    throw new IllegalStateException("a broken filter");
                }
                return null;
            }
        });
        var client = TestSupport.client(proxy);
        var origin = TestSupport.origin(TestSupport.fixed(200, "ok"));
        try {
            assertEquals(204, TestSupport.get(client, TestSupport.url(origin, "/answer")).statusCode());
            // A filter that throws closes the client's connection (which the JDK client tries again)
            org.junit.jupiter.api.Assertions.assertThrows(RuntimeException.class,
                    () -> TestSupport.get(client, TestSupport.url(origin, "/throw")));
            assertEquals(200, TestSupport.get(client, TestSupport.url(origin, "/fine")).statusCode());
        } finally {
            origin.stop(0);
        }
        assertEquals(1, value(r, "hooks.http_filters.rewrites"));
        long errors = value(r, "hooks.http_filters.errors");
        assertTrue(errors >= 1, "errors");
        // /answer: one hook; /throw: one per try; /fine: the four head hooks
        assertEquals(1 + errors + 4, value(r, "hooks.http_filters.invocations"));
        assertEquals(1 + errors + 4, value(r, "hooks.http_filters.latency_us"));
    }
}
