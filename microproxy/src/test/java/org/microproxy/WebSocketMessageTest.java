package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.WebSocketPeer.Message;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.WebSocketFrame;
import org.microproxy.http.WebSocketMessage;

/**
 * Whole WebSocket messages: frames joined for {@link HttpFilters#filterWebSocketMessage}, with
 * control frames in between, edits, drops, replies, the size limit, and the order of the frame
 * and message hooks.
 */
@Timeout(30)
class WebSocketMessageTest {

    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
    }

    private void start(HttpFilters filters) {
        start(MicroProxy.bootstrap(), filters);
    }

    private void start(HttpProxyServerBootstrap bootstrap, HttpFilters filters) {
        proxy = bootstrap.withPort(0).withFiltersSource(new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                return filters;
            }
        }).start();
    }

    private static String describe(WebSocketFrame f) {
        String kind = switch (f.opcode()) {
            case WebSocketFrame.OPCODE_TEXT -> "text";
            case WebSocketFrame.OPCODE_BINARY -> "binary";
            case WebSocketFrame.OPCODE_CONTINUATION -> "cont";
            case WebSocketFrame.OPCODE_PING -> "ping";
            case WebSocketFrame.OPCODE_PONG -> "pong";
            case WebSocketFrame.OPCODE_CLOSE -> "close";
            default -> "op" + f.opcode();
        };
        return kind + (f.isFinal() ? "" : "+") + ":" + (f.isClose() ? "" : f.payloadAsText());
    }

    // -------------------------------------------------------------------------------------------
    // The record
    // -------------------------------------------------------------------------------------------

    @Test
    void messagesAreImmutableValues() {
        byte[] data = {1, 2, 3};
        WebSocketMessage m = WebSocketMessage.binary(data, true);
        data[0] = 9;
        assertArrayEquals(new byte[] {1, 2, 3}, m.payload());
        m.payload()[1] = 9;
        assertArrayEquals(new byte[] {1, 2, 3}, m.payload());
        assertEquals(3, m.length());
        assertTrue(m.isBinary());
        assertTrue(m.fromClient());

        WebSocketMessage t = WebSocketMessage.text("héllo", false);
        assertTrue(t.isText());
        assertEquals("héllo", t.text());
        assertEquals("héllo", t.textOrNull());
        assertEquals(6, t.length());
        assertEquals(WebSocketFrame.OPCODE_TEXT, t.type().opcode());
        assertEquals(WebSocketFrame.OPCODE_BINARY, WebSocketMessage.Type.BINARY.opcode());
        assertEquals("HI", t.withText("HI").text());
        assertFalse(t.withText("HI").fromClient());
        assertTrue(t.withFromClient(true).fromClient());
        assertTrue(t.withType(WebSocketMessage.Type.BINARY).isBinary());
        assertArrayEquals(new byte[] {7}, t.withPayload(new byte[] {7}).payload());
        assertNull(WebSocketMessage.binary(new byte[] {(byte) 0xc3}, true).textOrNull());

        assertEquals(WebSocketMessage.text("a", true), WebSocketMessage.text("a", true));
        assertEquals(WebSocketMessage.text("a", true).hashCode(), WebSocketMessage.text("a", true).hashCode());
        assertNotEquals(WebSocketMessage.text("a", true), WebSocketMessage.text("a", false));
        assertNotEquals(WebSocketMessage.text("a", true), WebSocketMessage.binary(new byte[] {'a'}, true));
        assertEquals("WebSocketMessage[TEXT from client, 1 bytes]", WebSocketMessage.text("a", true).toString());
        assertThrows(NullPointerException.class, () -> new WebSocketMessage(null, new byte[0], true));
    }

    // -------------------------------------------------------------------------------------------
    // Joining
    // -------------------------------------------------------------------------------------------

    @Test
    void fragmentsAreJoinedAndControlFramesInBetweenGoOnAtOnce() throws Exception {
        List<String> messages = new CopyOnWriteArrayList<>();
        List<String> frames = new CopyOnWriteArrayList<>();
        start(new HttpFilters() {
            @Override
            public void webSocketFrameReceived(WebSocketFrame frame, boolean fromClient) {
                if (fromClient) frames.add(describe(frame));
            }

            @Override
            public WebSocketMessage filterWebSocketMessage(WebSocketMessage message, boolean fromClient) {
                messages.add((fromClient ? "> " : "< ") + message.type() + " " + message.text());
                return message;
            }
        });
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            client.send(WebSocketFrame.of(false, 0, WebSocketFrame.OPCODE_TEXT, "pi".getBytes()));
            client.send(WebSocketFrame.of(true, 0, WebSocketFrame.OPCODE_PING, "p1".getBytes()));
            client.send(WebSocketFrame.of(false, 0, WebSocketFrame.OPCODE_CONTINUATION, "ng ".getBytes()));
            // The ping reaches the server while the message is still being joined.
            eventually("the ping to reach the server", () -> server.received.size() == 1);
            assertEquals("p1", server.received.getFirst().text());
            client.send(WebSocketFrame.of(true, 0, WebSocketFrame.OPCODE_PONG, "p2".getBytes()));
            client.send(WebSocketFrame.of(true, 0, WebSocketFrame.OPCODE_CONTINUATION, "hello".getBytes()));
            assertEquals("echo:ping hello", client.readMessage().text());

            List<Message> received = new ArrayList<>(server.received);
            assertEquals(3, received.size(), received.toString());
            assertEquals(WebSocketFrame.OPCODE_PING, received.get(0).opcode());
            assertEquals(WebSocketFrame.OPCODE_PONG, received.get(1).opcode());
            assertEquals("ping hello", received.get(2).text());
            // Unchanged, so split as it came, and masked again towards the server.
            assertEquals(List.of("text+:pi", "cont+:ng ", "cont:hello"),
                    received.get(2).frames().stream().map(WebSocketMessageTest::describe).toList());
            assertTrue(received.get(2).frames().stream().allMatch(WebSocketFrame::isMasked));
            assertEquals(List.of("> TEXT ping hello", "< TEXT echo:ping hello"), messages);
            assertEquals(List.of("text+:pi", "ping:p1", "cont+:ng ", "pong:p2", "cont:hello"), frames);
        }
    }

    @Test
    void editedMessagesGoOutAsOneFrameAndDroppedOnesNotAtAll() throws Exception {
        start(new HttpFilters() {
            @Override
            public WebSocketMessage filterWebSocketMessage(WebSocketMessage message, boolean fromClient) {
                if (message.isBinary() && message.length() > 4) return null;
                if (message.isText() && fromClient) return message.withText(message.text().toUpperCase());
                return message;
            }
        });
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            client.sendMessage(WebSocketFrame.OPCODE_BINARY, new byte[10], false, 3);
            client.sendMessage(WebSocketFrame.OPCODE_BINARY, new byte[] {1, 2}, false, 2);
            client.sendMessage(WebSocketFrame.OPCODE_TEXT, "ping, in pieces".getBytes(), false, 4);
            Message echoBinary = client.readMessage();
            assertArrayEquals(new byte[] {1, 2}, echoBinary.payload());
            assertEquals("echo:PING, IN PIECES", client.readMessage().text());
            eventually("two messages at the server", () -> server.received.size() == 2);
            assertEquals(2, server.received.getFirst().frames().size(), "unchanged: split as it came");
            assertEquals(List.of("text:PING, IN PIECES"),
                    server.received.get(1).frames().stream().map(WebSocketMessageTest::describe).toList());
        }
    }

    @Test
    void filtersCanAnswerAndAddMessagesInEitherDirection() throws Exception {
        start(new HttpFilters() {
            @Override
            public List<WebSocketMessage> filterWebSocketMessages(WebSocketMessage message, boolean fromClient) {
                if (!fromClient) return List.of(message);
                return switch (message.text()) {
                    // Answered by the proxy: the server never sees it.
                    case "whoami" -> List.of(WebSocketMessage.text("you are " + "the client", false));
                    // Sent on, with a note to the client first.
                    default -> List.of(message.withText("[proxied]").withFromClient(false), message,
                            WebSocketMessage.text("ping extra", true));
                };
            }
        });
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            client.sendText("whoami");
            assertEquals("you are the client", client.readMessage().text());
            client.sendText("ping 1");
            List<String> replies = new ArrayList<>();
            for (int i = 0; i < 3; i++) replies.add(client.readMessage().text());
            assertEquals(List.of("[proxied]", "echo:ping 1", "echo:ping extra"), replies);
            assertEquals(List.of("ping 1", "ping extra"), server.texts());
        }
    }

    @Test
    void theFrameHookRunsFirstAndTheMessageHookSeesWhatItReturned() throws Exception {
        List<String> order = new CopyOnWriteArrayList<>();
        HttpFiltersBuilder.Built filters = HttpFilters.builder()
                .onWebSocketFrame((frame, fromClient) -> {
                    if (!fromClient) return frame;
                    order.add("frame " + describe(frame));
                    if (frame.isPing()) return null;
                    if (frame.payloadAsText().equals("drop")) return null;
                    return frame.withText(frame.payloadAsText() + "!");
                })
                .onWebSocketMessage((message, fromClient) -> {
                    if (fromClient) order.add("message " + message.text());
                    return message;
                })
                .onWebSocketMessage((message, fromClient) -> fromClient ? message.withText(message.text() + "?") : message)
                .build();
        start(filters);
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            client.send(WebSocketFrame.of(false, 0, WebSocketFrame.OPCODE_TEXT, "ping".getBytes()));
            client.send(WebSocketFrame.of(true, 0, WebSocketFrame.OPCODE_PING, "x".getBytes()));
            client.send(WebSocketFrame.of(false, 0, WebSocketFrame.OPCODE_CONTINUATION, "drop".getBytes()));
            client.send(WebSocketFrame.of(true, 0, WebSocketFrame.OPCODE_CONTINUATION, "end".getBytes()));
            assertEquals("echo:ping!end!?", client.readMessage().text());
            assertEquals(List.of("frame text+:ping", "frame ping:x", "frame cont+:drop", "frame cont:end",
                    "message ping!end!"), order);
            assertEquals(List.of("ping!end!?"), server.texts(), "the dropped ping never arrived");
        }
    }

    @Test
    void aMessageOverTheLimitClosesBothSidesWith1009() throws Exception {
        start(MicroProxy.bootstrap().withMaxWebSocketMessageSize(1000), new HttpFilters() {
            @Override
            public WebSocketMessage filterWebSocketMessage(WebSocketMessage message, boolean fromClient) {
                return message;
            }
        });
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            client.sendMessage(WebSocketFrame.OPCODE_BINARY, new byte[1000], false, 3);
            assertEquals(1000, client.readMessage().payload().length, "exactly the limit is fine");
            client.send(WebSocketFrame.of(false, 0, WebSocketFrame.OPCODE_BINARY, new byte[600]));
            client.send(WebSocketFrame.of(true, 0, WebSocketFrame.OPCODE_CONTINUATION, new byte[600]));
            Message close = client.readMessage();
            assertTrue(close.isClose());
            assertEquals(1009, close.closeCode());
            // Then the connection ends; the server's answer to its own close may come through first.
            assertThrows(IOException.class, () -> {
                while (true) assertTrue(client.readFrame().isClose());
            });
            eventually("the server to get the close", () -> server.received.size() == 2);
            assertEquals(1009, server.received.get(1).closeCode());
        }
    }

    @Test
    void aSingleFrameOverTheLimitIsNotEvenRead() throws Exception {
        start(MicroProxy.bootstrap().withMaxWebSocketMessageSize(100), HttpFilters.builder()
                .onWebSocketMessage((m, c) -> m).build());
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            // Only the header goes: the proxy fails the connection before reading a payload.
            byte[] wire = WebSocketFrame.binary(new byte[5000]).toWire(true);
            client.sendRaw(java.util.Arrays.copyOf(wire, 8));
            Message close = client.readMessage();
            assertEquals(1009, close.closeCode());
            eventually("the server to get the close", () -> server.received.size() == 1);
            assertEquals(1009, server.received.getFirst().closeCode());
        }
    }

    @Test
    void framesThatBreakMessageOrderFailTheConnectionWhenJoining() throws Exception {
        start(HttpFilters.builder().onWebSocketMessage((m, c) -> m).build());
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            client.send(WebSocketFrame.of(true, 0, WebSocketFrame.OPCODE_CONTINUATION, "stray".getBytes()));
            assertEquals(1002, client.readMessage().closeCode());
        }
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            client.send(WebSocketFrame.of(false, 0, WebSocketFrame.OPCODE_TEXT, "one".getBytes()));
            client.send(WebSocketFrame.of(true, 0, WebSocketFrame.OPCODE_TEXT, "two".getBytes()));
            assertEquals(1002, client.readMessage().closeCode());
        }
    }

    @Test
    void aThrowingMessageFilterForwardsTheMessage() throws Exception {
        start(new HttpFilters() {
            @Override
            public WebSocketMessage filterWebSocketMessage(WebSocketMessage message, boolean fromClient) {
                throw new IllegalStateException("boom");
            }
        });
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            client.sendMessage(WebSocketFrame.OPCODE_TEXT, "ping anyway".getBytes(), false, 2);
            assertEquals("echo:ping anyway", client.readMessage().text());
        }
    }

    @Test
    void chainsPassMessagesFromFilterToFilter() throws Exception {
        HttpFiltersSource first = HttpFilters.builder().onWebSocketMessage((m, c) -> c ? m.withText(m.text() + " 1") : m).build();
        HttpFiltersSource second = new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                return new HttpFilters() {
                    @Override
                    public List<WebSocketMessage> filterWebSocketMessages(WebSocketMessage message, boolean fromClient) {
                        return fromClient ? List.of(message.withFromClient(false), message.withText(message.text() + " 2"))
                                : List.of(message);
                    }
                };
            }
        };
        HttpFiltersSource third = HttpFilters.builder().onWebSocketMessage((m, c) -> m.withText(m.text() + " 3")).build();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(HttpFiltersChain.of(first, second, third)).start();
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            client.sendText("ping");
            // The copy sent back to the client went through the third filter too, as a server message.
            assertEquals("ping 1 3", client.readMessage().text());
            assertEquals("echo:ping 1 2 3 3", client.readMessage().text());
            assertEquals(List.of("ping 1 2 3"), server.texts());
        }
    }

    // -------------------------------------------------------------------------------------------
    // Without message hooks
    // -------------------------------------------------------------------------------------------

    @Test
    void withoutAMessageHookFragmentsAreNotHeldBack() throws Exception {
        start(HttpFilters.builder().onWebSocketFrame((f, c) -> f).build());
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), null)) {
            client.send(WebSocketFrame.of(false, 0, WebSocketFrame.OPCODE_TEXT, "ping ".getBytes()));
            // The first fragment reaches the server before the rest is even sent.
            eventually("the first fragment to arrive", () -> server.fragments.get() == 1);
            client.send(WebSocketFrame.of(true, 0, WebSocketFrame.OPCODE_CONTINUATION, "last".getBytes()));
            assertEquals("echo:ping last", client.readMessage().text());
        }
    }

    // -------------------------------------------------------------------------------------------
    // A real client
    // -------------------------------------------------------------------------------------------

    @Test
    void aWebSocketSessionIsOneRecordWhenItCloses() throws Exception {
        RecordedFlows flows = new RecordedFlows();
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                HttpClient http = HttpClient.newHttpClient()) {
            start(MicroProxy.bootstrap().withReverseProxy("http://127.0.0.1:" + server.port()).plusActivityTracker(flows),
                    HttpFilters.builder().build());
            CompletableFuture<String> reply = new CompletableFuture<>();
            WebSocket ws = http.newWebSocketBuilder().buildAsync(
                    URI.create("ws://127.0.0.1:" + proxy.getListenAddress().getPort() + "/chat"), new WebSocket.Listener() {
                        @Override
                        public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                            reply.complete(data.toString());
                            return null;
                        }
                    }).get(10, TimeUnit.SECONDS);
            ws.sendText("ping", true).get(5, TimeUnit.SECONDS);
            assertEquals("echo:ping", reply.get(10, TimeUnit.SECONDS));
            assertTrue(flows.records.isEmpty(), "no record while the session is open: " + flows.records);
            ws.abort();
            FlowRecord r = flows.await(FlowRecord.Kind.WEBSOCKET);
            assertEquals(101, r.responseCode());
            assertTrue(r.bytesReceived() > 0 && r.bytesSent() > 0, r.toString());
            assertEquals("websocket", org.microproxy.extras.AccessLogFormat.envoy("%MP_FLOW%").format(r));
        }
    }

    @Test
    void theJdkClientsFragmentedMessagesAreJoined() throws Exception {
        List<String> seen = new CopyOnWriteArrayList<>();
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                HttpClient http = HttpClient.newHttpClient()) {
            // As a reverse proxy: the JDK client sends a WebSocket through a forward proxy in a CONNECT tunnel.
            start(MicroProxy.bootstrap().withReverseProxy("http://127.0.0.1:" + server.port()),
                    HttpFilters.builder().onWebSocketMessage((m, fromClient) -> {
                        seen.add((fromClient ? "> " : "< ") + m.text());
                        return fromClient ? m.withText(m.text().replace("secret", "******")) : m;
                    }).build());
            CompletableFuture<String> reply = new CompletableFuture<>();
            WebSocket ws = http.newWebSocketBuilder().buildAsync(
                    URI.create("ws://127.0.0.1:" + proxy.getListenAddress().getPort() + "/chat"), new WebSocket.Listener() {
                        private final StringBuilder text = new StringBuilder();

                        @Override
                        public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                            text.append(data);
                            if (last) reply.complete(text.toString());
                            webSocket.request(1);
                            return null;
                        }
                    }).get(10, TimeUnit.SECONDS);
            ws.sendText("ping, my ", false).get(5, TimeUnit.SECONDS);
            ws.sendPing(ByteBuffer.wrap("x".getBytes(StandardCharsets.UTF_8))).get(5, TimeUnit.SECONDS);
            ws.sendText("secret is ", false).get(5, TimeUnit.SECONDS);
            ws.sendText("safe", true).get(5, TimeUnit.SECONDS);
            assertEquals("echo:ping, my ****** is safe", reply.get(10, TimeUnit.SECONDS));
            assertEquals(List.of("> ping, my secret is safe", "< echo:ping, my ****** is safe"), seen);
            Message joined = server.received.stream().filter(m -> m.opcode() == WebSocketFrame.OPCODE_TEXT)
                    .findFirst().orElseThrow();
            assertEquals(1, joined.frames().size(), "an edited message goes out as one frame");
            // The JDK's client offers no extensions, so compression needs the hand-built peers.
            assertNull(WebSocketTestSupport.header(server.requests.getFirst(), "Sec-WebSocket-Extensions"));
            ws.abort();
        }
    }
}
