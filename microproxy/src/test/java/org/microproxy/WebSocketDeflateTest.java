package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;
import static org.microproxy.WebSocketTestSupport.header;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.WebSocketPeer.Message;
import org.microproxy.http.WebSocketFrame;
import org.microproxy.http.WebSocketMessage;

/**
 * permessage-deflate (RFC 7692) through filters that read payloads: the proxy inflates what each
 * peer sends and deflates what it forwards with its own context per hop, honouring context
 * takeover and window sizes per direction, and bounds what it inflates. The peers are built on the
 * JDK's Deflater and Inflater, since {@code java.net.http.WebSocket} offers no extensions.
 */
@Timeout(30)
class WebSocketDeflateTest {

    private static final String OFFER = "permessage-deflate; client_max_window_bits";

    private HttpProxyServer proxy;
    private final List<String> seen = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
    }

    /** Rewrites {@code hello} to {@code HELLO} in client messages, and records every message. */
    private void startRewriting(HttpProxyServerBootstrap bootstrap) {
        proxy = bootstrap.withPort(0).withFiltersSource(HttpFilters.builder().onWebSocketMessage((m, fromClient) -> {
            seen.add((fromClient ? "> " : "< ") + (m.isText() ? m.text() : m.length() + " bytes"));
            return fromClient && m.isText() ? m.withText(m.text().replace("hello", "HELLO")) : m;
        }).build()).start();
    }

    private static int frameBytes(Message m) {
        return m.frames().stream().mapToInt(f -> (int) f.payloadLength()).sum();
    }

    @Test
    void withContextTakeoverBothWaysFiltersSeePlaintext() throws Exception {
        startRewriting(MicroProxy.bootstrap());
        try (WebSocketPeer.Server server = new WebSocketPeer.Server("permessage-deflate");
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), OFFER)) {
            assertEquals("permessage-deflate", header(client.head, "Sec-WebSocket-Extensions"));
            assertEquals(OFFER, header(server.requests.getFirst(), "Sec-WebSocket-Extensions"));
            String text = "ping hello, a message long enough to be worth compressing, hello again";
            for (int i = 0; i < 2; i++) {
                client.sendText(text);
                Message echo = client.readMessage();
                assertTrue(echo.compressed());
                assertEquals("echo:" + text.replace("hello", "HELLO"), echo.text());
            }
            List<Message> received = new ArrayList<>(server.received);
            assertTrue(received.stream().allMatch(Message::compressed));
            assertEquals(List.of(text.replace("hello", "HELLO"), text.replace("hello", "HELLO")), server.texts());
            // The proxy's own context carries over: the repeat costs a fraction of the first.
            assertTrue(frameBytes(received.get(1)) < frameBytes(received.get(0)) / 2,
                    frameBytes(received.get(0)) + " then " + frameBytes(received.get(1)));
            assertEquals(List.of("> " + text, "< echo:" + text.replace("hello", "HELLO"), "> " + text,
                    "< echo:" + text.replace("hello", "HELLO")), seen);
        }
    }

    @Test
    void withoutContextTakeoverEveryMessageStandsAlone() throws Exception {
        startRewriting(MicroProxy.bootstrap());
        // Each peer resets its decompressor after every message, so a proxy that kept its
        // context would send data they cannot read.
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(
                        "permessage-deflate; server_no_context_takeover; client_no_context_takeover");
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(),
                        "permessage-deflate; server_no_context_takeover; client_no_context_takeover")) {
            String text = "ping hello, the same words again and again, the same words again and again";
            List<Message> echoes = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                client.sendText(text);
                echoes.add(client.readMessage());
                assertEquals("echo:" + text.replace("hello", "HELLO"), echoes.getLast().text());
            }
            assertEquals(3, server.received.size());
            for (Message m : server.received) {
                assertTrue(m.compressed());
                assertArrayEquals(server.received.getFirst().frames().getFirst().payload(), m.frames().getFirst().payload());
            }
            for (Message m : echoes) {
                assertArrayEquals(echoes.getFirst().frames().getFirst().payload(), m.frames().getFirst().payload());
            }
        }
    }

    @Test
    void contextTakeoverIsDecidedPerDirection() throws Exception {
        startRewriting(MicroProxy.bootstrap());
        // The client resets after each message (and so must the proxy towards the server); the
        // server keeps its context (and so may the proxy towards the client).
        try (WebSocketPeer.Server server = new WebSocketPeer.Server("permessage-deflate; client_no_context_takeover");
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), OFFER)) {
            String text = "ping hello, the same words again and again, the same words again and again";
            List<Message> echoes = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                client.sendText(text);
                echoes.add(client.readMessage());
            }
            assertEquals(List.of("echo:" + text.replace("hello", "HELLO")),
                    echoes.stream().map(Message::text).distinct().toList());
            assertEquals(1, server.received.stream().map(m -> new String(m.frames().getFirst().payload(),
                    StandardCharsets.ISO_8859_1)).distinct().count(), "towards the server: no context");
            assertTrue(frameBytes(echoes.get(1)) < frameBytes(echoes.get(0)) / 2, "towards the client: context");
        }
    }

    @Test
    void smallWindowsGetNoBackReferencesFromTheProxy() throws Exception {
        startRewriting(MicroProxy.bootstrap());
        byte[] block = new byte[2048];
        new Random(7).nextBytes(block);
        byte[] payload = new byte[block.length * 4];
        for (int i = 0; i < 4; i++) System.arraycopy(block, 0, payload, i * block.length, block.length);
        String answer = "permessage-deflate; server_max_window_bits=10; client_max_window_bits=9";
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(answer);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(),
                        "permessage-deflate; client_max_window_bits; server_max_window_bits=10")) {
            // The parameters reach both peers as they agreed them.
            assertEquals("permessage-deflate; client_max_window_bits; server_max_window_bits=10",
                    header(server.requests.getFirst(), "Sec-WebSocket-Extensions"));
            assertEquals(answer, header(client.head, "Sec-WebSocket-Extensions"));
            // These peers compress with a full window anyway; the proxy reads that regardless.
            client.sendMessage(WebSocketFrame.OPCODE_BINARY, payload, true, 1);
            Message echo = client.readMessage();
            assertArrayEquals(payload, echo.payload());
            Message atServer = server.received.getFirst();
            assertArrayEquals(payload, atServer.payload());
            assertTrue(atServer.compressed() && echo.compressed());
            // What the proxy compressed needs no more history than each receiver agreed to keep.
            assertTrue(WebSocketPeer.maxDistance(atServer.frames().getFirst().payload()) <= 1 << 9);
            assertTrue(WebSocketPeer.maxDistance(echo.frames().getFirst().payload()) <= 1 << 10);
            // ...where a full window would have referred back 2 KiB.
            byte[] full = WebSocketPeer.client(null, null, WebSocketPeer.Agreement.parse("permessage-deflate"))
                    .compress(payload);
            assertEquals(2048, WebSocketPeer.maxDistance(full));
        }
    }

    @Test
    void frameFiltersSeeEachFrameInflatedAndTheProxyCompressesThemAgain() throws Exception {
        List<String> frames = new CopyOnWriteArrayList<>();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(HttpFilters.builder()
                .onWebSocketFrame((frame, fromClient) -> {
                    if (!fromClient || frame.opcode() >= WebSocketFrame.OPCODE_CLOSE) return frame;
                    frames.add(frame.opcode() + "/" + frame.rsv() + "/" + frame.payloadAsText());
                    return frame.withText(frame.payloadAsText().toUpperCase());
                }).build()).start();
        try (WebSocketPeer.Server server = new WebSocketPeer.Server("permessage-deflate");
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), OFFER)) {
            String text = "ping: frames of a compressed message, compressed as one and split in three";
            // The compressed bytes are split, so no frame holds a whole DEFLATE block.
            client.sendMessage(WebSocketFrame.OPCODE_TEXT, text.getBytes(StandardCharsets.UTF_8), true, 3);
            Message echo = client.readMessage();
            assertEquals("echo:" + text.toUpperCase(), echo.text());
            assertEquals(text, frames.stream().map(f -> f.substring(f.indexOf('/', 2) + 1)).reduce("", String::concat));
            assertTrue(frames.stream().allMatch(f -> f.matches("[01]/0/.*")), frames.toString());
            Message atServer = server.received.getFirst();
            assertTrue(atServer.compressed());
            assertEquals(3, atServer.frames().size(), "frames are relayed one by one");
            assertEquals(4, atServer.frames().getFirst().rsv());
            assertEquals(0, atServer.frames().get(1).rsv());
            assertEquals(text.toUpperCase(), atServer.text());
        }
    }

    @Test
    void aCompressionBombClosesBothSidesWith1009() throws Exception {
        for (boolean messages : new boolean[] {true, false}) {
            HttpFiltersBuilder filters = HttpFilters.builder();
            if (messages) {
                filters.onWebSocketMessage((m, c) -> m);
            } else {
                filters.onWebSocketFrame((f, c) -> f);
            }
            proxy = MicroProxy.bootstrap().withPort(0).withMaxWebSocketMessageSize(64 * 1024)
                    .withFiltersSource(filters.build()).start();
            try (WebSocketPeer.Server server = new WebSocketPeer.Server("permessage-deflate");
                    WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), OFFER)) {
                client.sendMessage(WebSocketFrame.OPCODE_BINARY, new byte[60 * 1024], true, 1);
                assertEquals(60 * 1024, client.readMessage().payload().length, "under the limit");
                byte[] compressed = client.compress(new byte[1 << 20]);
                assertTrue(compressed.length < 64 * 1024);
                for (WebSocketFrame f : WebSocketPeer.messageFrames(WebSocketFrame.OPCODE_BINARY, compressed, true, 4)) {
                    client.send(f);
                }
                Message close = client.readMessage();
                assertEquals(1009, close.closeCode(), "with " + (messages ? "a message" : "a frame") + " hook");
                eventually("the server to get the close", () -> server.received.size() == 2);
                assertEquals(1009, server.received.get(1).closeCode());
            }
            proxy.abort();
        }
    }

    @Test
    void invalidCompressedDataClosesWith1002() throws Exception {
        startRewriting(MicroProxy.bootstrap());
        try (WebSocketPeer.Server server = new WebSocketPeer.Server("permessage-deflate");
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), OFFER)) {
            client.send(WebSocketFrame.of(true, 4, WebSocketFrame.OPCODE_TEXT, new byte[] {(byte) 0xff, (byte) 0xfe, 1}));
            assertEquals(1002, client.readMessage().closeCode());
        }
    }

    @Test
    void uncompressedMessagesStayUncompressed() throws Exception {
        startRewriting(MicroProxy.bootstrap());
        try (WebSocketPeer.Server server = new WebSocketPeer.Server("permessage-deflate");
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), OFFER)) {
            server.compressReplies = false;
            client.sendMessage(WebSocketFrame.OPCODE_TEXT, "ping hello plain".getBytes(StandardCharsets.UTF_8), false, 2);
            Message echo = client.readMessage();
            assertFalse(echo.compressed());
            assertEquals("echo:ping HELLO plain", echo.text());
            assertFalse(server.received.getFirst().compressed());
            assertEquals(List.of("> ping hello plain", "< echo:ping HELLO plain"), seen);
        }
    }

    @Test
    void repliesFromFiltersAreCompressedTowardsTheirPeer() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource((request, ctx) -> new HttpFilters() {
            @Override
            public List<WebSocketMessage> filterWebSocketMessages(WebSocketMessage message, boolean fromClient) {
                return fromClient ? List.of(message.withText("answered by the proxy").withFromClient(false))
                        : List.of(message);
            }
        }).start();
        try (WebSocketPeer.Server server = new WebSocketPeer.Server("permessage-deflate");
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), OFFER)) {
            client.sendMessage(WebSocketFrame.OPCODE_TEXT, "question".getBytes(StandardCharsets.UTF_8), false, 1);
            Message reply = client.readMessage();
            assertTrue(reply.compressed());
            assertEquals("answered by the proxy", reply.text());
            assertTrue(server.received.isEmpty());
        }
    }

    @Test
    void offersKeepOnlyWhatTheRelayCanRead() throws Exception {
        startRewriting(MicroProxy.bootstrap());
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(),
                        "x-webkit-deflate-frame, permessage-deflate; client_max_window_bits, permessage-deflate; foo=1")) {
            assertEquals(OFFER, header(server.requests.getFirst(), "Sec-WebSocket-Extensions"));
            client.sendText("ping");
            assertEquals("echo:ping", client.readMessage().text());
        }
        // Nothing usable: no offer at all.
        try (WebSocketPeer.Server server = new WebSocketPeer.Server(null);
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), "x-webkit-deflate-frame")) {
            assertNull(header(server.requests.getFirst(), "Sec-WebSocket-Extensions"));
        }
    }

    @Test
    void anExtensionTheProxyCannotReadLeavesFramesAsTheyAre() throws Exception {
        startRewriting(MicroProxy.bootstrap());
        try (WebSocketPeer.Server server = new WebSocketPeer.Server("x-mystery");
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), OFFER)) {
            client.sendText("ping hello");
            assertEquals("echo:ping hello", client.readMessage().text());
            assertTrue(seen.isEmpty(), seen.toString());
        }
    }

    @Test
    void withoutFiltersCompressedFramesPassByteForByte() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).start();
        try (WebSocketPeer.Server server = new WebSocketPeer.Server("permessage-deflate");
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), OFFER)) {
            assertEquals("permessage-deflate", header(client.head, "Sec-WebSocket-Extensions"));
            byte[] compressed = client.compress("ping raw".getBytes(StandardCharsets.UTF_8));
            client.send(WebSocketFrame.of(true, 4, WebSocketFrame.OPCODE_TEXT, compressed));
            assertEquals("echo:ping raw", client.readMessage().text());
            assertArrayEquals(compressed, server.received.getFirst().frames().getFirst().payload());
        }
    }

    @Test
    void framesOnlyWatchedArePassedCompressed() throws Exception {
        List<Integer> rsv = new CopyOnWriteArrayList<>();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource((request, ctx) -> new HttpFilters() {
            @Override
            public void webSocketFrameReceived(WebSocketFrame frame, boolean fromClient) {
                if (fromClient) rsv.add(frame.rsv());
            }
        }).start();
        try (WebSocketPeer.Server server = new WebSocketPeer.Server("permessage-deflate");
                WebSocketPeer client = WebSocketPeer.connect(proxy, server.port(), OFFER)) {
            byte[] compressed = client.compress("ping watched".getBytes(StandardCharsets.UTF_8));
            client.send(WebSocketFrame.of(true, 4, WebSocketFrame.OPCODE_TEXT, compressed));
            assertEquals("echo:ping watched", client.readMessage().text());
            assertArrayEquals(compressed, server.received.getFirst().frames().getFirst().payload());
            assertEquals(List.of(4), rsv);
            assertNotNull(header(server.requests.getFirst(), "Sec-WebSocket-Extensions"));
        }
    }
}
