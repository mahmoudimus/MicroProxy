package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;
import static org.microproxy.TestSupport.write;
import static org.microproxy.WebSocketTestSupport.header;
import static org.microproxy.WebSocketTestSupport.readFrame;
import static org.microproxy.WebSocketTestSupport.sendFromClient;

import io.github.mahmoudimus.http2.ErrorCode;
import io.github.mahmoudimus.http2.HeaderField;
import io.github.mahmoudimus.http2.Http2Settings;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.WebSocketTestSupport.EchoServer;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.WebSocketFrame;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * WebSockets over HTTP/2 (RFC 8441): a client's extended {@code CONNECT} reaches an HTTP/1.1
 * WebSocket server as an upgrade, or an HTTP/2 server that allows extended {@code CONNECT} as
 * one; frames are filtered as for HTTP/1 upgrades, flow control holds both ways, and either side's
 * end or reset ends the other's.
 */
@Timeout(60)
class Http2WebSocketTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("H2 WebSocket Origin CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("H2 WebSocket Proxy CA");

    private HttpProxyServer proxy;
    private H2TestOrigin h2Origin;

    @AfterEach
    void tearDown() throws IOException {
        if (proxy != null) proxy.abort();
        if (h2Origin != null) h2Origin.close();
    }

    private static HttpProxyServerBootstrap h2c() {
        return MicroProxy.bootstrap().withPort(0).withProxyAlias("ws2").withHttp2Cleartext(true);
    }

    private H2StreamClient client(TestSupport.RawServer origin) throws IOException {
        return H2StreamClient.cleartext(proxy.getListenAddress(), "127.0.0.1:" + origin.port());
    }

    // -------------------------------------------------------------------------------------------
    // To HTTP/1.1 WebSocket servers
    // -------------------------------------------------------------------------------------------

    @Test
    void anExtendedConnectReachesAnHttp11ServerAsAnUpgrade() throws Exception {
        proxy = h2c().start();
        try (EchoServer server = new EchoServer(); H2StreamClient c = client(server.raw())) {
            assertEquals(1L, c.setting(Http2Settings.ENABLE_CONNECT_PROTOCOL));
            H2StreamClient.Stream ws = c.open(c.webSocket("/chat?room=1", "sec-websocket-protocol", "chat, superchat",
                    "origin", "http://example.test"), false);
            assertEquals(200, ws.status());
            // The server's choice of subprotocol comes back; the HTTP/1.1 handshake's own fields do not.
            assertEquals("chat", ws.header("sec-websocket-protocol"));
            assertNull(ws.header("sec-websocket-accept"));
            assertNull(ws.header("content-length"));

            sendFromClient(ws.out(), WebSocketFrame.text("ping 1"));
            WebSocketFrame echo = readFrame(ws.in());
            assertEquals("echo:ping 1", echo.payloadAsText());
            assertFalse(echo.isMasked());

            String upgrade = server.upgradeRequest;
            assertTrue(upgrade.startsWith("GET /chat?room=1 HTTP/1.1\r\n"), upgrade);
            assertEquals("websocket", header(upgrade, "Upgrade"));
            assertEquals("Upgrade", header(upgrade, "Connection"));
            assertEquals("13", header(upgrade, "Sec-WebSocket-Version"));
            assertEquals(24, header(upgrade, "Sec-WebSocket-Key").length(), upgrade);
            assertEquals("chat, superchat", header(upgrade, "Sec-WebSocket-Protocol"));
            assertEquals("http://example.test", header(upgrade, "Origin"));
            assertEquals("127.0.0.1:" + server.raw().port(), header(upgrade, "Host"));
            assertEquals("2 ws2", header(upgrade, "Via"));
            // Client frames stay masked over HTTP/2, as RFC 8441 requires.
            assertTrue(server.received.getFirst().isMasked());
        }
    }

    @Test
    void theCloseHandshakeEndsTheStreamInBothDirections() throws Exception {
        proxy = h2c().start();
        try (EchoServer server = new EchoServer(); H2StreamClient c = client(server.raw())) {
            H2StreamClient.Stream ws = c.open(c.webSocket("/chat"), false);
            assertEquals(200, ws.status());
            sendFromClient(ws.out(), WebSocketFrame.close(1000, "done"));
            WebSocketFrame reply = readFrame(ws.in());
            assertTrue(reply.isClose());
            // The server closed its connection after its close frame: END_STREAM.
            assertEquals(-1, ws.in().read());
            ws.end();
            assertNull(ws.awaitEnd());
            eventually("the server connection to end", () -> server.ended.get() == 1);
            // Both sides ended cleanly: the stream was never reset.
            H2StreamClient.Stream next = c.open(c.webSocket("/again"), false);
            assertEquals(200, next.status());
            assertNull(ws.awaitEnd());
            next.reset(ErrorCode.CANCEL);
        }
    }

    @Test
    void withoutFrameFiltersBytesAreRelayedAsTheyCome() throws Exception {
        proxy = h2c().start();
        AtomicInteger bytes = new AtomicInteger();
        List<String> upgrades = new CopyOnWriteArrayList<>();
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
                    String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
                    upgrades.add(head);
                    write(s.getOutputStream(), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                            + "Sec-WebSocket-Accept: " + WebSocketTestSupport.accept(header(head, "Sec-WebSocket-Key"))
                            + "\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n");
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = s.getInputStream().read(buf)) > 0) bytes.addAndGet(n);
                });
                H2StreamClient c = client(origin)) {
            H2StreamClient.Stream ws = c.open(c.webSocket("/raw", "sec-websocket-extensions", "permessage-deflate"), false);
            assertEquals(200, ws.status());
            assertEquals("permessage-deflate", ws.header("sec-websocket-extensions"));
            // Half a frame reaches the server at once: nothing waits to parse whole frames.
            byte[] frame = WebSocketFrame.binary(new byte[1000]).toWire(true);
            ws.out().write(frame, 0, 500);
            eventually("half a frame to reach the server", () -> bytes.get() == 500);
            ws.out().write(frame, 500, frame.length - 500);
            eventually("the rest of the frame", () -> bytes.get() == frame.length);
            assertEquals("permessage-deflate", header(upgrades.getFirst(), "Sec-WebSocket-Extensions"));
            ws.reset(ErrorCode.CANCEL);
        }
    }

    @Test
    void aLargeMessageFlowsUnderFlowControlOnTheFastPath() throws Exception {
        proxy = h2c().start();
        largeMessageThroughAnEchoServer();
    }

    @Test
    void aLargeMessageFlowsUnderFlowControlWhenFramesAreParsed() throws Exception {
        AtomicInteger frames = new AtomicInteger();
        proxy = h2c().withFiltersSource((original, ctx) -> new HttpFiltersAdapter(original, ctx) {
            @Override
            public void webSocketFrameReceived(WebSocketFrame frame, boolean fromClient) {
                frames.incrementAndGet();
            }
        }).start();
        largeMessageThroughAnEchoServer();
        assertEquals(4, frames.get()); // the binary frame and its echo, the close frame and its answer
    }

    /** Sends a 900 KB binary message, much larger than any window, and reads its echo meanwhile. */
    private void largeMessageThroughAnEchoServer() throws Exception {
        byte[] payload = H2TestOrigin.bytes(900_000, 7);
        try (EchoServer server = new EchoServer(); H2StreamClient c = client(server.raw())) {
            server.echoBinary = true;
            H2StreamClient.Stream ws = c.open(c.webSocket("/large"), false);
            assertEquals(200, ws.status());
            CompletableFuture<WebSocketFrame> echo = CompletableFuture.supplyAsync(() -> {
                try {
                    return readFrame(ws.in());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            sendFromClient(ws.out(), WebSocketFrame.binary(payload));
            WebSocketFrame back = echo.get(30, TimeUnit.SECONDS);
            assertArrayEquals(payload, back.payload());
            assertArrayEquals(payload, server.received.getFirst().payload());
            sendFromClient(ws.out(), WebSocketFrame.close(1000, ""));
            assertTrue(readFrame(ws.in()).isClose());
            ws.end();
            assertNull(ws.awaitEnd());
        }
    }

    @Test
    void aClientResetClosesTheServerConnection() throws Exception {
        proxy = h2c().start();
        try (EchoServer server = new EchoServer(); H2StreamClient c = client(server.raw())) {
            H2StreamClient.Stream ws = c.open(c.webSocket("/chat"), false);
            assertEquals(200, ws.status());
            sendFromClient(ws.out(), WebSocketFrame.text("ping"));
            assertEquals("echo:ping", readFrame(ws.in()).payloadAsText());
            ws.reset(ErrorCode.CANCEL);
            eventually("the server connection to close", () -> server.ended.get() == 1);
        }
    }

    @Test
    void aServerThatResetsItsConnectionResetsTheStream() throws Exception {
        proxy = h2c().start();
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
                    String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
                    write(s.getOutputStream(), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                            + "Sec-WebSocket-Accept: " + WebSocketTestSupport.accept(header(head, "Sec-WebSocket-Key")) + "\r\n\r\n");
                    readFrame(s.getInputStream());
                    s.setSoLinger(true, 0); // close with a TCP reset
                });
                H2StreamClient c = client(origin)) {
            H2StreamClient.Stream ws = c.open(c.webSocket("/chat"), false);
            assertEquals(200, ws.status());
            sendFromClient(ws.out(), WebSocketFrame.text("bye"));
            assertEquals(ErrorCode.CANCEL, ws.awaitReset());
        }
    }

    @Test
    void aRefusedUpgradeIsAnOrdinaryResponse() throws Exception {
        proxy = h2c().start();
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
                    TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
                    write(s.getOutputStream(), "HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\nno way");
                });
                H2StreamClient c = client(origin)) {
            H2StreamClient.Stream ws = c.open(c.webSocket("/chat"), false);
            assertEquals(403, ws.status());
            assertEquals("no way", ws.text());
        }
    }

    // -------------------------------------------------------------------------------------------
    // To HTTP/2 servers that allow extended CONNECT
    // -------------------------------------------------------------------------------------------

    /** Request heads an extended-CONNECT origin received, and the frames it read. */
    private final List<List<HeaderField>> originHeads = new CopyOnWriteArrayList<>();
    private final List<WebSocketFrame> originFrames = new CopyOnWriteArrayList<>();

    /**
     * An HTTP/2 origin that allows extended CONNECT and serves WebSockets on such streams: text
     * frames starting with {@code ping} are answered with {@code echo:} and the text, binary frames
     * with the same payload, a close frame with a close frame and END_STREAM.
     */
    private H2TestOrigin extendedConnectOrigin(boolean eagerCredit) throws IOException {
        H2TestOrigin.Options options = new H2TestOrigin.Options();
        options.enableConnectProtocol = true;
        options.eagerCredit = eagerCredit;
        h2Origin = new H2TestOrigin(originCa.serverContext("localhost", "127.0.0.1"), options, s -> {
            originHeads.add(s.headers);
            if (!"CONNECT".equals(s.header(":method")) || !"websocket".equals(s.header(":protocol"))) {
                s.respond(400, true);
                return;
            }
            s.respond(200, false, "sec-websocket-protocol", "chat");
            InputStream in = s.input();
            while (true) {
                WebSocketFrame frame;
                try {
                    frame = readFrame(in);
                } catch (java.io.EOFException e) {
                    s.data(new byte[0], true);
                    return;
                }
                originFrames.add(frame);
                if (frame.isClose()) {
                    s.data(WebSocketFrame.close(1000, "bye").toWire(false), true);
                    return;
                }
                if (frame.isText() && frame.payloadAsText().startsWith("ping")) {
                    s.data(WebSocketFrame.text("echo:" + frame.payloadAsText()).toWire(false), false);
                } else if (frame.isBinary()) {
                    s.data(WebSocketFrame.binary(frame.payload()).toWire(false), false);
                }
            }
        });
        return h2Origin;
    }

    private static HttpProxyServerBootstrap mitm() {
        return MicroProxy.bootstrap().withPort(0).withProxyAlias("ws2")
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp2(true).withHttp2Upstream(true);
    }

    private static String value(List<HeaderField> fields, String name) {
        for (HeaderField f : fields) {
            if (f.name().equals(name)) return f.value();
        }
        return null;
    }

    @Test
    void anHttp2ClientsWebSocketIsAnExtendedConnectStreamToAnHttp2Server() throws Exception {
        H2TestOrigin origin = extendedConnectOrigin(true);
        List<String> requests = new CopyOnWriteArrayList<>();
        proxy = mitm().withFiltersSource((original, ctx) -> new HttpFiltersAdapter(original, ctx) {
            @Override
            public HttpResponse clientToProxyRequest(HttpObject o) {
                if (o instanceof HttpRequest r) requests.add(r.method() + " " + r.uri() + " " + r.headers().get("Upgrade"));
                return null;
            }

            @Override
            public WebSocketFrame filterWebSocketFrame(WebSocketFrame frame, boolean fromClient) {
                return frame.isText() && !fromClient ? frame.withText(frame.payloadAsText() + "!") : frame;
            }
        }).start();
        String target = "localhost:" + origin.port();
        try (H2StreamClient c = H2StreamClient.intercepted(proxy.getListenAddress(), target, proxyCa.clientContext())) {
            H2StreamClient.Stream ws = c.open(c.webSocket("/chat", "sec-websocket-protocol", "chat"), false);
            assertEquals(200, ws.status());
            assertEquals("chat", ws.header("sec-websocket-protocol"));
            sendFromClient(ws.out(), WebSocketFrame.text("ping"));
            WebSocketFrame echo = readFrame(ws.in());
            assertEquals("echo:ping!", echo.payloadAsText());
            assertFalse(echo.isMasked());
            sendFromClient(ws.out(), WebSocketFrame.close(1000, ""));
            assertTrue(readFrame(ws.in()).isClose());
            assertEquals(-1, ws.in().read());
            ws.end();
            assertNull(ws.awaitEnd());
        }
        List<HeaderField> head = originHeads.getFirst();
        assertEquals("CONNECT", value(head, ":method"));
        assertEquals("websocket", value(head, ":protocol"));
        assertEquals("https", value(head, ":scheme"));
        assertEquals("/chat", value(head, ":path"));
        assertEquals(target, value(head, ":authority"));
        assertEquals("13", value(head, "sec-websocket-version"));
        assertEquals("chat", value(head, "sec-websocket-protocol"));
        assertNull(value(head, "sec-websocket-key"));
        assertNull(value(head, "upgrade"));
        assertTrue(originFrames.getFirst().isMasked());
        // The CONNECT's HTTP/2 connection carried the WebSocket: one connection to the server.
        assertEquals(1, origin.accepts.get());
        assertEquals(List.of("CONNECT " + target + " null", "GET /chat websocket"), requests);
    }

    @Test
    void anInterceptedHttp2ClientsWebSocketUpgradesAnHttp11ServerOverTls() throws Exception {
        List<String> seen = new CopyOnWriteArrayList<>();
        // HTTP/2 to servers is on, but this server speaks HTTP/1.1 only (no ALPN).
        proxy = mitm().withFiltersSource((original, ctx) -> new HttpFiltersAdapter(original, ctx) {
            @Override
            public void webSocketFrameReceived(WebSocketFrame frame, boolean fromClient) {
                if (frame.isText()) seen.add((fromClient ? "> " : "< ") + frame.payloadAsText());
            }
        }).start();
        try (EchoServer server = new EchoServer(originCa.serverContext("localhost", "127.0.0.1"));
                H2StreamClient c = H2StreamClient.intercepted(proxy.getListenAddress(), "localhost:" + server.raw().port(),
                        proxyCa.clientContext())) {
            H2StreamClient.Stream ws = c.open(c.webSocket("/secure"), false);
            assertEquals(200, ws.status());
            sendFromClient(ws.out(), WebSocketFrame.text("ping wss"));
            assertEquals("echo:ping wss", readFrame(ws.in()).payloadAsText());
            sendFromClient(ws.out(), WebSocketFrame.close(1000, ""));
            assertTrue(readFrame(ws.in()).isClose());
            ws.end();
            assertNull(ws.awaitEnd());
            assertTrue(server.upgradeRequest.startsWith("GET /secure HTTP/1.1\r\n"), server.upgradeRequest);
            assertEquals(List.of("> ping wss", "< echo:ping wss"), seen);
        }
    }

    @Test
    void aLargeMessageToAnHttp2ServerUnderFlowControl() throws Exception {
        // The server credits data only as it reads it, and the client grants small windows.
        H2TestOrigin origin = extendedConnectOrigin(false);
        AtomicInteger frames = new AtomicInteger();
        proxy = mitm().withFiltersSource((original, ctx) -> new HttpFiltersAdapter(original, ctx) {
            @Override
            public void webSocketFrameReceived(WebSocketFrame frame, boolean fromClient) {
                frames.incrementAndGet();
            }
        }).start();
        byte[] payload = H2TestOrigin.bytes(700_000, 11);
        try (H2StreamClient c = H2StreamClient.intercepted(proxy.getListenAddress(), "localhost:" + origin.port(),
                proxyCa.clientContext(), 16_384)) {
            H2StreamClient.Stream ws = c.open(c.webSocket("/large"), false);
            assertEquals(200, ws.status());
            CompletableFuture<WebSocketFrame> echo = CompletableFuture.supplyAsync(() -> {
                try {
                    return readFrame(ws.in());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            sendFromClient(ws.out(), WebSocketFrame.binary(payload));
            assertArrayEquals(payload, echo.get(30, TimeUnit.SECONDS).payload());
            ws.reset(ErrorCode.CANCEL);
        }
        assertArrayEquals(payload, originFrames.getFirst().payload());
        assertEquals(2, frames.get());
    }

    @Test
    void aServerResetResetsTheClientsStream() throws Exception {
        H2TestOrigin.Options options = new H2TestOrigin.Options();
        options.enableConnectProtocol = true;
        h2Origin = new H2TestOrigin(originCa.serverContext("localhost", "127.0.0.1"), options, s -> {
            s.respond(200, false);
            readFrame(s.input());
            s.reset(ErrorCode.INTERNAL_ERROR);
        });
        proxy = mitm().start();
        try (H2StreamClient c = H2StreamClient.intercepted(proxy.getListenAddress(), "localhost:" + h2Origin.port(),
                proxyCa.clientContext())) {
            H2StreamClient.Stream ws = c.open(c.webSocket("/chat"), false);
            assertEquals(200, ws.status());
            sendFromClient(ws.out(), WebSocketFrame.text("bye"));
            assertEquals(ErrorCode.CANCEL, ws.awaitReset());
        }
    }
}
