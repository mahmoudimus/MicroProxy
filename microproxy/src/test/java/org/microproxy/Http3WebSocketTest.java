package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;
import static org.microproxy.TestSupport.write;
import static org.microproxy.WebSocketTestSupport.header;
import static org.microproxy.WebSocketTestSupport.readFrame;
import static org.microproxy.WebSocketTestSupport.sendFromClient;

import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3ErrorCode;
import io.github.mahmoudimus.quic.QuicStreamException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.WebSocketTestSupport.EchoServer;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.WebSocketFrame;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * WebSockets over HTTP/3 (RFC 9220): a client's extended {@code CONNECT} with {@code :protocol
 * websocket}, on a forward proxy's or a reverse proxy's HTTP/3 listener, reaches an HTTP/1.1
 * WebSocket server as an upgrade; filters see it as one, frames and messages go through the same
 * hooks as HTTP/1 upgrades (permessage-deflate included), and either side's end or reset ends the
 * other's.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class Http3WebSocketTest {

    private static final SelfSignedSslContextSource TLS = new SelfSignedSslContextSource();

    private HttpProxyServer proxy;
    private H3TestClient client;

    @AfterEach
    void tearDown() {
        if (client != null) client.close();
        if (proxy != null) proxy.abort();
    }

    private static HttpProxyServerBootstrap forwardProxy() {
        return MicroProxy.bootstrap().withPort(0).withProxyAlias("ws3").withSslContextSource(TLS).withHttp3(true);
    }

    private H3TestClient client() throws IOException {
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        client = H3TestClient.connect(address, "localhost", TLS.getCertificate());
        return client;
    }

    private static List<HeaderField> webSocket(TestSupport.RawServer server, String path, HeaderField... fields) {
        return H3TestClient.extendedConnect("websocket", "http", "127.0.0.1:" + server.port(), path,
                fields.length == 0 ? new HeaderField[] {new HeaderField("sec-websocket-version", "13")} : fields);
    }

    @Test
    void anExtendedConnectReachesAnHttp11ServerAsAnUpgrade() throws Exception {
        proxy = forwardProxy().start();
        try (EchoServer server = new EchoServer()) {
            H3TestClient c = client();
            assertTrue(c.serverSettings().enableConnectProtocol(), "SETTINGS_ENABLE_CONNECT_PROTOCOL");
            H3TestClient.Tunnel ws = c.open(webSocket(server.raw(), "/chat?room=1",
                    new HeaderField("sec-websocket-version", "13"),
                    new HeaderField("sec-websocket-protocol", "chat, superchat"),
                    new HeaderField("origin", "http://example.test")));
            assertEquals(200, ws.status);
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
            assertEquals(24, header(upgrade, "Sec-WebSocket-Key").length(), upgrade);
            assertEquals("chat, superchat", header(upgrade, "Sec-WebSocket-Protocol"));
            assertEquals("http://example.test", header(upgrade, "Origin"));
            assertEquals("127.0.0.1:" + server.raw().port(), header(upgrade, "Host"));
            assertEquals("3 ws3", header(upgrade, "Via"));
            assertTrue(server.received.getFirst().isMasked());

            sendFromClient(ws.out(), WebSocketFrame.close(1000, "done"));
            assertTrue(readFrame(ws.in()).isClose());
            // The server closed its connection after its close frame: the stream's FIN.
            assertEquals(-1, ws.in().read());
            ws.end();
            eventually("the server connection to end", () -> server.ended.get() == 1);
        }
    }

    @Test
    void framesAreFilteredAsForHttp1Upgrades() throws Exception {
        List<String> requests = new CopyOnWriteArrayList<>();
        List<String> responses = new CopyOnWriteArrayList<>();
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = forwardProxy().withFiltersSource((original, ctx) -> new HttpFiltersAdapter(original, ctx) {
            @Override
            public HttpResponse clientToProxyRequest(HttpObject o) {
                if (o instanceof HttpRequest r) {
                    requests.add(r.method() + " " + r.uri() + " " + r.protocolVersion() + " upgrade=" + r.headers().get("Upgrade"));
                }
                return null;
            }

            @Override
            public HttpObject proxyToClientResponse(HttpObject o) {
                if (o instanceof HttpResponse r) responses.add(r.status().code() + " " + r.headers().get("Upgrade"));
                return o;
            }

            @Override
            public void webSocketFrameReceived(WebSocketFrame frame, boolean fromClient) {
                if (frame.isText()) seen.add((fromClient ? "> " : "< ") + frame.payloadAsText());
            }

            @Override
            public WebSocketFrame filterWebSocketFrame(WebSocketFrame frame, boolean fromClient) {
                if (!frame.isText()) return frame;
                String text = frame.payloadAsText();
                if (fromClient && text.contains("secret")) return null;
                return fromClient ? frame.withText(text.toUpperCase(Locale.ROOT)) : frame.withText(text + " (filtered)");
            }

        }).start();
        try (EchoServer server = new EchoServer()) {
            H3TestClient.Tunnel ws = client().open(webSocket(server.raw(), "/chat"));
            assertEquals(200, ws.status);
            sendFromClient(ws.out(), WebSocketFrame.text("hello"));
            sendFromClient(ws.out(), WebSocketFrame.text("my secret"));
            sendFromClient(ws.out(), WebSocketFrame.text("ping"));
            assertEquals("echo:PING (filtered)", readFrame(ws.in()).payloadAsText());
            sendFromClient(ws.out(), WebSocketFrame.close(1000, ""));
            assertTrue(readFrame(ws.in()).isClose());
            ws.end();

            List<String> texts = server.received.stream().map(f -> f.isClose() ? "<close>" : f.payloadAsText()).toList();
            assertEquals(List.of("HELLO", "PING", "<close>"), texts);
            String target = "http://127.0.0.1:" + server.raw().port() + "/chat";
            assertEquals(List.of("GET " + target + " HTTP/3.0 upgrade=websocket"), requests);
            assertEquals(List.of("101 websocket"), responses);
            assertEquals(List.of("> hello", "> my secret", "> ping", "< echo:PING"), seen);
        }
    }

    @Test
    void messagesAreJoinedAndInflatedWithPermessageDeflate() throws Exception {
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = forwardProxy().withFiltersSource(HttpFilters.builder().onWebSocketMessage((m, fromClient) -> {
            seen.add((fromClient ? "> " : "< ") + m.text());
            return fromClient ? m.withText(m.text().toUpperCase(Locale.ROOT)) : m;
        }).build()).start();
        try (WebSocketPeer.Server server = new WebSocketPeer.Server("permessage-deflate; client_no_context_takeover")) {
            H3TestClient.Tunnel ws = client().open(webSocket(server.raw(), "/chat",
                    new HeaderField("sec-websocket-version", "13"),
                    new HeaderField("sec-websocket-extensions", "permessage-deflate; client_max_window_bits")));
            assertEquals(200, ws.status);
            String agreed = ws.header("sec-websocket-extensions");
            assertEquals("permessage-deflate; client_no_context_takeover", agreed);
            WebSocketPeer peer = WebSocketPeer.client(ws.in(), ws.out(), WebSocketPeer.Agreement.parse(agreed));
            for (int i = 0; i < 2; i++) {
                peer.sendMessage(WebSocketFrame.OPCODE_TEXT, "ping over h3, ping over h3".getBytes(), true, 3);
                WebSocketPeer.Message echo = peer.readMessage();
                assertTrue(echo.compressed());
                assertEquals("echo:PING OVER H3, PING OVER H3", echo.text());
            }
            assertEquals(List.of("> ping over h3, ping over h3", "< echo:PING OVER H3, PING OVER H3",
                    "> ping over h3, ping over h3", "< echo:PING OVER H3, PING OVER H3"), seen);
            ws.reset(Http3ErrorCode.H3_REQUEST_CANCELLED.code());
        }
    }

    @Test
    void aClientResetClosesTheServerConnection() throws Exception {
        proxy = forwardProxy().start();
        try (EchoServer server = new EchoServer()) {
            H3TestClient.Tunnel ws = client().open(webSocket(server.raw(), "/chat"));
            assertEquals(200, ws.status);
            sendFromClient(ws.out(), WebSocketFrame.text("ping"));
            assertEquals("echo:ping", readFrame(ws.in()).payloadAsText());
            ws.reset(Http3ErrorCode.H3_REQUEST_CANCELLED.code());
            eventually("the server connection to close", () -> server.ended.get() == 1);
        }
    }

    @Test
    void aServerThatResetsItsConnectionCancelsTheStream() throws Exception {
        proxy = forwardProxy().start();
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
            String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
            write(s.getOutputStream(), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    + "Sec-WebSocket-Accept: " + WebSocketTestSupport.accept(header(head, "Sec-WebSocket-Key")) + "\r\n\r\n");
            readFrame(s.getInputStream());
            s.setSoLinger(true, 0); // close with a TCP reset
        })) {
            H3TestClient.Tunnel ws = client().open(webSocket(origin, "/chat"));
            assertEquals(200, ws.status);
            sendFromClient(ws.out(), WebSocketFrame.text("bye"));
            QuicStreamException reset = assertThrows(QuicStreamException.class, ws::readAll);
            assertEquals(Http3ErrorCode.H3_REQUEST_CANCELLED.code(), reset.errorCode());
        }
    }

    @Test
    void aRefusedUpgradeIsAnOrdinaryResponse() throws Exception {
        proxy = forwardProxy().start();
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
            TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
            write(s.getOutputStream(), "HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno");
        })) {
            H3TestClient.Tunnel ws = client().open(webSocket(origin, "/chat"));
            assertEquals(403, ws.status);
            assertEquals("no", ws.text());
        }
    }

    @Test
    void otherExtendedConnectProtocolsGet501() throws Exception {
        proxy = forwardProxy().start();
        H3TestClient.Tunnel t = client().open(H3TestClient.extendedConnect("webtransport", "https", "localhost:1", "/"));
        assertEquals(501, t.status);
    }

    @Test
    void aReverseProxyServesWebSocketsOverHttp3ToItsUpstream() throws Exception {
        try (EchoServer server = new EchoServer()) {
            proxy = MicroProxy.bootstrap().withPort(0).withReverseProxy("http://127.0.0.1:" + server.raw().port())
                    .withSslContextSource(TLS).withHttp3(true).start();
            H3TestClient.Tunnel ws = client().open(H3TestClient.extendedConnect("websocket", "https",
                    "localhost:" + proxy.getListenAddress().getPort(), "/reverse",
                    new HeaderField("sec-websocket-version", "13")));
            assertEquals(200, ws.status);
            sendFromClient(ws.out(), WebSocketFrame.text("ping over the reverse proxy"));
            assertEquals("echo:ping over the reverse proxy", readFrame(ws.in()).payloadAsText());
            assertTrue(server.upgradeRequest.startsWith("GET /reverse HTTP/1.1\r\n"), server.upgradeRequest);
            ws.reset(Http3ErrorCode.H3_REQUEST_CANCELLED.code());
        }
    }
}
