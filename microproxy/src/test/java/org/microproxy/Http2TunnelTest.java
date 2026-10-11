package org.microproxy;

import static org.junit.jupiter.api.Assertions.*;

import io.github.mahmoudimus.http2.ErrorCode;
import io.github.mahmoudimus.http2.Frame;
import io.github.mahmoudimus.http2.HeaderField;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.http.WebSocketFrame;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/** Real stream tunnels: handshakes, frame hooks, half-close and cancellation isolation. */
class Http2TunnelTest {
    private HttpProxyServer proxy;

    @AfterEach
    void stop() {
        if (proxy != null) proxy.abort();
    }

    private HttpProxyServerBootstrap h2c() {
        return MicroProxy.bootstrap().withPort(0).withHttp2Cleartext(true);
    }

    private static List<HeaderField> connect(String authority) {
        return List.of(new HeaderField(":method", "CONNECT"), new HeaderField(":authority", authority));
    }

    private static Frame.Headers head(H2TestClient c, int id, int status) throws Exception {
        Frame f = c.awaitFrame(x -> x.streamId() == id && (x instanceof Frame.Headers || x instanceof Frame.RstStream));
        assertInstanceOf(Frame.Headers.class, f);
        Frame.Headers h = (Frame.Headers) f;
        assertEquals(Integer.toString(status), c.fields(h).stream().filter(x -> x.name().equals(":status"))
                .findFirst().orElseThrow().value());
        return h;
    }

    @Test
    void connectRelaysEarlyDataAndHalfClosesWithoutClosingTheConnection() throws Exception {
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
            byte[] request = s.getInputStream().readAllBytes();
            s.getOutputStream().write(request);
            s.getOutputStream().flush();
        })) {
            proxy = h2c().start();
            try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), "127.0.0.1:" + origin.port()).handshake()) {
                c.headers(1, connect(c.authority), false);
                byte[] bytes = "data sent before the tunnel opens".getBytes(StandardCharsets.UTF_8);
                c.data(1, bytes, true);
                H2TestClient.Response response = c.response(1);
                assertEquals(200, response.status());
                assertNull(response.reset());
                assertArrayEquals(bytes, response.body());
                // A second tunnel on the same connection, after the first has ended.
                c.headers(3, connect(c.authority), false);
                c.data(3, "second".getBytes(StandardCharsets.UTF_8), true);
                assertEquals("second", c.response(3).text());
            }
        }
    }

    @Test
    void connectPayloadLargerThanBothFlowControlWindowsIsRelayedExactly() throws Exception {
        byte[] bytes = new byte[(3 << 18) + 37];
        new java.util.Random(41).nextBytes(bytes);
        try (TestSupport.RawServer origin = TestSupport.rawServer(socket -> {
            socket.getOutputStream().write(socket.getInputStream().readAllBytes());
            socket.getOutputStream().flush();
        })) {
            proxy = h2c().start();
            try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), "127.0.0.1:" + origin.port()).handshake()) {
                c.headers(1, connect(c.authority), false);
                Http2WebSocketUpstreamTest.sendWithStreamWindow(c, 1, bytes, true);
                H2TestClient.Response response = c.response(1);
                assertEquals(200, response.status());
                assertNull(response.reset());
                assertArrayEquals(bytes, response.body());
            }
        }
    }

    @Test
    void resetClosesOnlyItsTunnelAndReleasesTheOrigin() throws Exception {
        CountDownLatch closed = new CountDownLatch(1);
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
            s.getInputStream().readAllBytes();
            closed.countDown();
        })) {
            proxy = h2c().withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
                @Override
                public org.microproxy.http.HttpResponse clientToProxyRequest(org.microproxy.http.HttpObject o) {
                    return request.method().name().equals("GET")
                            ? new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                                    "still alive".getBytes(StandardCharsets.UTF_8)) : null;
                }
            }).start();
            try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), "127.0.0.1:" + origin.port()).handshake()) {
                c.headers(1, connect(c.authority), false);
                assertFalse(head(c, 1, 200).endStream());
                c.rst(1, ErrorCode.CANCEL);
                c.get(3, "/alive");
                assertEquals("still alive", c.response(3).text());
                assertTrue(closed.await(5, TimeUnit.SECONDS), "reset must close the origin socket");
            }
        }
    }

    @Test
    void connectToANonTlsServerTunnelsEvenWhenMitmIsConfigured() throws Exception {
        // CONNECT streams are intercepted (Http2ConnectTest); a server that does not speak TLS
        // gets a plain tunnel instead, as an HTTP/1 CONNECT does (MitmNonTlsServerTest).
        CertificateAuthority ca = CertificateAuthority.generate("stream tunnel CA");
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
            s.getOutputStream().write(s.getInputStream().readNBytes(4));
            s.getOutputStream().flush();
        })) {
            proxy = h2c().withManInTheMiddle(new CertificateAuthorityMitmManager(ca)).start();
            try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), "127.0.0.1:" + origin.port()).handshake()) {
                c.headers(1, connect(c.authority), false);
                c.data(1, "raw!".getBytes(StandardCharsets.UTF_8), true);
                assertEquals("raw!", c.response(1).text());
            }
        }
    }

    @Test
    void extendedConnectUsesTheHttp1FrameHooksAndTranslatesTheHandshake() throws Exception {
        List<String> frames = new CopyOnWriteArrayList<>();
        try (WebSocketTestSupport.EchoServer origin = new WebSocketTestSupport.EchoServer()) {
            proxy = h2c().withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
                @Override
                public WebSocketFrame filterWebSocketFrame(WebSocketFrame frame, boolean fromClient) {
                    frames.add(fromClient + ":" + frame.opcode());
                    if (frame.isPing()) return null;
                    return frame.isText() ? WebSocketFrame.text(fromClient ? "ping:edited" : "reply:edited") : frame;
                }
            }).start();
            try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), "127.0.0.1:" + origin.raw().port()).handshake()) {
                assertEquals(1L, c.setting(8)); // SETTINGS_ENABLE_CONNECT_PROTOCOL
                c.headers(1, c.request("CONNECT", "/chat", ":protocol", "websocket", "sec-websocket-version", "13",
                        "sec-websocket-extensions", "permessage-deflate"), false);
                assertFalse(head(c, 1, 200).endStream(), "successful CONNECT must stay open");
                byte[] wire = WebSocketFrame.text("original").toWire(true);
                c.data(1, new byte[] {wire[0]}, false);
                c.data(1, java.util.Arrays.copyOfRange(wire, 1, wire.length), false);
                ByteArrayOutputStream response = new ByteArrayOutputStream();
                int expected = WebSocketFrame.text("reply:edited").toWire(false).length;
                while (response.size() < expected) {
                    Frame.Data data = (Frame.Data) c.awaitFrame(x -> x instanceof Frame.Data d && d.streamId() == 1);
                    assertFalse(data.endStream());
                    response.write(data.data());
                }
                WebSocketFrame reply = WebSocketTestSupport.readFrame(new ByteArrayInputStream(response.toByteArray()));
                assertEquals("reply:edited", reply.payloadAsText());
                assertEquals("ping:edited", origin.received.getFirst().payloadAsText());
                assertTrue(origin.received.getFirst().isMasked());
                assertFalse(origin.upgradeRequest.toLowerCase().contains("transfer-encoding"));
                assertFalse(origin.upgradeRequest.toLowerCase().contains("sec-websocket-extensions"));
                assertTrue(origin.upgradeRequest.startsWith("GET /chat HTTP/1.1"), origin.upgradeRequest);
                assertEquals(List.of("true:1", "false:1"), frames);
                c.data(1, WebSocketFrame.close(1000, "bye").toWire(true), true);
                c.awaitFrame(x -> x instanceof Frame.Data d && d.streamId() == 1 && d.endStream());
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"200 OK", "204 No Content", "101 Switching Protocols"})
    void anHttp1OriginMustCompleteAValidWebSocketHandshake(String status) throws Exception {
        try (TestSupport.RawServer origin = TestSupport.rawServer(socket -> {
            TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
            TestSupport.write(socket.getOutputStream(), "HTTP/1.1 " + status
                    + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n"
                    + "Content-Length: 0\r\n\r\n");
        })) {
            proxy = h2c().start();
            try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), "127.0.0.1:" + origin.port()).handshake()) {
                c.headers(1, c.request("CONNECT", "/chat", ":protocol", "websocket", "sec-websocket-version", "13"), false);
                assertEquals(502, c.response(1).status(), "invalid HTTP/1 opening handshake must not become tunnel acceptance");
            }
        }
    }

    @Test
    void unsupportedExtendedProtocolIsRejectedWithoutOpeningATcpTunnel() throws Exception {
        proxy = h2c().start();
        try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), "unresolvable.invalid:443").handshake()) {
            c.headers(1, c.request("CONNECT", "/", ":protocol", "unknown"), false);
            assertEquals(501, c.response(1).status());
        }
    }

    @Test
    void webSocketWithANonHttpSchemeIsAStreamError() throws Exception {
        proxy = h2c().start();
        try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), "unresolvable.invalid:443").handshake()) {
            List<HeaderField> fields = new java.util.ArrayList<>(c.request("CONNECT", "/chat", ":protocol", "websocket"));
            fields.set(1, new HeaderField(":scheme", "ftp"));
            c.headers(1, fields, false);
            assertEquals(ErrorCode.PROTOCOL_ERROR, c.awaitReset(1).error());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void aFilterCanRejectTheWebSocketHandshake(boolean atClient) throws Exception {
        CountDownLatch ended = new CountDownLatch(1);
        try (WebSocketTestSupport.EchoServer origin = new WebSocketTestSupport.EchoServer()) {
            proxy = h2c().withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
                @Override
                public void exchangeEnded(boolean completed) {
                    ended.countDown();
                }
                @Override
                public org.microproxy.http.HttpObject serverToProxyResponse(org.microproxy.http.HttpObject o) {
                    return atClient ? o : rejectHandshake(o);
                }
                @Override
                public org.microproxy.http.HttpObject proxyToClientResponse(org.microproxy.http.HttpObject o) {
                    return atClient ? rejectHandshake(o) : o;
                }
                private org.microproxy.http.HttpObject rejectHandshake(org.microproxy.http.HttpObject o) {
                    return o instanceof org.microproxy.http.HttpResponse
                            ? new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.valueOf(403),
                                    "denied".getBytes(StandardCharsets.UTF_8)) : o;
                }
            }).start();
            try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), "127.0.0.1:" + origin.raw().port()).handshake()) {
                c.headers(1, c.request("CONNECT", "/chat", ":protocol", "websocket", "sec-websocket-version", "13"), false);
                H2TestClient.Response r = c.response(1);
                assertEquals(403, r.status());
                assertEquals("denied", r.text());
                assertTrue(ended.await(3, TimeUnit.SECONDS), "rejected handshake must end without waiting for tunnel data");
            }
        }
    }

    @Test
    void aTunnelWithNoSendWindowDoesNotBlockAnotherStreamsResponse() throws Exception {
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
            s.getOutputStream().write(new byte[1 << 20]);
            s.getOutputStream().flush();
            s.getInputStream().readAllBytes();
        })) {
            proxy = h2c().withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
                @Override
                public org.microproxy.http.HttpResponse clientToProxyRequest(org.microproxy.http.HttpObject o) {
                    return request.method().name().equals("GET")
                            ? new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                                    "unblocked".getBytes(StandardCharsets.UTF_8)) : null;
                }
            }).start();
            try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), "127.0.0.1:" + origin.port()).handshake()) {
                c.writer.writeSettings(java.util.Map.of(4, 0L));
                c.writer.flush();
                c.awaitFrame(f -> f instanceof Frame.Settings settings && settings.ack());
                c.headers(1, connect(c.authority), false);
                assertFalse(head(c, 1, 200).endStream());
                c.get(3, "/alive");
                c.writer.writeWindowUpdate(3, 65_535);
                c.writer.flush();
                assertEquals("unblocked", c.response(3).text());
                c.rst(1, ErrorCode.CANCEL);
            }
        }
    }

    @Test
    void throwingConnectResponseFiltersReleaseTheOriginWithoutClosingOtherStreams() throws Exception {
        CountDownLatch closed = new CountDownLatch(1);
        try (TestSupport.RawServer origin = TestSupport.rawServer(socket -> {
            socket.getInputStream().readAllBytes();
            closed.countDown();
        })) {
            proxy = h2c().withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
                @Override
                public org.microproxy.http.HttpObject serverToProxyResponse(org.microproxy.http.HttpObject o) {
                    if (request.method().name().equals("CONNECT")) throw new IllegalStateException("test filter failed");
                    return o;
                }
                @Override
                public org.microproxy.http.HttpResponse clientToProxyRequest(org.microproxy.http.HttpObject o) {
                    return request.method().name().equals("GET")
                            ? new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                                    "alive".getBytes(StandardCharsets.UTF_8)) : null;
                }
            }).start();
            try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), "127.0.0.1:" + origin.port()).handshake()) {
                c.headers(1, connect(c.authority), false);
                assertEquals(ErrorCode.INTERNAL_ERROR, c.awaitReset(1).error());
                assertTrue(closed.await(5, TimeUnit.SECONDS));
                c.get(3, "/alive");
                assertEquals("alive", c.response(3).text());
            }
        }
    }

}
