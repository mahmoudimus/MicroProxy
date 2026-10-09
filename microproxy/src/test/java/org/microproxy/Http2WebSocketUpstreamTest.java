package org.microproxy;

import static org.junit.jupiter.api.Assertions.*;

import io.github.mahmoudimus.http2.Frame;
import io.github.mahmoudimus.http2.HeaderField;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import io.github.mahmoudimus.http2.ErrorCode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.microproxy.http.WebSocketFrame;

class Http2WebSocketUpstreamTest {
    private HttpProxyServer proxy;
    private H2TestOrigin origin;
    private final List<List<HeaderField>> requests = new CopyOnWriteArrayList<>();

    @AfterEach
    void stop() throws Exception {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.close();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void webSocketsToHttp2OriginsUseFrameHooksForBothClientProtocols(boolean h2Client) throws Exception {
        H2TestOrigin.Options options = new H2TestOrigin.Options();
        options.enableConnectProtocol = true;
        origin = new H2TestOrigin(Http2UpstreamTest.originContext(), options, s -> {
            requests.add(s.headers);
            s.respond(200, false, "sec-websocket-protocol", "chat");
            InputStream in = s.input();
            while (true) {
                WebSocketFrame frame = WebSocketTestSupport.readFrame(in);
                s.data(frame.toWire(false), false);
                if (frame.isClose()) {
                    s.readBody();
                    s.data(new byte[0], true);
                    return;
                }
            }
        });
        List<String> frames = new CopyOnWriteArrayList<>();
        proxy = Http2UpstreamTest.mitm().withHttp2(true).withFiltersSource((req, ctx) -> new HttpFiltersAdapter(req, ctx) {
            @Override
            public WebSocketFrame filterWebSocketFrame(WebSocketFrame frame, boolean fromClient) {
                frames.add(fromClient + ":" + frame.opcode());
                return frame.isText() ? WebSocketFrame.text(fromClient ? "sent:edited" : "received:edited") : frame;
            }
        }).start();
        String authority = "localhost:" + origin.port();
        if (h2Client) {
            try (H2TestClient c = H2TestClient.connect(proxy.getListenAddress(), authority,
                    Http2UpstreamTest.proxyCa.clientContext()).handshake()) {
                c.headers(1, c.request("CONNECT", "/chat", ":protocol", "websocket", "sec-websocket-version", "13",
                        "sec-websocket-protocol", "chat"), false);
                Frame f = c.awaitFrame(x -> x.streamId() == 1 && (x instanceof Frame.Headers || x instanceof Frame.RstStream));
                assertInstanceOf(Frame.Headers.class, f);
                Frame.Headers h = (Frame.Headers) f;
                assertFalse(h.endStream());
                List<HeaderField> fields = c.fields(h);
                assertTrue(fields.contains(new HeaderField(":status", "200")), fields.toString());
                assertFalse(fields.stream().anyMatch(x -> x.name().equals("sec-websocket-accept")));
                c.data(1, WebSocketFrame.text("original").toWire(true), false);
                assertEquals("received:edited", WebSocketTestSupport.readFrame(new ByteArrayInputStream(
                        readData(c, 1, WebSocketFrame.text("received:edited").toWire(false).length))).payloadAsText());
                c.data(1, WebSocketFrame.close(1000, "bye").toWire(true), true);
                c.awaitFrame(x -> x instanceof Frame.Data d && d.streamId() == 1 && d.endStream());
            }
        } else {
            try (Socket raw = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
                raw.setSoTimeout(10_000);
                TestSupport.write(raw.getOutputStream(), "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n");
                assertTrue(TestSupport.readUntil(raw.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 200"));
                try (SSLSocket tls = (SSLSocket) Http2UpstreamTest.proxyCa.clientContext().getSocketFactory()
                        .createSocket(raw, "localhost", origin.port(), true)) {
                    tls.setSoTimeout(10_000);
                    tls.startHandshake();
                    TestSupport.write(tls.getOutputStream(), "GET /chat HTTP/1.1\r\nHost: " + authority
                            + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
                            + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: chat\r\n\r\n");
                    String response = TestSupport.readUntil(tls.getInputStream(), "\r\n\r\n");
                    assertTrue(response.startsWith("HTTP/1.1 101"), response);
                    assertTrue(response.toLowerCase().contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="), response);
                    WebSocketTestSupport.sendFromClient(tls.getOutputStream(), WebSocketFrame.text("original"));
                    assertEquals("received:edited", WebSocketTestSupport.readFrame(tls.getInputStream()).payloadAsText());
                    WebSocketTestSupport.sendFromClient(tls.getOutputStream(), WebSocketFrame.close(1000, "bye"));
                    assertTrue(WebSocketTestSupport.readFrame(tls.getInputStream()).isClose());
                }
            }
        }
        assertFalse(requests.isEmpty());
        List<HeaderField> request = requests.getFirst();
        assertTrue(request.contains(new HeaderField(":method", "CONNECT")), request.toString());
        assertTrue(request.contains(new HeaderField(":protocol", "websocket")), request.toString());
        assertTrue(request.contains(new HeaderField(":path", "/chat")), request.toString());
        assertFalse(request.stream().anyMatch(f -> List.of("connection", "upgrade", "sec-websocket-key", "transfer-encoding")
                .contains(f.name())), request.toString());
        assertTrue(frames.contains("true:1"));
        assertTrue(frames.contains("false:1"));
        assertEquals(1, origin.accepts.get(), "WebSocket must reuse the session's HTTP/2 origin connection");
    }

    @Test
    void resetAndOrdinaryRequestsLeaveTheSharedOriginConnectionAlive() throws Exception {
        H2TestOrigin.Options options = new H2TestOrigin.Options();
        options.enableConnectProtocol = true;
        origin = new H2TestOrigin(Http2UpstreamTest.originContext(), options, s -> {
            if ("websocket".equals(s.header(":protocol"))) {
                s.respond(200, false);
                s.readBody();
            } else {
                s.respond(200, false);
                s.data("ordinary".getBytes(java.nio.charset.StandardCharsets.UTF_8), true);
            }
        });
        proxy = Http2UpstreamTest.mitm().withHttp2(true).start();
        try (H2TestClient c = H2TestClient.connect(proxy.getListenAddress(), "localhost:" + origin.port(),
                Http2UpstreamTest.proxyCa.clientContext()).handshake()) {
            c.headers(1, c.request("CONNECT", "/chat", ":protocol", "websocket", "sec-websocket-version", "13"), false);
            Frame.Headers h = (Frame.Headers) c.awaitFrame(f -> f instanceof Frame.Headers x && x.streamId() == 1);
            assertTrue(c.fields(h).contains(new HeaderField(":status", "200")));
            c.get(3, "/ordinary");
            assertEquals("ordinary", c.response(3).text());
            c.rst(1, ErrorCode.CANCEL);
            TestSupport.eventually("origin sees the WebSocket stream reset", () -> origin.resets.contains(ErrorCode.CANCEL));
            c.get(5, "/after-cancel");
            assertEquals("ordinary", c.response(5).text());
            assertEquals(1, origin.accepts.get());
        }
    }

    @Test
    void originWithoutExtendedConnectFallsBackToHttp1() throws Exception {
        H2TestOrigin.Options options = new H2TestOrigin.Options();
        List<String> http1 = new CopyOnWriteArrayList<>();
        options.http1Handler = socket -> {
            http1.add(WebSocketTestSupport.handshake(socket));
            WebSocketFrame frame = WebSocketTestSupport.readFrame(socket.getInputStream());
            socket.getOutputStream().write(frame.toWire(false));
            socket.getOutputStream().flush();
        };
        origin = new H2TestOrigin(Http2UpstreamTest.originContext(), options, s -> {
            s.respond(500, true); // No extended CONNECT may be sent without the origin's setting.
        });
        proxy = Http2UpstreamTest.mitm().withHttp2(true).start();
        try (H2TestClient c = H2TestClient.connect(proxy.getListenAddress(), "localhost:" + origin.port(),
                Http2UpstreamTest.proxyCa.clientContext()).handshake()) {
            c.headers(1, c.request("CONNECT", "/chat", ":protocol", "websocket", "sec-websocket-version", "13"), false);
            Frame.Headers h = (Frame.Headers) c.awaitFrame(f -> f instanceof Frame.Headers x && x.streamId() == 1);
            assertTrue(c.fields(h).contains(new HeaderField(":status", "200")));
            byte[] frame = WebSocketFrame.text("fallback").toWire(true);
            c.data(1, frame, false);
            assertEquals("fallback", WebSocketTestSupport.readFrame(new ByteArrayInputStream(
                    readData(c, 1, WebSocketFrame.text("fallback").toWire(false).length))).payloadAsText());
            assertEquals(1, http1.size());
            assertTrue(http1.getFirst().startsWith("GET /chat HTTP/1.1"));
            assertEquals(2, origin.accepts.get(), "one pooled h2 connection and one HTTP/1 WebSocket");
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {200, 204})
    void secureWebSocketsOnH2cActuallyUseTlsToTheOrigin(int status) throws Exception {
        H2TestOrigin.Options options = new H2TestOrigin.Options();
        options.enableConnectProtocol = true;
        origin = new H2TestOrigin(Http2UpstreamTest.originContext(), options, s -> {
            requests.add(s.headers);
            s.respond(status, false);
            WebSocketFrame frame = WebSocketTestSupport.readFrame(s.input());
            s.data(frame.toWire(false), true);
        });
        proxy = Http2UpstreamTest.mitm().withHttp2Cleartext(true).start();
        try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), "localhost:" + origin.port()).handshake()) {
            List<HeaderField> fields = new java.util.ArrayList<>(c.request("CONNECT", "/chat", ":protocol", "websocket",
                    "sec-websocket-version", "13"));
            fields.set(1, new HeaderField(":scheme", "https"));
            c.headers(1, fields, false);
            Frame.Headers h = (Frame.Headers) c.awaitFrame(f -> f instanceof Frame.Headers x && x.streamId() == 1);
            assertTrue(c.fields(h).contains(new HeaderField(":status", "200")));
            c.data(1, WebSocketFrame.text("secure").toWire(true), true);
            assertEquals("secure", WebSocketTestSupport.readFrame(new ByteArrayInputStream(
                    readData(c, 1, WebSocketFrame.text("secure").toWire(false).length))).payloadAsText());
            assertTrue(requests.getFirst().contains(new HeaderField(":scheme", "https")));
        }
    }

    @Test
    void largeFramesCrossBothStreamWindowsAndKeepTheFrameBufferLimit() throws Exception {
        byte[] payload = new byte[400_000];
        new java.util.Random(73).nextBytes(payload);
        H2TestOrigin.Options options = new H2TestOrigin.Options();
        options.enableConnectProtocol = true;
        origin = new H2TestOrigin(Http2UpstreamTest.originContext(), options, s -> {
            s.respond(200, false);
            WebSocketFrame frame = WebSocketTestSupport.readFrame(s.input());
            s.data(frame.toWire(false), true);
        });
        List<String> truncated = new CopyOnWriteArrayList<>();
        proxy = Http2UpstreamTest.mitm().withHttp2(true).withMaxWebSocketFrameBufferSize(32_768)
                .withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
                    @Override
                    public void webSocketFrameReceived(WebSocketFrame frame, boolean fromClient) {
                        truncated.add(fromClient + ":" + frame.isTruncated() + ":" + frame.payloadLength());
                    }
                }).start();
        try (H2TestClient c = H2TestClient.connect(proxy.getListenAddress(), "localhost:" + origin.port(),
                Http2UpstreamTest.proxyCa.clientContext()).handshake()) {
            c.headers(1, c.request("CONNECT", "/chat", ":protocol", "websocket", "sec-websocket-version", "13"), false);
            Frame.Headers h = (Frame.Headers) c.awaitFrame(f -> f instanceof Frame.Headers x && x.streamId() == 1);
            assertTrue(c.fields(h).contains(new HeaderField(":status", "200")));
            sendWithStreamWindow(c, 1, WebSocketFrame.binary(payload).toWire(true), true);
            byte[] wire = readData(c, 1, WebSocketFrame.binary(payload).toWire(false).length);
            assertArrayEquals(payload, WebSocketTestSupport.readFrame(new ByteArrayInputStream(wire)).payload());
            assertEquals(List.of("true:true:400000", "false:true:400000"), truncated);
        }
    }

    /** These fixtures send less than the advertised connection window, but exceed the stream window. */
    static void sendWithStreamWindow(H2TestClient c, int id, byte[] bytes, boolean end) throws Exception {
        int window = c.setting(4) == null ? 65_535 : c.setting(4).intValue();
        int offset = 0;
        while (offset < bytes.length) {
            if (window == 0) {
                Frame.WindowUpdate update = (Frame.WindowUpdate) c.awaitFrame(f ->
                        f instanceof Frame.WindowUpdate w && w.streamId() == id);
                window += update.increment();
            }
            int n = Math.min(Math.min(window, 16_384), bytes.length - offset);
            c.data(id, java.util.Arrays.copyOfRange(bytes, offset, offset + n), end && offset + n == bytes.length);
            offset += n;
            window -= n;
        }
    }

    static byte[] readData(H2TestClient c, int id, int length) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        while (bytes.size() < length) {
            Frame.Data d = (Frame.Data) c.awaitFrame(x -> x instanceof Frame.Data data && data.streamId() == id);
            bytes.write(d.data());
            if (d.flowControlledLength() > 0) {
                c.writer.writeWindowUpdate(id, d.flowControlledLength());
                c.writer.writeWindowUpdate(0, d.flowControlledLength());
                c.writer.flush();
            }
        }
        return bytes.toByteArray();
    }
}
