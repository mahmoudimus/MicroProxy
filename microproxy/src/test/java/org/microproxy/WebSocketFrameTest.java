package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.write;

import java.io.DataInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.WebSocketFrame;
import org.microproxy.WebSocketTestSupport.EchoServer;

class WebSocketFrameTest {

    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
    }

    /** A WebSocket "server" that answers the upgrade, reads one frame and sends two back. */
    private static TestSupport.RawServer webSocketServer(int bigFrameSize) {
        return TestSupport.rawServer(socket -> {
            TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
            write(socket.getOutputStream(), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                    + "Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n");
            DataInputStream in = new DataInputStream(socket.getInputStream());
            in.readNBytes(2 + 4 + 5); // the client's masked "hello"
            OutputStream out = socket.getOutputStream();
            out.write(new byte[] {(byte) 0x81, 5});
            out.write("world".getBytes(StandardCharsets.US_ASCII));
            out.write(new byte[] {(byte) 0x82, 126, (byte) (bigFrameSize >> 8), (byte) bigFrameSize});
            out.write(new byte[bigFrameSize]);
            out.flush();
            in.read(); // wait for the client to close
        });
    }

    record Seen(WebSocketFrame frame, boolean fromClient) {}

    @Test
    void framesAreDecodedForFiltersAndRelayedUnchanged() throws Exception {
        List<Seen> seen = new CopyOnWriteArrayList<>();
        List<byte[]> raw = new CopyOnWriteArrayList<>();
        proxy = MicroProxy.bootstrap().withPort(0).withMaxWebSocketFrameBufferSize(1000)
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(HttpRequest req, FlowContext ctx) {
                        return new HttpFilters() {
                            @Override
                            public void webSocketFrameReceived(WebSocketFrame frame, boolean fromClient) {
                                seen.add(new Seen(frame, fromClient));
                                HttpFilters.super.webSocketFrameReceived(frame, fromClient);
                            }

                            @Override
                            public void webSocketFrameReceived(Supplier<byte[]> frameBytes, boolean fromClient) {
                                raw.add(frameBytes.get());
                            }
                        };
                    }
                }).start();
        try (TestSupport.RawServer server = webSocketServer(2000);
                Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            s.setSoTimeout(10_000);
            write(s.getOutputStream(), "GET http://127.0.0.1:" + server.port() + "/chat HTTP/1.1\r\nHost: x\r\n"
                    + "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
                    + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
            InputStream in = s.getInputStream();
            assertTrue(TestSupport.readUntil(in, "\r\n\r\n").startsWith("HTTP/1.1 101"));
            byte[] mask = {1, 2, 3, 4};
            byte[] hello = "hello".getBytes(StandardCharsets.US_ASCII);
            byte[] frame = new byte[2 + 4 + hello.length];
            frame[0] = (byte) 0x81;
            frame[1] = (byte) (0x80 | hello.length);
            System.arraycopy(mask, 0, frame, 2, 4);
            for (int i = 0; i < hello.length; i++) frame[6 + i] = (byte) (hello[i] ^ mask[i % 4]);
            s.getOutputStream().write(frame);
            s.getOutputStream().flush();

            DataInputStream din = new DataInputStream(in);
            byte[] reply = new byte[7];
            din.readFully(reply);
            assertEquals("world", new String(reply, 2, 5, StandardCharsets.US_ASCII));
            byte[] big = new byte[4 + 2000];
            din.readFully(big);
            assertEquals(126, big[1]);

            // Frames were relayed byte for byte; now check what the filter saw.
            for (int i = 0; i < 50 && seen.size() < 3; i++) Thread.sleep(20);
            assertEquals(3, seen.size());
            Seen fromClient = seen.stream().filter(Seen::fromClient).findFirst().orElseThrow();
            assertTrue(fromClient.frame().isText());
            assertTrue(fromClient.frame().isMasked());
            assertEquals("hello", fromClient.frame().payloadAsText());
            assertArrayEquals(frame, raw.get(seen.indexOf(fromClient)));

            List<Seen> fromServer = seen.stream().filter(x -> !x.fromClient()).toList();
            assertEquals("world", fromServer.get(0).frame().payloadAsText());
            assertFalse(fromServer.get(0).frame().isMasked());
            WebSocketFrame truncated = fromServer.get(1).frame();
            assertTrue(truncated.isBinary());
            assertTrue(truncated.isTruncated());
            assertEquals(2000, truncated.payloadLength());
            assertNull(truncated.payload());
        }
    }

    @Test
    void framesRoundTripThroughTheWireEncoding() throws Exception {
        for (int size : new int[] {0, 125, 126, 65535, 65536, 70000}) {
            byte[] payload = new byte[size];
            for (int i = 0; i < size; i++) payload[i] = (byte) (i * 31);
            for (boolean masked : new boolean[] {false, true}) {
                WebSocketFrame frame = WebSocketFrame.of(false, 4, WebSocketFrame.OPCODE_BINARY, payload);
                byte[] wire = frame.toWire(masked);
                WebSocketFrame back = WebSocketTestSupport.readFrame(new java.io.ByteArrayInputStream(wire));
                assertEquals(masked, back.isMasked(), "masked " + size);
                assertFalse(back.isFinal());
                assertEquals(4, back.rsv());
                assertTrue(back.isBinary());
                assertEquals(size, back.payloadLength());
                assertArrayEquals(payload, back.payload(), "payload " + size);
            }
        }
        WebSocketFrame close = WebSocketFrame.close(1001, "going away");
        assertTrue(close.isClose());
        assertEquals(1001, (close.payload()[0] & 0xff) << 8 | (close.payload()[1] & 0xff));
        assertEquals("hi", WebSocketFrame.text("x").withText("hi").payloadAsText());
    }

    @Test
    void filtersRewriteAndDropFramesInBothDirections() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withMaxWebSocketFrameBufferSize(1000)
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(HttpRequest req, FlowContext ctx) {
                        return new HttpFilters() {
                            @Override
                            public WebSocketFrame filterWebSocketFrame(WebSocketFrame frame, boolean fromClient) {
                                if (frame.isTruncated()) return null; // too big to inspect: drop it
                                if (!frame.isText()) return frame;
                                String text = frame.payloadAsText();
                                if (text.startsWith("secret")) return null;
                                return fromClient ? frame.withText(text.toUpperCase()) : frame.withText(text + "!");
                            }
                        };
                    }
                }).start();
        try (EchoServer server = new EchoServer(); Socket s = WebSocketTestSupport.connect(proxy, server.raw())) {
            OutputStream out = s.getOutputStream();
            WebSocketTestSupport.sendFromClient(out, WebSocketFrame.text("hello"));
            WebSocketTestSupport.sendFromClient(out, WebSocketFrame.text("secret token"));
            WebSocketTestSupport.sendFromClient(out, WebSocketFrame.binary(new byte[2000]));
            WebSocketTestSupport.sendFromClient(out, WebSocketFrame.text("ping"));
            WebSocketFrame echo = WebSocketTestSupport.readFrame(s.getInputStream());
            assertEquals("echo:PING!", echo.payloadAsText());
            assertFalse(echo.isMasked(), "frames towards the client are not masked");
            WebSocketTestSupport.sendFromClient(out, WebSocketFrame.close(1000, "done"));
            assertTrue(WebSocketTestSupport.readFrame(s.getInputStream()).isClose());

            assertTrue(server.upgradeRequest.startsWith("GET /chat"), server.upgradeRequest);
            assertFalse(server.upgradeRequest.toLowerCase().contains("sec-websocket-extensions"),
                    "compression is not negotiated when frames are rewritten");
            List<String> texts = server.received.stream()
                    .map(f -> f.isClose() ? "<close>" : f.payloadAsText()).toList();
            assertEquals(List.of("HELLO", "PING", "<close>"), texts);
            assertTrue(server.received.stream().allMatch(WebSocketFrame::isMasked), "frames towards the server are masked");
        }
    }
}
