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
}
