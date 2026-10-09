package org.microproxy;

import static org.microproxy.TestSupport.write;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.microproxy.http.WebSocketFrame;

/** A WebSocket echo origin and client helpers that speak the frame format directly. */
public final class WebSocketTestSupport {

    private WebSocketTestSupport() {}

    /** Reads one frame as on the wire (masked or not). */
    public static WebSocketFrame readFrame(InputStream stream) throws IOException {
        DataInputStream in = new DataInputStream(stream);
        byte[] head = new byte[14];
        in.readFully(head, 0, 2);
        int pos = 2;
        long length = head[1] & 0x7f;
        if (length == 126) {
            in.readFully(head, pos, 2);
            length = (head[2] & 0xff) << 8 | (head[3] & 0xff);
            pos += 2;
        } else if (length == 127) {
            in.readFully(head, pos, 8);
            length = 0;
            for (int i = 0; i < 8; i++) length = length << 8 | (head[pos + i] & 0xff);
            pos += 8;
        }
        if ((head[1] & 0x80) != 0) {
            in.readFully(head, pos, 4);
            pos += 4;
        }
        byte[] payload = in.readNBytes((int) length);
        return new WebSocketFrame(Arrays.copyOf(head, pos), payload, length);
    }

    /** Sends a frame towards a server: masked, as clients must. */
    public static void sendFromClient(OutputStream out, WebSocketFrame frame) throws IOException {
        out.write(frame.toWire(true));
        out.flush();
    }

    /** Opens a WebSocket through {@code proxy} to {@code server}; returns after the 101. */
    public static Socket connect(HttpProxyServer proxy, TestSupport.RawServer server) throws IOException {
        Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort());
        s.setSoTimeout(10_000);
        write(s.getOutputStream(), "GET http://127.0.0.1:" + server.port() + "/chat HTTP/1.1\r\nHost: x\r\n"
                + "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
                + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                + "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n");
        String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
        if (!head.startsWith("HTTP/1.1 101")) throw new IOException("no upgrade: " + head);
        return s;
    }

    /** Accepts an HTTP/1 WebSocket handshake with the request's actual nonce. */
    public static String handshake(Socket socket) throws IOException {
        String request = TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
        String key = request.lines().filter(line -> line.toLowerCase(java.util.Locale.ROOT)
                .startsWith("sec-websocket-key:"))
                .map(line -> line.substring(line.indexOf(':') + 1).strip()).findFirst().orElseThrow();
        String accept;
        try {
            accept = java.util.Base64.getEncoder().encodeToString(java.security.MessageDigest.getInstance("SHA-1")
                    .digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
                            .getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        write(socket.getOutputStream(), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                + "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");
        return request;
    }

    /**
     * An origin that accepts the upgrade, records every frame it receives, answers each text
     * frame starting with {@code PING} or {@code ping} with {@code "echo:" + text}, and answers a
     * close frame with a close frame.
     */
    public static final class EchoServer implements AutoCloseable {
        public final List<WebSocketFrame> received = new CopyOnWriteArrayList<>();
        public volatile String upgradeRequest;
        private final TestSupport.RawServer server;

        public EchoServer() {
            server = TestSupport.rawServer(socket -> {
                upgradeRequest = handshake(socket);
                OutputStream out = socket.getOutputStream();
                while (true) {
                    WebSocketFrame frame = readFrame(socket.getInputStream());
                    received.add(frame);
                    if (frame.isClose()) {
                        out.write(WebSocketFrame.close(1000, "bye").toWire(false));
                        out.flush();
                        return;
                    }
                    if (frame.isText() && frame.payloadAsText().toLowerCase().startsWith("ping")) {
                        out.write(WebSocketFrame.text("echo:" + frame.payloadAsText()).toWire(false));
                        out.flush();
                    }
                }
            });
        }

        public TestSupport.RawServer raw() {
            return server;
        }

        @Override
        public void close() throws IOException {
            server.close();
        }
    }
}
