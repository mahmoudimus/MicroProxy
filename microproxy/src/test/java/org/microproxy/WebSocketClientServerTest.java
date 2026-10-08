package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.write;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.WebSocketFrame;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * A WebSocket client and server talking through the proxy over a CONNECT tunnel ({@code ws}) and
 * through man-in-the-middle interception ({@code wss}), where the upgrade happens inside the
 * intercepted TLS session (ported from LittleProxy's {@code websockets/WebSocketClientServerTest}).
 */
@Timeout(30)
class WebSocketClientServerTest {

    private static final String MESSAGE = "test 1 test 2 test 3 test 4";

    static CertificateAuthority originCa;
    static CertificateAuthority proxyCa;

    private HttpProxyServer proxy;

    @BeforeAll
    static void createAuthorities() {
        originCa = CertificateAuthority.generate("WebSocket Origin CA");
        proxyCa = CertificateAuthority.generate("WebSocket Proxy CA");
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
    }

    // -------------------------------------------------------------------------------------------
    // Frames, as on the wire
    // -------------------------------------------------------------------------------------------

    /** A text frame: masked when sent by a client, as RFC 6455 requires. */
    private static byte[] textFrame(String text, boolean masked) {
        byte[] payload = text.getBytes(StandardCharsets.UTF_8);
        if (payload.length > 125) throw new IllegalArgumentException("short frames only");
        byte[] mask = {0x37, (byte) 0xfa, 0x21, 0x3d};
        byte[] frame = new byte[2 + (masked ? 4 : 0) + payload.length];
        frame[0] = (byte) 0x81;
        frame[1] = (byte) ((masked ? 0x80 : 0) | payload.length);
        int pos = 2;
        if (masked) {
            System.arraycopy(mask, 0, frame, pos, 4);
            pos += 4;
        }
        for (int i = 0; i < payload.length; i++) {
            frame[pos + i] = masked ? (byte) (payload[i] ^ mask[i % 4]) : payload[i];
        }
        return frame;
    }

    /** Reads one short text frame and returns its (unmasked) text. */
    private static String readTextFrame(InputStream stream) throws IOException {
        DataInputStream in = new DataInputStream(stream);
        int b0 = in.readUnsignedByte();
        int b1 = in.readUnsignedByte();
        if ((b0 & 0x0f) != 1) throw new IOException("not a text frame: " + Integer.toHexString(b0));
        int length = b1 & 0x7f;
        if (length >= 126) throw new IOException("short frames only");
        byte[] mask = new byte[4];
        boolean masked = (b1 & 0x80) != 0;
        if (masked) in.readFully(mask);
        byte[] payload = new byte[length];
        in.readFully(payload);
        if (masked) {
            for (int i = 0; i < length; i++) payload[i] ^= mask[i % 4];
        }
        return new String(payload, StandardCharsets.UTF_8);
    }

    // -------------------------------------------------------------------------------------------
    // Server
    // -------------------------------------------------------------------------------------------

    /**
     * A WebSocket server (TLS when {@code tls} is given) that accepts the upgrade and answers
     * every text frame with the same text in upper case.
     */
    private static final class UpperCaseServer implements AutoCloseable {
        final ServerSocket serverSocket;
        volatile String upgradeRequest;

        UpperCaseServer(SSLContext tls) throws IOException {
            serverSocket = tls == null ? new ServerSocket(0, 50, TestSupport.LOOPBACK)
                    : tls.getServerSocketFactory().createServerSocket(0, 50, TestSupport.LOOPBACK);
            Thread.ofVirtual().start(() -> {
                while (!serverSocket.isClosed()) {
                    try {
                        Socket s = serverSocket.accept();
                        Thread.ofVirtual().start(() -> serve(s));
                    } catch (IOException e) {
                        return;
                    }
                }
            });
        }

        private void serve(Socket socket) {
            try (socket) {
                upgradeRequest = TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
                OutputStream out = socket.getOutputStream();
                write(out, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        + "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n");
                while (true) {
                    String text = readTextFrame(socket.getInputStream());
                    out.write(textFrame(text.toUpperCase(Locale.ROOT), false));
                    out.flush();
                }
            } catch (IOException e) {
                // client went away
            }
        }

        int port() {
            return serverSocket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            serverSocket.close();
        }
    }

    // -------------------------------------------------------------------------------------------
    // Client
    // -------------------------------------------------------------------------------------------

    private Socket connectThroughProxy(int port) throws IOException {
        Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort());
        s.setSoTimeout(10_000);
        write(s.getOutputStream(), "CONNECT 127.0.0.1:" + port + " HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\n\r\n");
        String established = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
        assertTrue(established.startsWith("HTTP/1.1 200 "), established);
        return s;
    }

    /** Upgrades {@code s} to a WebSocket, sends {@link #MESSAGE} and returns the reply. */
    private static String exchange(Socket s, int port) throws IOException {
        write(s.getOutputStream(), "GET /websocket HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\n"
                + "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
                + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
        String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
        assertTrue(head.startsWith("HTTP/1.1 101 "), head);
        s.getOutputStream().write(textFrame(MESSAGE, true));
        s.getOutputStream().flush();
        return readTextFrame(s.getInputStream());
    }

    @Test
    void wsThroughConnectTunnel() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withTransparent(true).start();
        try (UpperCaseServer server = new UpperCaseServer(null); Socket s = connectThroughProxy(server.port())) {
            assertEquals(MESSAGE.toUpperCase(Locale.ROOT), exchange(s, server.port()));
        }
    }

    record Seen(String text, boolean fromClient, boolean masked) {}

    @Test
    void wssThroughManInTheMiddle() throws Exception {
        List<Seen> frames = new CopyOnWriteArrayList<>();
        List<String> requests = new CopyOnWriteArrayList<>();
        // Not transparent: the upgrade must survive the proxy's hop-by-hop header rewriting.
        proxy = MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                        requests.add(originalRequest.method() + " " + originalRequest.uri());
                        return new HttpFilters() {
                            @Override
                            public void webSocketFrameReceived(WebSocketFrame frame, boolean fromClient) {
                                if (frame.isText()) frames.add(new Seen(frame.payloadAsText(), fromClient, frame.isMasked()));
                            }
                        };
                    }
                })
                .start();
        try (UpperCaseServer server = new UpperCaseServer(originCa.serverContext("127.0.0.1", "localhost"));
                Socket s = connectThroughProxy(server.port())) {
            // The client trusts only the proxy's CA, so this only works if the session is intercepted.
            SSLSocket tls = (SSLSocket) proxyCa.clientContext().getSocketFactory()
                    .createSocket(s, "127.0.0.1", server.port(), true);
            tls.setSoTimeout(10_000);
            tls.startHandshake();
            assertEquals(MESSAGE.toUpperCase(Locale.ROOT), exchange(tls, server.port()));
            assertTrue(server.upgradeRequest.toLowerCase(Locale.ROOT).contains("upgrade: websocket"), server.upgradeRequest);

            long deadline = System.nanoTime() + 5_000_000_000L;
            while (frames.size() < 2 && System.nanoTime() < deadline) Thread.sleep(10);
            assertEquals(List.of("CONNECT 127.0.0.1:" + server.port(), "GET /websocket"), requests);
            assertTrue(frames.contains(new Seen(MESSAGE, true, true)), frames.toString());
            assertTrue(frames.contains(new Seen(MESSAGE.toUpperCase(Locale.ROOT), false, false)), frames.toString());
        }
    }
}
