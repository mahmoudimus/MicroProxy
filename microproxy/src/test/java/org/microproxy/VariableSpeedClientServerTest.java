package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.write;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.zip.CRC32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Large bodies relayed between peers that read and write at very different speeds arrive intact
 * (ported from LittleProxy's {@code VariableSpeedClientServerTest}, with megabytes instead of a
 * gigabyte and short pauses instead of throttled streams so it stays quick and deterministic).
 */
@Timeout(60)
class VariableSpeedClientServerTest {

    private static final int SIZE = 4 << 20;
    private static final int PIECE = 32 * 1024;

    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() {
        proxy = MicroProxy.bootstrap().withPort(0).start();
    }

    @AfterEach
    void tearDown() {
        proxy.abort();
    }

    private static byte[] payload(int size) {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) data[i] = (byte) (i * 31 % 251);
        return data;
    }

    private static long crc(byte[] data) {
        CRC32 crc = new CRC32();
        crc.update(data);
        return crc.getValue();
    }

    private static void pause() {
        try {
            Thread.sleep(1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** An origin that sends {@link #SIZE} bytes, pausing after every piece when {@code slow}. */
    private static TestSupport.RawServer downloadServer(boolean slow) {
        byte[] data = payload(SIZE);
        return TestSupport.rawServer(socket -> {
            TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
            OutputStream out = socket.getOutputStream();
            write(out, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " + SIZE + "\r\n\r\n");
            for (int off = 0; off < SIZE; off += PIECE) {
                out.write(data, off, Math.min(PIECE, SIZE - off));
                out.flush();
                if (slow) pause();
            }
        });
    }

    @Test
    void slowServerToFastClient() throws Exception {
        try (TestSupport.RawServer server = downloadServer(true)) {
            HttpResponse<byte[]> response = TestSupport.client(proxy).send(HttpRequest.newBuilder(
                            URI.create("http://127.0.0.1:" + server.port() + "/big"))
                    .timeout(Duration.ofSeconds(30)).build(), HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200, response.statusCode());
            assertEquals(String.valueOf(SIZE), response.headers().firstValue("content-length").orElseThrow());
            assertEquals(SIZE, response.body().length);
            assertEquals(crc(payload(SIZE)), crc(response.body()));
        }
    }

    @Test
    void fastServerToSlowClient() throws Exception {
        try (TestSupport.RawServer server = downloadServer(false); Socket s = new Socket()) {
            // A small receive window so the proxy, and then the server, must wait for the client.
            s.setReceiveBufferSize(16 * 1024);
            InetSocketAddress address = proxy.getListenAddress();
            s.connect(new InetSocketAddress(address.getAddress(), address.getPort()), 5000);
            s.setSoTimeout(20_000);
            write(s.getOutputStream(), "GET http://127.0.0.1:" + server.port() + "/big HTTP/1.1\r\nHost: x\r\n"
                    + "Connection: close\r\n\r\n");
            InputStream in = s.getInputStream();
            String head = TestSupport.readUntil(in, "\r\n\r\n");
            assertTrue(head.startsWith("HTTP/1.1 200 "), head);
            assertTrue(head.toLowerCase().contains("content-length: " + SIZE), head);
            ByteArrayOutputStream body = new ByteArrayOutputStream(SIZE);
            byte[] buf = new byte[8 * 1024];
            int reads = 0;
            int n;
            while ((n = in.read(buf)) >= 0) {
                body.write(buf, 0, n);
                if (++reads % 4 == 0) pause();
            }
            assertEquals(SIZE, body.size());
            assertEquals(crc(payload(SIZE)), crc(body.toByteArray()));
        }
    }

    @Test
    void fastClientUploadToSlowServer() throws Exception {
        byte[] upload = payload(SIZE);
        try (TestSupport.RawServer server = TestSupport.rawServer(socket -> {
            InputStream in = socket.getInputStream();
            String head = TestSupport.readUntil(in, "\r\n\r\n");
            int length = Integer.parseInt(head.lines()
                    .filter(l -> l.toLowerCase().startsWith("content-length:"))
                    .findFirst().orElseThrow().substring(15).strip());
            CRC32 crc = new CRC32();
            byte[] buf = new byte[8 * 1024];
            int total = 0;
            int reads = 0;
            while (total < length) {
                int n = in.read(buf, 0, Math.min(buf.length, length - total));
                if (n < 0) break;
                crc.update(buf, 0, n);
                total += n;
                if (++reads % 4 == 0) pause();
            }
            String answer = total + " " + crc.getValue();
            write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: " + answer.length() + "\r\n\r\n" + answer);
        })) {
            HttpResponse<String> response = TestSupport.client(proxy).send(HttpRequest.newBuilder(
                            URI.create("http://127.0.0.1:" + server.port() + "/upload"))
                    .timeout(Duration.ofSeconds(30))
                    .POST(HttpRequest.BodyPublishers.ofByteArray(upload)).build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.US_ASCII));
            assertEquals(200, response.statusCode());
            assertEquals(SIZE + " " + crc(upload), response.body());
        }
    }
}
