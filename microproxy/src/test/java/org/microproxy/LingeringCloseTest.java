package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/**
 * An HTTP/1 connection that the proxy closes after a final response, while the client is still
 * sending (the rest of a request head, a body the proxy did not read, a pipelined request), keeps
 * that response: the proxy half-closes and reads what still comes for a while before it closes,
 * rather than closing with unread bytes (or with bytes still on their way), which resets the
 * connection and can throw away the response before the client has read it.
 *
 * <p>Each test makes the reset certain, rather than leaving it to timing: the client waits until
 * the response has arrived, without reading it, then keeps sending for a while (or until a write
 * fails, which only a reset makes happen) and only then reads.
 */
class LingeringCloseTest {

    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
    }

    @Test
    void aRequestHeadTimeoutKeepsIts408WhileTheClientStillSends() throws Exception {
        proxy = Launcher.start(new String[] {"--port", "0", "--http1-policy", "request_head_timeout=250"},
                new PrintStream(OutputStream.nullOutputStream()));
        try (Socket client = connect()) {
            OutputStream out = client.getOutputStream();
            out.write("GET / HTTP/1.1\r\nHost: example.test\r\nX-Slow: ".getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            String response = sendOnAfterTheResponseThenRead(client, () -> out.write('x'));
            assertTrue(response.startsWith("HTTP/1.1 408 Request Timeout\r\n"), response);
        }
    }

    @Test
    void aMalformedRequestKeepsIts400WithBytesUnreadBehindIt() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).start();
        try (Socket client = connect()) {
            OutputStream out = client.getOutputStream();
            // A request line the proxy refuses at once, and more than it reads with it.
            out.write("NOT HTTP\r\n".getBytes(StandardCharsets.ISO_8859_1));
            out.write(new byte[64 * 1024]);
            out.flush();
            String response = sendOnAfterTheResponseThenRead(client, () -> out.write(new byte[512]));
            assertTrue(response.startsWith("HTTP/1.1 400 "), response);
        }
    }

    @Test
    void aShortCircuitResponseKeepsItsAnswerWhileTheBodyStillComes() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0)
                .withFiltersSource(RecordingFilters.sourceOf(new HttpFilters() {
                    @Override
                    public org.microproxy.http.HttpResponse clientToProxyRequest(HttpObject o) {
                        return o instanceof org.microproxy.http.HttpRequest
                                ? new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN)
                                : null;
                    }
                }))
                .start();
        try (Socket client = connect()) {
            OutputStream out = client.getOutputStream();
            // A body the proxy never reads: the filter answers on the head.
            out.write(("POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\nContent-Length: 10000000\r\n\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.write(new byte[16 * 1024]);
            out.flush();
            String response = sendOnAfterTheResponseThenRead(client, () -> out.write(new byte[512]));
            assertTrue(response.startsWith("HTTP/1.1 403 Forbidden\r\n"), response);
            assertTrue(response.toLowerCase(java.util.Locale.ROOT).contains("connection: close"), response);
        }
    }

    @Test
    void anEarlyServerResponseKeepsItsAnswerWhileTheAbandonedBodyStillComes() throws Exception {
        AtomicBoolean answered = new AtomicBoolean();
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
            // Answers on the head, and goes away without reading the body.
            TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
            s.getOutputStream().write("HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .getBytes(StandardCharsets.ISO_8859_1));
            s.getOutputStream().flush();
            answered.set(true);
        })) {
            proxy = MicroProxy.bootstrap().withPort(0).start();
            try (Socket client = connect()) {
                OutputStream out = client.getOutputStream();
                out.write(("POST http://127.0.0.1:" + origin.port() + "/ HTTP/1.1\r\nHost: 127.0.0.1:" + origin.port()
                        + "\r\nContent-Length: 100000000\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                out.flush();
                // The body keeps coming until the response does: the proxy stops relaying it when
                // its writes to the server fail, and answers with the server's early response.
                String response = sendOnAfterTheResponseThenRead(client, () -> out.write(new byte[512]));
                assertTrue(answered.get());
                assertTrue(response.startsWith("HTTP/1.1 413 "), response);
            }
        }
    }

    private Socket connect() throws IOException {
        Socket client = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort());
        client.setSoTimeout(10_000);
        return client;
    }

    @FunctionalInterface
    private interface Send {
        void run() throws IOException;
    }

    /**
     * Keeps sending until the response has arrived (unread), then for {@link #SEND_ON_MILLIS} more
     * or until a write fails, then reads the whole response and the end of the connection. A
     * proxy that closes outright resets the connection once those bytes reach it, and the client's
     * next write fails; the read then fails too, the response discarded with the reset.
     */
    private static String sendOnAfterTheResponseThenRead(Socket client, Send send) throws Exception {
        InputStream in = client.getInputStream();
        long giveUp = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        boolean sending = true;
        // (A failed write means the connection was reset: whatever came is read below.)
        while (sending && in.available() == 0) {
            assertTrue(System.nanoTime() - giveUp < 0, "no response");
            sending = trySend(send);
            Thread.sleep(SEND_INTERVAL_MILLIS);
        }
        long until = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(SEND_ON_MILLIS);
        while (sending && System.nanoTime() - until < 0) {
            sending = trySend(send);
            Thread.sleep(SEND_INTERVAL_MILLIS);
        }
        ByteArrayOutputStream response = new ByteArrayOutputStream();
        in.transferTo(response);
        assertEquals(-1, in.read());
        return response.toString(StandardCharsets.ISO_8859_1);
    }

    private static boolean trySend(Send send) {
        try {
            send.run();
            return true;
        } catch (IOException resetOrClosed) {
            return false;
        }
    }

    /** How long the client keeps sending once the response is there: well within the proxy's linger. */
    private static final long SEND_ON_MILLIS = 300;
    private static final long SEND_INTERVAL_MILLIS = 10;
}
