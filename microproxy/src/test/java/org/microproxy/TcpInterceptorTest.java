package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.http2.HeaderField;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.tcp.TcpContext;
import org.microproxy.tcp.TcpInterceptor;
import org.microproxy.tcp.TcpMessage;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Raw TCP tunnels through a {@link TcpInterceptor}: messages rewritten, dropped and added in both
 * directions, half-closes, servers that speak first, and tunnels on HTTP/2 {@code CONNECT}
 * streams.
 */
class TcpInterceptorTest {

    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();

    @AfterEach
    void tearDown() {
        proxies.close();
    }

    /** Records every hook call, and rewrites messages with {@code rewrite}. */
    static class Recorder implements TcpInterceptor {
        final List<String> events = new CopyOnWriteArrayList<>();
        final CountDownLatch done = new CountDownLatch(1);
        final BiFunction<TcpMessage, TcpContext, byte[]> rewrite;
        volatile TcpContext context;
        volatile Throwable error;

        Recorder(BiFunction<TcpMessage, TcpContext, byte[]> rewrite) {
            this.rewrite = rewrite;
        }

        @Override
        public void tcpStart(TcpContext ctx) {
            context = ctx;
            events.add("start");
        }

        @Override
        public byte[] tcpMessage(TcpMessage message, TcpContext ctx) {
            events.add((message.fromClient() ? "> " : "< ") + message.text());
            return rewrite.apply(message, ctx);
        }

        @Override
        public void tcpHalfClose(TcpContext ctx, boolean fromClient) {
            events.add(fromClient ? "client done" : "server done");
        }

        @Override
        public void tcpEnd(TcpContext ctx) {
            events.add("end");
            done.countDown();
        }

        @Override
        public void tcpError(TcpContext ctx, Throwable e) {
            error = e;
            events.add("error");
            done.countDown();
        }

        void awaitDone() throws InterruptedException {
            assertTrue(done.await(10, TimeUnit.SECONDS), "the tunnel must end: " + events);
        }
    }

    /** An origin that answers each line with {@code echo: <line>}. */
    static TestSupport.RawServer lineEcho() {
        return TestSupport.rawServer(s -> {
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            OutputStream out = s.getOutputStream();
            String line;
            while ((line = in.readLine()) != null) {
                out.write(("echo: " + line + "\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        });
    }

    static void send(Socket s, String line) throws IOException {
        TestSupport.write(s.getOutputStream(), line + "\n");
    }

    static String line(Socket s) throws IOException {
        String line = TestSupport.readUntil(s.getInputStream(), "\n");
        return line.endsWith("\n") ? line.substring(0, line.length() - 1) : line;
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Rewrites, drops and adds bytes as the tests below expect, line by line: lines the client
     * sends without waiting for an answer may arrive in one message. (Lines are not split here:
     * each is written at once, and small.)
     */
    private static byte[] edit(TcpMessage m, TcpContext ctx) {
        String text = m.text();
        if (!m.fromClient()) return utf8(text.replace("echo:", "ECHO:"));
        StringBuilder out = new StringBuilder();
        for (String line : text.split("(?<=\n)")) {
            if (line.equals("drop me\n") || line.equals("nothing\n")) continue;
            if (line.equals("inject\n")) {
                ctx.send(true, utf8("injected\n"));
                ctx.send(false, utf8("from the proxy\n"));
            }
            out.append(line.replace("secret", "public"));
        }
        // Both ways of dropping: null, and no bytes.
        if (out.isEmpty()) return text.startsWith("nothing") ? new byte[0] : null;
        return utf8(out.toString());
    }

    private Socket tunnel(HttpProxyServer proxy, int port) throws IOException {
        Socket s = ChainTestSupport.open(proxy.getListenAddress());
        assertEquals(200, ChainTestSupport.status(ChainTestSupport.connect(s, "127.0.0.1:" + port)));
        return s;
    }

    @Test
    void messagesAreRewrittenDroppedAndAddedInBothDirections() throws Exception {
        Recorder recorder = new Recorder(TcpInterceptorTest::edit);
        try (TestSupport.RawServer origin = lineEcho()) {
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withTcpInterceptor(recorder));
            try (Socket s = tunnel(proxy, origin.port())) {
                send(s, "hello secret");
                assertEquals("ECHO: hello public", line(s));
                send(s, "drop me");
                send(s, "nothing");
                send(s, "after");
                assertEquals("ECHO: after", line(s), "dropped lines never reach the server");
                send(s, "inject");
                assertEquals("from the proxy", line(s));
                assertEquals("ECHO: inject", line(s));
                assertEquals("ECHO: injected", line(s), "sent after the message it was added to");
                s.shutdownOutput();
                assertEquals(-1, s.getInputStream().read());
            }
            recorder.awaitDone();
        }
        TcpContext ctx = recorder.context;
        assertEquals("127.0.0.1", ctx.host());
        assertFalse(ctx.tlsIntercepted());
        assertNull(ctx.sni());
        assertNull(ctx.alpn());
        assertTrue(ctx.connectionId() > 0);
        assertEquals("127.0.0.1", ctx.clientAddress().getAddress().getHostAddress());
        assertEquals(ctx.connectionId(), ctx.flowContext().getConnectionId());
        List<String> events = recorder.events;
        assertEquals("start", events.getFirst());
        assertEquals("end", events.getLast());
        assertTrue(events.contains("> hello secret\n"), events.toString());
        assertTrue(events.contains("> drop me\n"), events.toString());
        assertTrue(events.indexOf("client done") < events.indexOf("end"), events.toString());
        assertTrue(events.contains("server done"), events.toString());
        assertNull(recorder.error);
        IllegalStateException ended = org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                () -> ctx.send(true, utf8("late")));
        assertTrue(ended.getMessage().contains("ended"), ended.getMessage());
    }

    @Test
    void aHalfCloseIsReportedAndPassedOnWhileTheOtherDirectionGoesOn() throws Exception {
        CountDownLatch serverSawEnd = new CountDownLatch(1);
        List<String> serverRead = new CopyOnWriteArrayList<>();
        Recorder recorder = new Recorder((m, ctx) -> m.data()) {
            @Override
            public void tcpHalfClose(TcpContext ctx, boolean fromClient) {
                super.tcpHalfClose(ctx, fromClient);
                // The last bytes before the end goes on.
                if (fromClient) ctx.send(true, utf8("last words\n"));
            }
        };
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
            serverRead.add(new String(s.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
            serverSawEnd.countDown();
            // Still writing after the client finished: a half-closed connection.
            s.getOutputStream().write(utf8("bye\n"));
            s.getOutputStream().flush();
        })) {
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withTcpInterceptor(recorder));
            try (Socket s = tunnel(proxy, origin.port())) {
                send(s, "all I have");
                s.shutdownOutput();
                assertTrue(serverSawEnd.await(10, TimeUnit.SECONDS), "the end reaches the server");
                assertEquals("bye", line(s));
                assertEquals(-1, s.getInputStream().read());
            }
            recorder.awaitDone();
        }
        assertEquals(List.of("all I have\nlast words\n"), serverRead);
        List<String> events = recorder.events;
        assertTrue(events.indexOf("client done") < events.indexOf("< bye\n"), events.toString());
        assertTrue(events.indexOf("< bye\n") < events.indexOf("server done"), events.toString());
        assertEquals("end", events.getLast());
    }

    /** An SMTP-like origin: a banner first, then an answer per command, until QUIT. */
    static void smtp(Socket s) throws IOException {
        OutputStream out = s.getOutputStream();
        out.write(utf8("220 smtp.test ESMTP ready\r\n"));
        out.flush();
        BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            if (line.equals("QUIT")) {
                out.write(utf8("221 bye\r\n"));
                out.flush();
                return;
            }
            out.write(utf8("250 " + line + "\r\n"));
            out.flush();
        }
    }

    private static void speakSmtp(Socket s) throws IOException {
        // The client waits for the server: the proxy must not wait for the client.
        assertEquals("220 smtp.test ESMTP proxied\r\n", TestSupport.readUntil(s.getInputStream(), "\r\n"));
        TestSupport.write(s.getOutputStream(), "HELO client\r\n");
        assertEquals("250 HELO client\r\n", TestSupport.readUntil(s.getInputStream(), "\r\n"));
        TestSupport.write(s.getOutputStream(), "QUIT\r\n");
        assertEquals("221 bye\r\n", TestSupport.readUntil(s.getInputStream(), "\r\n"));
    }

    private static byte[] banner(TcpMessage m, TcpContext ctx) {
        return m.fromClient() ? m.data() : utf8(m.text().replace("ESMTP ready", "ESMTP proxied"));
    }

    @Test
    void aServerThatSpeaksFirstIsRelayedWithAndWithoutInterception() throws Exception {
        CertificateAuthority ca = CertificateAuthority.generate("TCP hooks CA");
        try (TestSupport.RawServer origin = TestSupport.rawServer(TcpInterceptorTest::smtp)) {
            for (boolean mitm : new boolean[] {false, true}) {
                Recorder recorder = new Recorder(TcpInterceptorTest::banner);
                HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap().withTcpInterceptor(recorder);
                if (mitm) bootstrap.withManInTheMiddle(new CertificateAuthorityMitmManager(ca));
                HttpProxyServer proxy = proxies.start(bootstrap);
                try (Socket s = tunnel(proxy, origin.port())) {
                    speakSmtp(s);
                }
                recorder.awaitDone();
                assertEquals("< 220 smtp.test ESMTP ready\r\n", recorder.events.get(1), "mitm " + mitm);
                assertFalse(recorder.context.tlsIntercepted());
            }
        }
    }

    /** An HTTP origin that answers with the request head it received as the body. */
    static TestSupport.RawServer headEcho() {
        return TestSupport.rawServer(s -> {
            String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
            byte[] body = utf8(head);
            s.getOutputStream().write(utf8("HTTP/1.1 200 OK\r\nContent-Length: " + body.length
                    + "\r\nConnection: close\r\n\r\n"));
            s.getOutputStream().write(body);
            s.getOutputStream().flush();
        });
    }

    @Test
    void aTcpHostIsRelayedAsBytesEvenWhenItSpeaksHttp() throws Exception {
        CertificateAuthority ca = CertificateAuthority.generate("TCP hosts CA");
        try (TestSupport.RawServer origin = headEcho()) {
            String request = "GET /plain HTTP/1.1\r\nHost: 127.0.0.1:" + origin.port() + "\r\nConnection: close\r\n\r\n";
            for (boolean tcpHost : new boolean[] {false, true}) {
                Recorder recorder = new Recorder((m, ctx) -> m.data());
                HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap().withTcpInterceptor(recorder)
                        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca));
                if (tcpHost) bootstrap.withTcpHosts("^127\\.0\\.0\\.");
                HttpProxyServer proxy = proxies.start(bootstrap);
                String answer;
                try (Socket s = tunnel(proxy, origin.port())) {
                    TestSupport.write(s.getOutputStream(), request);
                    answer = new String(s.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                }
                assertTrue(answer.startsWith("HTTP/1.1 200"), answer);
                if (tcpHost) {
                    // The server got the bytes as the client sent them, and the hooks saw them.
                    assertTrue(answer.endsWith("\r\n\r\n" + request), answer);
                    recorder.awaitDone();
                    assertEquals("> " + request, recorder.events.get(1));
                } else {
                    // Served as HTTP: the proxy's own request, with its Via.
                    assertTrue(answer.toLowerCase(java.util.Locale.ROOT).contains("via: 1.1 "), answer);
                    assertEquals(List.of(), recorder.events, "not a tunnel");
                }
            }
        }
    }

    @Test
    void aFailedTunnelEndsWithAnError() throws Exception {
        Recorder recorder = new Recorder((m, ctx) -> m.data());
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
            s.getInputStream().read();
            s.setSoLinger(true, 0);
            s.close();
        })) {
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withTcpInterceptor(recorder));
            try (Socket s = tunnel(proxy, origin.port())) {
                send(s, "x");
                try {
                    s.getInputStream().read();
                } catch (IOException expected) {
                    // the proxy resets or closes the client's connection too
                }
            }
            recorder.awaitDone();
        }
        assertEquals("error", recorder.events.getLast(), recorder.events.toString());
        assertTrue(recorder.error instanceof IOException, String.valueOf(recorder.error));
        assertFalse(recorder.events.contains("end"));
    }

    @Test
    void aThrowingHookPassesTheBytesOn() throws Exception {
        try (TestSupport.RawServer origin = lineEcho()) {
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withTcpInterceptor((m, ctx) -> {
                throw new IllegalStateException("broken hook");
            }));
            try (Socket s = tunnel(proxy, origin.port())) {
                send(s, "unchanged");
                assertEquals("echo: unchanged", line(s));
            }
        }
    }

    @Test
    void streamsOfAnHttp2ConnectionAreTunnelsToo() throws Exception {
        Recorder recorder = new Recorder(TcpInterceptorTest::edit);
        int port;
        try (TestSupport.RawServer origin = lineEcho()) {
            port = origin.port();
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withHttp2Cleartext(true).withTcpInterceptor(recorder));
            try (H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), "127.0.0.1:" + origin.port()).handshake()) {
                c.headers(1, List.of(new HeaderField(":method", "CONNECT"), new HeaderField(":authority", c.authority)), false);
                c.data(1, utf8("a secret\n"), true);
                H2TestClient.Response response = c.response(1);
                assertEquals(200, response.status());
                assertEquals("ECHO: a public\n", response.text());
            }
            recorder.awaitDone();
        }
        assertEquals(port, recorder.context.port());
        assertTrue(recorder.events.contains("client done"), recorder.events.toString());
        assertEquals("end", recorder.events.getLast());
    }
}
