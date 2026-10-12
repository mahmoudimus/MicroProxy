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
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
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
        // TCP keeps no message boundaries: lines sent back to back may reach the hook as one message.
        String fromClient = events.stream().filter(e -> e.startsWith("> ")).map(e -> e.substring(2))
                .collect(java.util.stream.Collectors.joining());
        assertTrue(fromClient.startsWith("hello secret\n"), events.toString());
        assertTrue(fromClient.contains("drop me\nnothing\nafter\n"), events.toString());
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
    void reverseTcpConnectionsAreTunnels() throws Exception {
        Recorder recorder = new Recorder(TcpInterceptorTest::edit);
        try (TestSupport.RawServer origin = lineEcho()) {
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withTcpInterceptor(recorder)
                    .withReverseProxy(ReverseProxyMode.parse("tcp://127.0.0.1:" + origin.port())));
            try (Socket s = ChainTestSupport.open(proxy.getListenAddress())) {
                send(s, "no CONNECT, a secret");
                assertEquals("ECHO: no CONNECT, a public", line(s));
            }
            recorder.awaitDone();
            assertEquals(origin.port(), recorder.context.port());
        }
        assertFalse(recorder.context.tlsIntercepted());
    }

    /** A SOCKS5 client's tunnel to {@code 127.0.0.1:port} through {@code proxy}, its request granted. */
    private static SocksClient socksTunnel(HttpProxyServer proxy, int port) throws IOException {
        SocksClient c = new SocksClient(proxy);
        assertEquals(0, c.open("127.0.0.1", port));
        return c;
    }

    @Test
    void socksTunnelsGoThroughTheHooksAsConnectTunnelsDo() throws Exception {
        CertificateAuthority ca = CertificateAuthority.generate("SOCKS TCP hooks CA");
        try (TestSupport.RawServer origin = lineEcho()) {
            // Without MITM the SOCKS client's first bytes are still read (for plain HTTP); with it,
            // they would be intercepted if they were TLS. Either way these are tunnelled.
            for (boolean mitm : new boolean[] {false, true}) {
                Recorder recorder = new Recorder(TcpInterceptorTest::edit);
                HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap().withSocksServer(true).withTcpInterceptor(recorder);
                if (mitm) bootstrap.withManInTheMiddle(new CertificateAuthorityMitmManager(ca));
                HttpProxyServer proxy = proxies.start(bootstrap);
                try (SocksClient c = socksTunnel(proxy, origin.port())) {
                    send(c.socket, "hello secret");
                    assertEquals("ECHO: hello public", line(c.socket), "mitm " + mitm);
                    send(c.socket, "drop me");
                    send(c.socket, "after");
                    assertEquals("ECHO: after", line(c.socket));
                    send(c.socket, "inject");
                    assertEquals("from the proxy", line(c.socket));
                    assertEquals("ECHO: inject", line(c.socket));
                    assertEquals("ECHO: injected", line(c.socket));
                    c.socket.shutdownOutput();
                    assertEquals(-1, c.socket.getInputStream().read());
                }
                recorder.awaitDone();
                TcpContext ctx = recorder.context;
                assertEquals("127.0.0.1", ctx.host());
                assertEquals(origin.port(), ctx.port());
                assertFalse(ctx.tlsIntercepted());
                assertEquals(5, ctx.flowContext().socksVersion().orElse(0));
                assertEquals("start", recorder.events.getFirst());
                assertEquals("> hello secret\n", recorder.events.get(1), "the bytes read before deciding come first");
                assertEquals("end", recorder.events.getLast());
                assertNull(recorder.error);
            }
        }
    }

    @Test
    void aServerThatSpeaksFirstToASocksClientIsRelayedThroughTheHooks() throws Exception {
        try (TestSupport.RawServer origin = TestSupport.rawServer(TcpInterceptorTest::smtp)) {
            Recorder recorder = new Recorder(TcpInterceptorTest::banner);
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withSocksServer(true).withTcpInterceptor(recorder));
            try (SocksClient c = socksTunnel(proxy, origin.port())) {
                speakSmtp(c.socket);
            }
            recorder.awaitDone();
            assertEquals("< 220 smtp.test ESMTP ready\r\n", recorder.events.get(1));
        }
    }

    @Test
    void aTcpHostReachedThroughSocksIsRelayedAsBytes() throws Exception {
        try (TestSupport.RawServer origin = headEcho()) {
            String request = "GET /plain HTTP/1.1\r\nHost: 127.0.0.1:" + origin.port() + "\r\nConnection: close\r\n\r\n";
            Recorder recorder = new Recorder((m, ctx) -> m.data());
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withSocksServer(true).withTcpInterceptor(recorder)
                    .withTcpHosts("^127\\.0\\.0\\."));
            String answer;
            try (SocksClient c = socksTunnel(proxy, origin.port())) {
                TestSupport.write(c.out, request);
                answer = new String(c.input().readAllBytes(), StandardCharsets.UTF_8);
            }
            // Not served as HTTP (which a SOCKS client's plain HTTP otherwise is): the bytes as sent.
            assertTrue(answer.endsWith("\r\n\r\n" + request), answer);
            recorder.awaitDone();
            assertEquals("> " + request, recorder.events.get(1));
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
    void aConnectStreamsHooksSeeItsOwnServerNameNotTheConnections() throws Exception {
        CertificateAuthority serverCa = CertificateAuthority.generate("Stream SNI Server CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Stream SNI Proxy CA");
        SSLContext innerContext = serverCa.serverContext("inner.test");
        List<String> names = new CopyOnWriteArrayList<>();
        CountDownLatch ended = new CountDownLatch(2);
        TcpInterceptor interceptor = new TcpInterceptor() {
            @Override
            public byte[] tcpMessage(TcpMessage m, TcpContext ctx) {
                return m.data();
            }

            @Override
            public void tcpEnd(TcpContext ctx) {
                names.add(ctx.port() + " sni=" + ctx.sni() + " alpn=" + ctx.alpn());
                ended.countDown();
            }
        };
        try (TestSupport.RawServer echo = lineEcho();
                TestSupport.RawServer inner = TestSupport.rawServer(accepted -> {
                    SSLSocket s = (SSLSocket) innerContext.getSocketFactory().createSocket(accepted, null, true);
                    s.setUseClientMode(false);
                    s.setSoTimeout(20_000);
                    TestSupport.write(s.getOutputStream(), "echo: " + line(s) + "\n");
                })) {
            // The proxy's own TLS listener, which the HTTP/2 client reaches with SNI localhost.
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap()
                    .withSslContextSource(() -> serverCa.serverContext("localhost"))
                    .withHttp2(true)
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, serverCa.clientContext()))
                    .withIgnoreHosts("^inner\\.test:")
                    .withTcpInterceptor(interceptor));
            try (H2StreamClient c = H2StreamClient.tls(proxy.getListenAddress(), serverCa.clientContext(), "localhost")) {
                // A ClientHello that the host rules decline by its name: relayed as it is, with that name.
                H2StreamClient.Stream declined = c.open(H2StreamClient.connect("127.0.0.1:" + inner.port()), false);
                assertEquals(200, declined.status());
                try (SSLSocket tls = TlsHellos.startTls(declined.asSocket(), "inner.test", serverCa.clientContext())) {
                    send(tls, "own name");
                    assertEquals("echo: own name", line(tls));
                }
                // No ClientHello: no name, not the connection's.
                H2StreamClient.Stream plain = c.open(H2StreamClient.connect("127.0.0.1:" + echo.port()), false);
                assertEquals(200, plain.status());
                Socket tunnel = plain.asSocket();
                send(tunnel, "no name");
                assertEquals("echo: no name", line(tunnel));
                tunnel.close();
                assertTrue(ended.await(10, TimeUnit.SECONDS), names.toString());
            }
            assertEquals(Set.of(inner.port() + " sni=inner.test alpn=null", echo.port() + " sni=null alpn=null"),
                    Set.copyOf(names));
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
