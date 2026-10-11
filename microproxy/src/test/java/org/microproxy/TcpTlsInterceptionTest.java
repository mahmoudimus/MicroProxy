package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TlsHellos.issuer;
import static org.microproxy.TlsHellos.throughConnect;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.microproxy.tcp.TcpContext;
import org.microproxy.tcp.TcpMessage;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * Intercepted TLS that does not carry HTTP: the proxy decides by the negotiated ALPN protocol,
 * the {@code tcp_hosts}, a server that speaks first and the client's first decrypted bytes, as
 * mitmproxy's next layer does inside TLS, and relays the session as raw TCP, so the TCP hooks see
 * it decrypted.
 */
class TcpTlsInterceptionTest {

    private static CertificateAuthority proxyCa;
    private static CertificateAuthority originCa;
    private static String proxyIssuer;
    private static String originIssuer;
    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private TlsOrigin origin;

    @BeforeAll
    static void authorities() {
        proxyCa = CertificateAuthority.generate("TCP TLS Proxy CA");
        originCa = CertificateAuthority.generate("TCP TLS Origin CA");
        proxyIssuer = proxyCa.getCertificate().getSubjectX500Principal().getName();
        originIssuer = originCa.getCertificate().getSubjectX500Principal().getName();
    }

    @AfterEach
    void tearDown() throws IOException {
        proxies.close();
        if (origin != null) origin.close();
    }

    @FunctionalInterface
    interface TlsHandler {
        void handle(SSLSocket socket) throws IOException;
    }

    /** A TLS server that chooses {@code alpn} when offered (none otherwise) and runs a handler per connection. */
    static final class TlsOrigin implements AutoCloseable {
        private final SSLServerSocket server;

        TlsOrigin(SSLContext context, String alpn, TlsHandler handler) throws IOException {
            server = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 50,
                    InetAddress.getLoopbackAddress());
            Thread.ofVirtual().start(() -> {
                while (!server.isClosed()) {
                    SSLSocket s;
                    try {
                        s = (SSLSocket) server.accept();
                    } catch (IOException e) {
                        return;
                    }
                    s.setHandshakeApplicationProtocolSelector((socket, offered) ->
                            alpn != null && offered.contains(alpn) ? alpn : "");
                    Thread.ofVirtual().start(() -> {
                        try (s) {
                            s.setSoTimeout(20_000);
                            s.startHandshake();
                            handler.handle(s);
                        } catch (IOException ignored) {
                            // test origin
                        }
                    });
                }
            });
        }

        String target() {
            return "127.0.0.1:" + server.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            server.close();
        }
    }

    private TlsOrigin origin(String alpn, TlsHandler handler) {
        try {
            origin = new TlsOrigin(originCa.serverContext("localhost", "127.0.0.1"), alpn, handler);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return origin;
    }

    /** Trusts both CAs, to see who answered. */
    private static SSLContext trustBoth() throws Exception {
        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setCertificateEntry("proxy", proxyCa.getCertificate());
        ks.setCertificateEntry("origin", originCa.getCertificate());
        javax.net.ssl.TrustManagerFactory tmf =
                javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), null);
        return context;
    }

    private HttpProxyServerBootstrap mitm() {
        return MicroProxy.bootstrap().withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()));
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** An IMAP-like server: a greeting first, then {@code <tag> OK <command>} per line until LOGOUT. */
    static void imap(SSLSocket s) throws IOException {
        OutputStream out = s.getOutputStream();
        out.write(utf8("* OK IMAP4rev1 ready\r\n"));
        out.flush();
        BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            String[] words = line.split(" ", 2);
            out.write(utf8(words[0] + " OK " + (words.length > 1 ? words[1] : "") + "\r\n"));
            out.flush();
            if (line.endsWith("LOGOUT")) return;
        }
    }

    private static String readLine(InputStream in) throws IOException {
        return TestSupport.readUntil(in, "\r\n");
    }

    /** Rewrites the greeting and the password of a LOGIN, in plain text. */
    private static byte[] rewriteImap(TcpMessage m, TcpContext ctx) {
        String text = m.text();
        return m.fromClient() ? utf8(text.replace("hunter2", "********")) : utf8(text.replace("ready", "proxied"));
    }

    @Test
    void aProtocolNamedByAlpnIsInterceptedAndItsPlaintextSeenByTheHooks() throws Exception {
        origin("imap", TcpTlsInterceptionTest::imap);
        TcpInterceptorTest.Recorder recorder = new TcpInterceptorTest.Recorder(TcpTlsInterceptionTest::rewriteImap);
        HttpProxyServer proxy = proxies.start(mitm().withTcpInterceptor(recorder));
        try (SSLSocket tls = throughConnect(proxy, origin.target(), "localhost", trustBoth(), "imap")) {
            assertEquals(proxyIssuer, issuer(tls), "intercepted");
            assertEquals("imap", tls.getApplicationProtocol(), "the server's choice, mirrored");
            InputStream in = tls.getInputStream();
            assertEquals("* OK IMAP4rev1 proxied\r\n", readLine(in));
            TestSupport.write(tls.getOutputStream(), "a1 LOGIN user hunter2\r\n");
            assertEquals("a1 OK LOGIN user ********\r\n", readLine(in));
            TestSupport.write(tls.getOutputStream(), "a2 LOGOUT\r\n");
            assertEquals("a2 OK LOGOUT\r\n", readLine(in));
        }
        recorder.awaitDone();
        TcpContext ctx = recorder.context;
        assertTrue(ctx.tlsIntercepted());
        assertEquals("localhost", ctx.sni());
        assertEquals("imap", ctx.alpn());
        assertTrue(recorder.events.contains("> a1 LOGIN user hunter2\r\n"), recorder.events.toString());
    }

    @Test
    void theSameInsideAConnectStreamOfAnHttp2Connection() throws Exception {
        origin("imap", TcpTlsInterceptionTest::imap);
        TcpInterceptorTest.Recorder recorder = new TcpInterceptorTest.Recorder(TcpTlsInterceptionTest::rewriteImap);
        HttpProxyServer proxy = proxies.start(mitm().withHttp2Cleartext(true).withTcpInterceptor(recorder));
        try (H2StreamClient c = H2StreamClient.cleartext(proxy.getListenAddress(), origin.target())) {
            H2StreamClient.Stream stream = c.open(H2StreamClient.connect(origin.target()), false);
            assertEquals(200, stream.status());
            try (SSLSocket tls = TlsHellos.startTls(stream.asSocket(), "localhost", trustBoth(), "imap")) {
                assertEquals(proxyIssuer, issuer(tls));
                InputStream in = tls.getInputStream();
                assertEquals("* OK IMAP4rev1 proxied\r\n", readLine(in));
                TestSupport.write(tls.getOutputStream(), "a1 LOGOUT\r\n");
                assertEquals("a1 OK LOGOUT\r\n", readLine(in));
            }
        }
        recorder.awaitDone();
        assertTrue(recorder.context.tlsIntercepted());
        assertEquals("imap", recorder.context.alpn());
    }

    @Test
    void theSameForASocksClient() throws Exception {
        origin("imap", TcpTlsInterceptionTest::imap);
        TcpInterceptorTest.Recorder recorder = new TcpInterceptorTest.Recorder(TcpTlsInterceptionTest::rewriteImap);
        HttpProxyServer proxy = proxies.start(mitm().withSocksServer(true).withTcpInterceptor(recorder));
        int port = Integer.parseInt(origin.target().substring(origin.target().lastIndexOf(':') + 1));
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0, c.open("127.0.0.1", port));
            try (SSLSocket tls = TlsHellos.startTls(c.socket, "localhost", trustBoth(), "imap")) {
                assertEquals(proxyIssuer, issuer(tls), "intercepted");
                assertEquals("imap", tls.getApplicationProtocol(), "the server's choice, mirrored");
                InputStream in = tls.getInputStream();
                assertEquals("* OK IMAP4rev1 proxied\r\n", readLine(in));
                TestSupport.write(tls.getOutputStream(), "a1 LOGIN user hunter2\r\n");
                assertEquals("a1 OK LOGIN user ********\r\n", readLine(in));
                TestSupport.write(tls.getOutputStream(), "a2 LOGOUT\r\n");
                assertEquals("a2 OK LOGOUT\r\n", readLine(in));
            }
        }
        recorder.awaitDone();
        TcpContext ctx = recorder.context;
        assertTrue(ctx.tlsIntercepted());
        assertEquals("localhost", ctx.sni());
        assertEquals("imap", ctx.alpn());
        assertEquals(5, ctx.flowContext().socksVersion().orElse(0));
        assertTrue(recorder.events.contains("> a1 LOGIN user hunter2\r\n"), recorder.events.toString());
    }

    @Test
    void aServerThatSpeaksFirstInsideTlsToASocksClientIsRelayedDecrypted() throws Exception {
        origin(null, s -> TcpInterceptorTest.smtp(s));
        TcpInterceptorTest.Recorder recorder = new TcpInterceptorTest.Recorder(
                (m, ctx) -> m.fromClient() ? m.data() : utf8(m.text().replace("ESMTP ready", "ESMTP proxied")));
        HttpProxyServer proxy = proxies.start(mitm().withSocksServer(true).withTcpInterceptor(recorder));
        int port = Integer.parseInt(origin.target().substring(origin.target().lastIndexOf(':') + 1));
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0, c.open("localhost", port));
            try (SSLSocket tls = TlsHellos.startTls(c.socket, "localhost", trustBoth())) {
                assertEquals(proxyIssuer, issuer(tls));
                InputStream in = tls.getInputStream();
                assertEquals("220 smtp.test ESMTP proxied\r\n", readLine(in));
                TestSupport.write(tls.getOutputStream(), "QUIT\r\n");
                assertEquals("221 bye\r\n", readLine(in));
            }
        }
        recorder.awaitDone();
        assertTrue(recorder.context.tlsIntercepted());
        assertEquals("localhost", recorder.context.host());
    }

    @Test
    void withoutAnInterceptorAProtocolNamedByAlpnIsTunnelledUntouched() throws Exception {
        origin("imap", TcpTlsInterceptionTest::imap);
        HttpProxyServer proxy = proxies.start(mitm());
        try (SSLSocket tls = throughConnect(proxy, origin.target(), "localhost", trustBoth(), "imap")) {
            assertEquals(originIssuer, issuer(tls), "nothing would see the plaintext: not intercepted");
            assertEquals("* OK IMAP4rev1 ready\r\n", readLine(tls.getInputStream()));
        }
    }

    @Test
    void anAcmeChallengeIsNeverIntercepted() throws Exception {
        origin("acme-tls/1", s -> s.getOutputStream().write(utf8("challenge\r\n")));
        TcpInterceptorTest.Recorder recorder = new TcpInterceptorTest.Recorder((m, ctx) -> m.data());
        HttpProxyServer proxy = proxies.start(mitm().withTcpInterceptor(recorder));
        try (SSLSocket tls = throughConnect(proxy, origin.target(), "localhost", trustBoth(), "acme-tls/1")) {
            assertEquals(originIssuer, issuer(tls));
        }
        recorder.awaitDone();
        assertFalse(recorder.context.tlsIntercepted(), "the hooks saw the encrypted tunnel");
    }

    @Test
    void aServerThatSpeaksFirstInsideTlsIsRelayedWithoutWaitingForTheClient() throws Exception {
        // SMTPS: no ALPN, and the client waits for the banner.
        origin(null, s -> TcpInterceptorTest.smtp(s));
        TcpInterceptorTest.Recorder recorder = new TcpInterceptorTest.Recorder(
                (m, ctx) -> m.fromClient() ? m.data() : utf8(m.text().replace("ESMTP ready", "ESMTP proxied")));
        HttpProxyServer proxy = proxies.start(mitm().withTcpInterceptor(recorder));
        try (SSLSocket tls = throughConnect(proxy, origin.target(), "localhost", trustBoth())) {
            assertEquals(proxyIssuer, issuer(tls));
            InputStream in = tls.getInputStream();
            assertEquals("220 smtp.test ESMTP proxied\r\n", readLine(in));
            TestSupport.write(tls.getOutputStream(), "EHLO client\r\n");
            assertEquals("250 EHLO client\r\n", readLine(in));
            TestSupport.write(tls.getOutputStream(), "QUIT\r\n");
            assertEquals("221 bye\r\n", readLine(in));
        }
        recorder.awaitDone();
        assertTrue(recorder.context.tlsIntercepted());
        assertEquals("localhost", recorder.context.sni());
        assertEquals("< 220 smtp.test ESMTP ready\r\n", recorder.events.get(1));
    }

    @Test
    void decryptedBytesThatAreNotHttpAreRelayedAsTcp() throws Exception {
        // An MQTT CONNECT packet without ALPN: the client speaks first, in binary.
        byte[] connect = {0x10, 0x0c, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00};
        byte[] connack = {0x20, 0x02, 0x00, 0x00};
        origin(null, s -> {
            byte[] got = s.getInputStream().readNBytes(connect.length);
            s.getOutputStream().write(java.util.Arrays.equals(got, connect) ? connack : utf8("unexpected"));
            s.getOutputStream().flush();
        });
        List<byte[]> fromClient = new java.util.concurrent.CopyOnWriteArrayList<>();
        TcpInterceptorTest.Recorder recorder = new TcpInterceptorTest.Recorder((m, ctx) -> {
            if (m.fromClient()) fromClient.add(m.data());
            return m.data();
        });
        HttpProxyServer proxy = proxies.start(mitm().withTcpInterceptor(recorder));
        try (SSLSocket tls = throughConnect(proxy, origin.target(), "localhost", trustBoth())) {
            assertEquals(proxyIssuer, issuer(tls));
            tls.getOutputStream().write(connect);
            tls.getOutputStream().flush();
            assertArrayEquals(connack, tls.getInputStream().readNBytes(connack.length));
        }
        recorder.awaitDone();
        java.io.ByteArrayOutputStream seen = new java.io.ByteArrayOutputStream();
        for (byte[] b : fromClient) seen.write(b);
        assertArrayEquals(connect, seen.toByteArray(), "the hooks saw the plaintext");
    }

    /** An HTTP server over TLS that answers with the request head it received. */
    static void headEcho(SSLSocket s) throws IOException {
        String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
        byte[] body = utf8(head);
        s.getOutputStream().write(utf8("HTTP/1.1 200 OK\r\nContent-Length: " + body.length
                + "\r\nConnection: close\r\n\r\n"));
        s.getOutputStream().write(body);
        s.getOutputStream().flush();
    }

    @Test
    void httpInsideTlsToATcpHostIsRelayedAsBytes() throws Exception {
        origin(null, TcpTlsInterceptionTest::headEcho);
        for (boolean tcpHost : new boolean[] {false, true}) {
            TcpInterceptorTest.Recorder recorder = new TcpInterceptorTest.Recorder((m, ctx) -> m.data());
            // (With HTTP/2 on, the client gets the http/1.1 it offered: the TCP host still wins.)
            HttpProxyServerBootstrap bootstrap = mitm().withHttp2(true).withTcpInterceptor(recorder);
            if (tcpHost) bootstrap.withTcpHosts("^localhost$");
            HttpProxyServer proxy = proxies.start(bootstrap);
            String request = "GET /inside HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            String answer;
            try (SSLSocket tls = throughConnect(proxy, origin.target(), "localhost", trustBoth(), "http/1.1")) {
                assertEquals(proxyIssuer, issuer(tls), "intercepted either way");
                assertEquals("http/1.1", tls.getApplicationProtocol());
                TestSupport.write(tls.getOutputStream(), request);
                answer = new String(tls.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            }
            assertTrue(answer.startsWith("HTTP/1.1 200"), answer);
            if (tcpHost) {
                // Matched by the SNI: the request went as the client sent it, through the hooks.
                assertTrue(answer.endsWith("\r\n\r\n" + request), answer);
                recorder.awaitDone();
                assertEquals("> " + request, recorder.events.get(1));
                assertTrue(recorder.context.tlsIntercepted());
            } else {
                assertTrue(answer.toLowerCase(Locale.ROOT).contains("via: 1.1 "), answer);
                assertEquals(List.of(), recorder.events);
            }
        }
    }

    @Test
    void httpWithoutAlpnIsStillServedAsHttp() throws Exception {
        origin(null, TcpTlsInterceptionTest::headEcho);
        TcpInterceptorTest.Recorder recorder = new TcpInterceptorTest.Recorder((m, ctx) -> m.data());
        HttpProxyServer proxy = proxies.start(mitm().withTcpInterceptor(recorder));
        try (SSLSocket tls = throughConnect(proxy, origin.target(), "localhost", trustBoth())) {
            TestSupport.write(tls.getOutputStream(), "GET /no-alpn HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            String answer = new String(tls.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            assertTrue(answer.toLowerCase(Locale.ROOT).contains("via: 1.1 "), answer);
        }
        assertEquals(List.of(), recorder.events, "the request line said HTTP");
    }
}
