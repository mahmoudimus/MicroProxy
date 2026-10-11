package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.http.HttpRequest;
import org.microproxy.impl.BootstrapView;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SelfSignedSslContextSource;
import org.microproxy.tls.SslContexts;

/**
 * {@link HttpProxyServerBootstrap#withTlsProtocols}: every TLS socket the proxy makes is limited to
 * TLS 1.3 and 1.2 by default, and configuration hooks still have the last word.
 *
 * <p>The JDK disables TLS 1.1 and older ({@code jdk.tls.disabledAlgorithms}), so a peer that
 * speaks only those cannot be built without changing JVM-wide security settings; the tests use
 * peers limited to TLS 1.2 against a proxy pinned to TLS 1.3 instead, and check the protocols
 * enabled on the sockets the proxy creates.
 */
class TlsProtocolPinningTest {

    private static final List<String> DEFAULT = List.of("TLSv1.3", "TLSv1.2");

    private static HttpServer origin;
    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();

    @BeforeAll
    static void startOrigin() {
        origin = TestSupport.origin(TestSupport.fixed(200, "ok"));
    }

    @AfterAll
    static void stopOrigin() {
        origin.stop(0);
    }

    @AfterEach
    void tearDown() {
        proxies.close();
    }

    /** A listener identity that records the protocols enabled when its configure hook runs. */
    private static final class Recording extends SelfSignedSslContextSource {
        final List<List<String>> seen = new CopyOnWriteArrayList<>();
        private final String[] own;

        Recording(String... own) {
            this.own = own.length == 0 ? null : own;
        }

        @Override
        public void configure(SSLSocket socket, boolean clientMode) {
            seen.add(List.of(socket.getEnabledProtocols()));
            if (own != null) socket.setEnabledProtocols(own);
        }
    }

    /** Handshakes with a TLS listener as a client limited to {@code protocols}; returns the protocol agreed. */
    private static String handshake(InetSocketAddress listener, String... protocols) throws IOException {
        SSLContext trustAll = SslContexts.trustAll();
        try (SSLSocket s = (SSLSocket) trustAll.getSocketFactory().createSocket(listener.getAddress(), listener.getPort())) {
            s.setSoTimeout(10_000);
            s.setEnabledProtocols(protocols);
            s.startHandshake();
            String protocol = s.getSession().getProtocol();
            // Make sure the proxy did not drop the connection right after the handshake.
            TestSupport.write(s.getOutputStream(), "GET " + TestSupport.url(origin, "/") + " HTTP/1.1\r\nHost: x\r\n"
                    + "Connection: close\r\n\r\n");
            assertTrue(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 200"));
            return protocol;
        }
    }

    @Test
    void theListenerOffersTls13And12ByDefault() throws Exception {
        Recording tls = new Recording();
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withSslContextSource(tls));
        assertEquals("TLSv1.3", handshake(proxy.getListenAddress(), "TLSv1.3"));
        assertEquals("TLSv1.2", handshake(proxy.getListenAddress(), "TLSv1.2"));
        assertEquals(List.of(DEFAULT, DEFAULT), tls.seen, "pinned before the configure hook runs");
    }

    @Test
    void peersOutsideThePinnedProtocolsAreRefused() throws Exception {
        Recording tls = new Recording();
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withSslContextSource(tls).withTlsProtocols("TLSv1.3"));
        assertEquals("TLSv1.3", handshake(proxy.getListenAddress(), "TLSv1.3", "TLSv1.2"));
        assertThrows(IOException.class, () -> handshake(proxy.getListenAddress(), "TLSv1.2"));
        assertEquals(List.of("TLSv1.3"), tls.seen.getFirst());

        HttpProxyServer older = proxies.start(MicroProxy.bootstrap().withSslContextSource(new Recording())
                .withTlsProtocols("TLSv1.2"));
        assertEquals("TLSv1.2", handshake(older.getListenAddress(), "TLSv1.3", "TLSv1.2"), "the setting is honoured");
        assertThrows(IOException.class, () -> handshake(older.getListenAddress(), "TLSv1.3"));
    }

    @Test
    void aConfigureHookThatSetsItsOwnProtocolsWins() throws Exception {
        Recording tls = new Recording("TLSv1.2");
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withSslContextSource(tls).withTlsProtocols("TLSv1.3"));
        assertEquals("TLSv1.2", handshake(proxy.getListenAddress(), "TLSv1.3", "TLSv1.2"));
        assertThrows(IOException.class, () -> handshake(proxy.getListenAddress(), "TLSv1.3"));
        assertEquals(List.of("TLSv1.3"), tls.seen.getFirst(), "the hook saw the pinned protocols first");
    }

    @Test
    void withoutPinningTheContextsDefaultsApply() throws Exception {
        Recording tls = new Recording();
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withSslContextSource(tls).withTlsProtocols());
        handshake(proxy.getListenAddress(), "TLSv1.3");
        SSLSocket fresh = (SSLSocket) tls.getSslContext().getSocketFactory().createSocket();
        fresh.setUseClientMode(false);
        assertEquals(List.of(fresh.getEnabledProtocols()), tls.seen.getFirst());
        fresh.close();
    }

    /**
     * A TLS origin limited to {@code protocols} that answers every request with {@code 200}. Made
     * from an {@link SSLServerSocket}, which answers a version it does not speak with a {@code
     * protocol_version} alert (the JDK's HTTPS server just closes the connection, which the proxy
     * takes for a server that does not speak TLS at all, and tunnels).
     */
    private SSLServerSocket tlsOrigin(SSLContext context, String... protocols) throws IOException {
        SSLServerSocket server = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 50,
                TestSupport.LOOPBACK);
        server.setEnabledProtocols(protocols);
        Thread.ofVirtual().start(() -> {
            while (!server.isClosed()) {
                try {
                    Socket s = server.accept();
                    Thread.ofVirtual().start(() -> {
                        try (s) {
                            s.setSoTimeout(10_000);
                            while (!TestSupport.readUntil(s.getInputStream(), "\r\n\r\n").isEmpty()) {
                                TestSupport.write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecure");
                            }
                        } catch (IOException ignored) {
                            // test origin
                        }
                    });
                } catch (IOException e) {
                    return;
                }
            }
        });
        return server;
    }

    @Test
    void bothSidesOfAnInterceptedSessionArePinned() throws Exception {
        CertificateAuthority originCa = CertificateAuthority.generate("Pinning Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Pinning Proxy CA");
        List<List<String>> serverSide = new CopyOnWriteArrayList<>();
        List<ProxyFailure> failures = new CopyOnWriteArrayList<>();
        CertificateAuthorityMitmManager ca = new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext());
        MitmManager recording = new MitmManager() {
            @Override
            public SSLContext serverSslContext(String peerHost, int peerPort) {
                return ca.serverSslContext(peerHost, peerPort);
            }

            @Override
            public SSLContext clientSslContextFor(HttpRequest connectRequest, SSLSession serverSslSession) {
                return ca.clientSslContextFor(connectRequest, serverSslSession);
            }

            @Override
            public void configureServerSocket(SSLSocket socket) {
                serverSide.add(List.of(socket.getEnabledProtocols()));
            }
        };
        try (SSLServerSocket tls12 = tlsOrigin(originCa.serverContext("127.0.0.1"), "TLSv1.2");
                SSLServerSocket tls13 = tlsOrigin(originCa.serverContext("127.0.0.1"), "TLSv1.3")) {
            HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withManInTheMiddle(recording));
            var response = get(client(proxy, proxyCa.clientContext()), "https://127.0.0.1:" + tls12.getLocalPort() + "/");
            assertEquals(200, response.statusCode());
            assertEquals("secure", response.body());
            assertEquals(List.of(DEFAULT), serverSide);

            // Pinned to TLS 1.3, the proxy refuses the TLS 1.2 origin.
            HttpProxyServer strict = proxies.start(MicroProxy.bootstrap().withManInTheMiddle(recording)
                    .withTlsProtocols("TLSv1.3")
                    .withFailureResponder((request, failure) -> {
                        failures.add(failure);
                        return null;
                    }));
            // The server handshake follows the client's ClientHello: the request inside is refused.
            assertEquals(502, get(client(strict, proxyCa.clientContext()), "https://127.0.0.1:" + tls12.getLocalPort() + "/")
                    .statusCode());
            assertInstanceOf(ProxyFailure.TlsFailed.class, failures.getFirst());
            assertEquals(List.of("TLSv1.3"), serverSide.getLast());

            // The client side of the session: a TLS 1.2-only client is refused by the strict proxy.
            try (Socket s = ChainTestSupport.open(strict.getListenAddress())) {
                assertEquals(200, ChainTestSupport.status(ChainTestSupport.connect(s, "127.0.0.1:" + tls13.getLocalPort())));
                SSLSocket tls = (SSLSocket) proxyCa.clientContext().getSocketFactory().createSocket(s, "127.0.0.1",
                        tls13.getLocalPort(), true);
                tls.setEnabledProtocols(new String[] {"TLSv1.2"});
                assertThrows(IOException.class, tls::startHandshake);
            }
        }
    }

    @Test
    void tlsChainedProxiesArePinned() throws Exception {
        SelfSignedSslContextSource upstreamTls = new SelfSignedSslContextSource() {
            @Override
            public void configure(SSLSocket socket, boolean clientMode) {
                socket.setEnabledProtocols(new String[] {"TLSv1.2"});
            }
        };
        HttpProxyServer upstream = proxies.start(MicroProxy.bootstrap().withSslContextSource(upstreamTls)
                .withTlsProtocols("TLSv1.2"));
        List<List<String>> seen = new CopyOnWriteArrayList<>();
        SSLContext trusting = SslContexts.trusting(upstreamTls.getCertificate());
        ChainedProxy chained = new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return upstream.getListenAddress();
            }

            @Override
            public boolean requiresEncryption() {
                return true;
            }

            @Override
            public SSLContext getSslContext() {
                return trusting;
            }

            @Override
            public void configure(SSLSocket socket, boolean clientMode) {
                seen.add(List.of(socket.getEnabledProtocols()));
            }
        };
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withChainProxyManager(ChainTestSupport.always(chained)));
        assertEquals(200, get(client(proxy), TestSupport.url(origin, "/")).statusCode());
        assertEquals(List.of(DEFAULT), seen);

        HttpProxyServer strict = proxies.start(MicroProxy.bootstrap().withTlsProtocols("TLSv1.3")
                .withChainProxyManager(ChainTestSupport.always(chained)));
        assertEquals(502, get(client(strict), TestSupport.url(origin, "/")).statusCode(),
                "the TLS 1.2-only chained proxy is refused");
    }

    @Test
    void protocolsTheContextDoesNotSupportFailClearly() throws Exception {
        List<Throwable> handshakeFailures = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withSslContextSource(new Recording())
                .withTlsProtocols("TLSv9")
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void tlsHandshakeFailed(FlowContext ctx, boolean clientSide, Throwable cause) {
                        handshakeFailures.add(cause);
                    }
                }));
        assertThrows(IOException.class, () -> handshake(proxy.getListenAddress(), "TLSv1.3"));
        TestSupport.eventually("the failure to be reported", () -> !handshakeFailures.isEmpty());
        String message = handshakeFailures.getFirst().getMessage();
        assertTrue(message.contains("TLSv9") && message.contains("withTlsProtocols") && message.contains("TLSv1.3"),
                message);
    }

    @Test
    void configuredFromPropertiesAndTheCommandLine(@TempDir Path dir) throws IOException {
        assertEquals(DEFAULT, BootstrapView.tlsProtocols(MicroProxy.bootstrap()));
        assertEquals(List.of("TLSv1.3"), BootstrapView.tlsProtocols(MicroProxy.bootstrap().withTlsProtocols(" TLSv1.3", "")));

        Path props = dir.resolve("tls.properties");
        Files.writeString(props, "tls_protocols=TLSv1.2, TLSv1.3\n");
        assertEquals(List.of("TLSv1.2", "TLSv1.3"), BootstrapView.tlsProtocols(MicroProxy.bootstrapFromFile(props)));
        Files.writeString(props, "tls_protocols=\n");
        assertEquals(List.of(), BootstrapView.tlsProtocols(MicroProxy.bootstrapFromFile(props)), "empty: JDK defaults");

        PrintStream quiet = new PrintStream(OutputStream.nullOutputStream());
        assertEquals(List.of("TLSv1.3"), BootstrapView.tlsProtocols(
                Launcher.parse(new String[] {"--tls-protocols", "TLSv1.3"}, quiet).bootstrap()));
        assertEquals(List.of("TLSv1.3"), BootstrapView.tlsProtocols(Launcher.parse(
                new String[] {"--config", props.toString(), "--tls-protocols", "TLSv1.3"}, quiet).bootstrap()));
    }
}
