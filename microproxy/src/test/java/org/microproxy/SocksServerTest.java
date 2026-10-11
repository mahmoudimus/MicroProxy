package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TlsHellos.issuer;
import static org.microproxy.TlsHellos.startTls;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalInt;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * The SOCKS server ({@code withSocksServer}, {@code --mode socks5}, and {@code withSocksDetection}
 * on the regular listener): the handshake, its replies, and what follows a request, which is what
 * follows an HTTP {@code CONNECT}.
 */
class SocksServerTest {

    private static CertificateAuthority proxyCa;
    private static CertificateAuthority originCa;
    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private final List<AutoCloseable> closing = new ArrayList<>();
    private TestSupport.RawServer echo;
    private HttpServer origin;

    @BeforeAll
    static void authorities() {
        proxyCa = CertificateAuthority.generate("SOCKS Proxy CA");
        originCa = CertificateAuthority.generate("SOCKS Origin CA");
    }

    @BeforeEach
    void servers() {
        echo = TestSupport.rawServer(s -> s.getInputStream().transferTo(s.getOutputStream()));
        origin = TestSupport.origin(TestSupport.echo());
    }

    @AfterEach
    void tearDown() throws Exception {
        proxies.close();
        echo.close();
        origin.stop(0);
        for (AutoCloseable c : closing) c.close();
    }

    private static HttpProxyServerBootstrap socks() {
        return MicroProxy.bootstrap().withSocksServer(true);
    }

    private static void assertEchoes(SocksClient c) throws IOException {
        c.write("ping\n");
        assertEquals("ping\n", c.read(5));
    }

    private static ProxyAuthenticator alice() {
        return (user, password) -> "alice".equals(user) && "secret".equals(password);
    }

    // --- address types ---------------------------------------------------------------------

    @Test
    void ipv4AndDomainNameDestinationsAreTunnelled() throws Exception {
        HttpProxyServer proxy = proxies.start(socks());
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0, c.open("127.0.0.1", echo.port()));
            assertEchoes(c);
        }
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0, c.greet(SocksClient.NO_AUTHENTICATION));
            assertEquals(0, c.request(SocksClient.CONNECT, SocksClient.DOMAIN, SocksClient.domain("localhost"), echo.port()));
            assertEchoes(c);
        }
    }

    @Test
    void ipv6DestinationsAreTunnelled() throws Exception {
        List<String> connects = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(socks().withFiltersSource((request, ctx) -> {
            connects.add(request.method() + " " + request.uri());
            return null;
        }));
        InetAddress v6 = InetAddress.getByName("::1");
        ServerSocket listener;
        try {
            listener = new ServerSocket(0, 50, v6);
        } catch (IOException e) {
            // Without IPv6 the address is still parsed: the connection fails, and is reported.
            try (SocksClient c = new SocksClient(proxy)) {
                c.greet(SocksClient.NO_AUTHENTICATION);
                assertTrue(c.request(SocksClient.CONNECT, SocksClient.IPV6, v6.getAddress(), 9) > 0);
            }
            assertEquals(List.of("CONNECT [0:0:0:0:0:0:0:1]:9"), connects);
            Assumptions.abort("no IPv6 loopback to tunnel to: " + e);
            return;
        }
        closing.add(listener);
        Thread.ofVirtual().start(() -> {
            try (Socket s = listener.accept()) {
                s.getInputStream().transferTo(s.getOutputStream());
            } catch (IOException ignored) {
                // test server
            }
        });
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0, c.greet(SocksClient.NO_AUTHENTICATION));
            assertEquals(0, c.request(SocksClient.CONNECT, SocksClient.IPV6, v6.getAddress(), listener.getLocalPort()));
            assertEchoes(c);
        }
        assertEquals(List.of("CONNECT [0:0:0:0:0:0:0:1]:" + listener.getLocalPort()), connects);
    }

    // --- authentication ----------------------------------------------------------------------

    @Test
    void usernameAndPasswordAuthenticateTheClient() throws Exception {
        List<String> users = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(socks().withProxyAuthenticator(alice())
                .withFiltersSource((request, ctx) -> {
                    users.add(request.method() + " " + ctx.getClientDetails().getUserName() + " "
                            + request.headers().contains(HttpHeaderNames.PROXY_AUTHORIZATION));
                    return null;
                }));
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(SocksClient.USERNAME_PASSWORD, c.greet(SocksClient.NO_AUTHENTICATION, SocksClient.USERNAME_PASSWORD));
            assertEquals(0, c.authenticate("alice", "secret"));
            assertEquals(0, c.connect("127.0.0.1", echo.port()));
            assertEchoes(c);
        }
        // The credentials never reach the filters.
        assertEquals(List.of("CONNECT alice false"), users);
    }

    @Test
    void wrongCredentialsAreRejected() throws Exception {
        HttpProxyServer proxy = proxies.start(socks().withProxyAuthenticator(alice()));
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(SocksClient.USERNAME_PASSWORD, c.greet(SocksClient.USERNAME_PASSWORD));
            assertEquals(1, c.authenticate("alice", "wrong"));
            assertTrue(c.closedByServer());
        }
    }

    @Test
    void noAcceptableMethodIsRejected() throws Exception {
        // An authenticator that wants credentials, and a client that offers none.
        HttpProxyServer guarded = proxies.start(socks().withProxyAuthenticator(alice()));
        try (SocksClient c = new SocksClient(guarded)) {
            assertEquals(SocksClient.NO_ACCEPTABLE, c.greet(SocksClient.NO_AUTHENTICATION));
            assertTrue(c.closedByServer());
        }
        // No authenticator, and a client that offers only credentials.
        HttpProxyServer open = proxies.start(socks());
        try (SocksClient c = new SocksClient(open)) {
            assertEquals(SocksClient.NO_ACCEPTABLE, c.greet(SocksClient.USERNAME_PASSWORD));
            assertTrue(c.closedByServer());
        }
    }

    @Test
    void anAuthenticatorMayAcceptClientsWithoutCredentials() throws Exception {
        List<String> users = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(socks()
                .withProxyAuthenticator(new ProxyAuthenticator() {
                    @Override
                    public AuthResult authenticate(HttpRequest request, FlowContext flow) {
                        // Trusts its own host, as a request-aware authenticator may.
                        return flow.getClientAddress().getAddress().isLoopbackAddress()
                                && flow.socksVersion().isPresent() ? AuthResult.accept("loopback") : AuthResult.reject();
                    }

                    @Override
                    public boolean authenticate(String userName, String password) {
                        return false;
                    }
                })
                .withFiltersSource((request, ctx) -> {
                    users.add(ctx.getClientDetails().getUserName());
                    return null;
                }));
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0, c.open("127.0.0.1", echo.port()));
            assertEchoes(c);
        }
        assertEquals(List.of("loopback"), users);
    }

    @Test
    void anAuthenticatorThatChecksEveryRequestSeesTheDestination() throws Exception {
        List<String> seen = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(socks().withProxyAuthenticator(new ProxyAuthenticator() {
            @Override
            public AuthResult authenticate(HttpRequest request, FlowContext flow) {
                seen.add(request.method() + " " + request.uri());
                if (request.uri().startsWith("forbidden.test")) return AuthResult.reject();
                return ProxyAuthenticator.super.authenticate(request, flow);
            }

            @Override
            public boolean authenticate(String userName, String password) {
                return "alice".equals(userName) && "secret".equals(password);
            }

            @Override
            public boolean authenticateEveryRequest() {
                return true;
            }
        }));
        try (SocksClient c = new SocksClient(proxy)) {
            c.greet(SocksClient.USERNAME_PASSWORD);
            assertEquals(0, c.authenticate("alice", "secret"));
            assertEquals(0x02, c.connect("forbidden.test", 443), "connection not allowed by ruleset");
            assertTrue(c.closedByServer());
        }
        try (SocksClient c = new SocksClient(proxy)) {
            c.greet(SocksClient.USERNAME_PASSWORD);
            assertEquals(0, c.authenticate("alice", "secret"));
            assertEquals(0, c.connect("127.0.0.1", echo.port()));
            assertEchoes(c);
        }
        assertEquals(List.of("CONNECT 0.0.0.0:0", "CONNECT forbidden.test:443", "CONNECT 0.0.0.0:0",
                "CONNECT 127.0.0.1:" + echo.port()), seen);
    }

    // --- refusals and failures ---------------------------------------------------------------

    @Test
    void onlyConnectIsSupported() throws Exception {
        HttpProxyServer proxy = proxies.start(socks());
        for (int command : new int[] {SocksClient.BIND, SocksClient.UDP_ASSOCIATE}) {
            try (SocksClient c = new SocksClient(proxy)) {
                c.greet(SocksClient.NO_AUTHENTICATION);
                assertEquals(0x07, c.request(command, SocksClient.IPV4, new byte[] {127, 0, 0, 1}, echo.port()),
                        "command not supported");
                assertTrue(c.closedByServer());
            }
        }
        try (SocksClient c = new SocksClient(proxy)) {
            c.greet(SocksClient.NO_AUTHENTICATION);
            assertEquals(0x08, c.request(SocksClient.CONNECT, 9, new byte[0], 80), "address type not supported");
            assertTrue(c.closedByServer());
        }
        try (SocksClient c = new SocksClient(proxy)) {
            c.greet(SocksClient.NO_AUTHENTICATION);
            assertEquals(0x01, c.request(SocksClient.CONNECT, SocksClient.DOMAIN, SocksClient.domain("bad/host"), 80));
        }
    }

    @Test
    void failuresAreReportedWithTheirReplyCodes() throws Exception {
        List<String> answered = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(socks()
                .withServerResolver((host, port) -> {
                    if (host.endsWith(".invalid")) throw new UnknownHostException(host);
                    return new InetSocketAddress(InetAddress.getByName(host), port);
                })
                .withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
                    @Override
                    public HttpResponse clientToProxyRequest(HttpObject httpObject) {
                        return request.uri().startsWith("blocked.test") ? new DefaultFullHttpResponse(
                                HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN) : null;
                    }
                })
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void responseSentToClient(FlowContext flowContext, HttpResponse response) {
                        answered.add(response.status().code() + " " + flowContext.socksVersion().orElse(0));
                    }
                }));
        try (Socket refusing = TestSupport.refusingPort(); SocksClient c = new SocksClient(proxy)) {
            assertEquals(0x05, c.open("127.0.0.1", refusing.getLocalPort()), "connection refused");
            assertTrue(c.closedByServer());
        }
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0x04, c.open("nowhere.invalid", 80), "host unreachable");
        }
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0x02, c.open("blocked.test", 443), "connection not allowed by ruleset");
        }
        TestSupport.eventually("three answers", () -> answered.size() == 3);
        assertEquals(List.of("502 5", "502 5", "403 5"), answered);
    }

    @Test
    void aRefusedRouteIsNotAllowed() throws Exception {
        HttpProxyServer proxy = proxies.start(socks().withChainProxyManager((request, queue, details) -> {}));
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0x02, c.open("127.0.0.1", echo.port()));
        }
    }

    @Test
    void aConnectTimeoutIsReportedAsTtlExpired() throws Exception {
        // A listener whose accept queue is full: on Linux new connection attempts to it hang.
        ServerSocket blackhole = new ServerSocket(0, 1, TestSupport.LOOPBACK);
        closing.add(blackhole);
        boolean saturated = false;
        for (int i = 0; i < 16 && !saturated; i++) {
            Socket s = new Socket();
            try {
                s.connect(blackhole.getLocalSocketAddress(), 200);
                closing.add(s);
            } catch (SocketTimeoutException e) {
                s.close();
                saturated = true;
            }
        }
        Assumptions.assumeTrue(saturated, "the accept queue could not be filled");
        HttpProxyServer proxy = proxies.start(socks().withConnectTimeout(300));
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0x06, c.open("127.0.0.1", blackhole.getLocalPort()), "TTL expired");
        }
    }

    @Test
    void anUnfinishedHandshakeTimesOut() throws Exception {
        HttpProxyServer proxy = proxies.start(socks().withTlsHandshakeTimeout(Duration.ofMillis(300)));
        try (SocksClient c = new SocksClient(proxy)) {
            long start = System.nanoTime();
            c.write(new byte[] {5, 2, 0});
            assertTrue(c.closedByServer());
            assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(5), "closed at the handshake deadline");
        }
    }

    @Test
    void theSocksListenerServesNoHttp() throws Exception {
        HttpProxyServer proxy = proxies.start(socks());
        String answer = TestSupport.rawExchange(proxy.getListenAddress(),
                "GET " + TestSupport.url(origin, "/") + " HTTP/1.1\r\nHost: x\r\n\r\n");
        assertEquals("", answer);
    }

    @Test
    void reverseProxiesAndTlsListenersAreNoSocksServers() {
        assertThrows(IllegalStateException.class,
                () -> proxies.start(socks().withReverseProxy("http://127.0.0.1:1")));
        assertThrows(IllegalStateException.class,
                () -> proxies.start(socks().withSslContextSource(() -> proxyCa.serverContext("localhost"))));
        assertThrows(IllegalStateException.class, () -> proxies.start(MicroProxy.bootstrap().withSocksDetection(true)
                .withReverseProxy("http://127.0.0.1:1")));
    }

    // --- what follows the request: the CONNECT flow ------------------------------------------

    @Test
    void plainHttpIsServedThroughTheFilters() throws Exception {
        List<String> seen = new CopyOnWriteArrayList<>();
        List<String> completed = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(socks()
                .withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
                    @Override
                    public HttpResponse clientToProxyRequest(HttpObject httpObject) {
                        if (!(httpObject instanceof HttpRequest r)) return null;
                        seen.add(r.method() + " " + r.uri() + " socks" + ctx.socksVersion().orElse(0));
                        r.headers().set("X-Via-Socks", String.valueOf(ctx.socksVersion().orElse(0)));
                        return null;
                    }
                })
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void responseCompleted(FlowContext flowContext, HttpResponse response) {
                        completed.add(response.status().code() + " connected=" + (flowContext.timings().connectEndNanos() >= 0));
                    }
                }));
        String target = "127.0.0.1:" + origin.getAddress().getPort();
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0, c.open("127.0.0.1", origin.getAddress().getPort()));
            c.write("GET /plain HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n");
            String response = new String(c.input().readAllBytes(), StandardCharsets.ISO_8859_1);
            assertTrue(response.startsWith("HTTP/1.1 200"), response);
            String body = response.substring(response.indexOf("\r\n\r\n") + 4);
            assertEquals(List.of("5"), TestSupport.echoedHeader(body, "X-Via-Socks"));
            assertEquals("/plain", TestSupport.echoedUri(body));
        }
        assertEquals(List.of("CONNECT " + target + " socks5", "GET /plain socks5"), seen);
        TestSupport.eventually("both exchanges completed", () -> completed.size() == 2);
        // The request goes on the connection made for the SOCKS request.
        assertEquals(List.of("200 connected=true", "200 connected=false"), completed);
    }

    @Test
    void httpsIsInterceptedWithTheMitmManager() throws Exception {
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), TestSupport.echo());
        closing.add(() -> secure.stop(0));
        List<String> seen = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(socks()
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource((request, ctx) -> {
                    seen.add(request.method() + " " + request.uri() + " sni="
                            + (ctx.getClientHello() == null ? "-" : ctx.getClientHello().sni())
                            + " socks" + ctx.socksVersion().orElse(0));
                    return null;
                }));
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0, c.open("localhost", secure.getAddress().getPort()));
            try (SSLSocket tls = startTls(c.socket, "localhost", proxyCa.clientContext(), "http/1.1")) {
                assertEquals(proxyCa.getCertificate().getSubjectX500Principal().getName(), issuer(tls));
                String response = TlsHellos.get(tls, "localhost", "/secure");
                assertTrue(response.startsWith("HTTP/1.1 200"), response);
                assertTrue(response.contains("uri: /secure"), response);
            }
        }
        assertEquals(List.of("CONNECT localhost:" + secure.getAddress().getPort() + " sni=- socks5",
                "GET /secure sni=localhost socks5"), seen);
    }

    @Test
    void ignoredHostsAreTunnelledRaw() throws Exception {
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), TestSupport.echo());
        closing.add(() -> secure.stop(0));
        List<String> seen = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(socks()
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withIgnoreHosts("^localhost:")
                .withFiltersSource((request, ctx) -> {
                    seen.add(request.method() + " " + request.uri());
                    return null;
                }));
        int port = secure.getAddress().getPort();
        // By the request's destination, without reading the ClientHello.
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0, c.open("localhost", port));
            try (SSLSocket tls = startTls(c.socket, "localhost", originCa.clientContext(), "http/1.1")) {
                assertEquals(originCa.getCertificate().getSubjectX500Principal().getName(), issuer(tls));
                assertTrue(TlsHellos.get(tls, "localhost", "/raw").startsWith("HTTP/1.1 200"));
            }
        }
        // By the ClientHello's SNI, for a destination given as an address.
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0, c.open("127.0.0.1", port));
            try (SSLSocket tls = startTls(c.socket, "localhost", originCa.clientContext(), "http/1.1")) {
                assertEquals(originCa.getCertificate().getSubjectX500Principal().getName(), issuer(tls));
                assertTrue(TlsHellos.get(tls, "localhost", "/raw").startsWith("HTTP/1.1 200"));
            }
        }
        assertEquals(List.of("CONNECT localhost:" + port, "CONNECT 127.0.0.1:" + port), seen);
    }

    @Test
    void chainedProxiesCarryTheTunnel() throws Exception {
        ChainTestSupport.RequestLog upstreamLog = new ChainTestSupport.RequestLog();
        HttpProxyServer upstream = proxies.start(MicroProxy.bootstrap().plusActivityTracker(upstreamLog));
        HttpProxyServer proxy = proxies.start(socks()
                .withChainProxyManager(ChainTestSupport.always(ChainTestSupport.http(upstream.getListenAddress()))));
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0, c.open("127.0.0.1", echo.port()));
            assertEchoes(c);
        }
        assertEquals(List.of("CONNECT 127.0.0.1:" + echo.port()), upstreamLog.received);
    }

    @Test
    void aServerThatSpeaksFirstIsTunnelled() throws Exception {
        TestSupport.RawServer banner = TestSupport.rawServer(s -> {
            s.getOutputStream().write("220 ready\r\n".getBytes(StandardCharsets.ISO_8859_1));
            s.getOutputStream().flush();
            s.getInputStream().transferTo(s.getOutputStream());
        });
        closing.add(banner);
        HttpProxyServer proxy = proxies.start(socks());
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0, c.open("127.0.0.1", banner.port()));
            assertEquals("220 ready\r\n", c.read(11));
            assertEchoes(c);
        }
    }

    // --- SOCKS4 and 4a, and SOCKS on the regular listener -------------------------------------

    @Test
    void socks4AndSocks4aConnect() throws Exception {
        List<OptionalInt> versions = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(socks().withFiltersSource((request, ctx) -> {
            versions.add(ctx.socksVersion());
            return null;
        }));
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(90, c.socks4(SocksClient.CONNECT, "127.0.0.1", echo.port(), "anyone"));
            assertEchoes(c);
        }
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(90, c.socks4(SocksClient.CONNECT, "localhost", echo.port(), ""));
            assertEchoes(c);
        }
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(91, c.socks4(SocksClient.BIND, "127.0.0.1", echo.port(), ""));
        }
        try (Socket refusing = TestSupport.refusingPort(); SocksClient c = new SocksClient(proxy)) {
            assertEquals(91, c.socks4(SocksClient.CONNECT, "127.0.0.1", refusing.getLocalPort(), ""));
        }
        try (SocksClient c = new SocksClient(proxy)) {
            // A user id longer than any field the server accepts.
            assertEquals(-1, c.socks4(SocksClient.CONNECT, "127.0.0.1", echo.port(), "u".repeat(300)));
        }
        assertEquals(List.of(OptionalInt.of(4), OptionalInt.of(4), OptionalInt.of(4)), versions);
    }

    @Test
    void socks4HasNoCredentialsForAnAuthenticator() throws Exception {
        HttpProxyServer proxy = proxies.start(socks().withProxyAuthenticator(alice()));
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(91, c.socks4(SocksClient.CONNECT, "127.0.0.1", echo.port(), "alice"));
            assertTrue(c.closedByServer());
        }
    }

    @Test
    void theRegularListenerTellsSocksFromHttp() throws Exception {
        List<String> seen = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap().withSocksDetection(true)
                .withFiltersSource((request, ctx) -> {
                    seen.add(request.method() + " socks" + ctx.socksVersion().orElse(0));
                    return null;
                }));
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(0, c.open("127.0.0.1", echo.port()));
            assertEchoes(c);
        }
        try (SocksClient c = new SocksClient(proxy)) {
            assertEquals(90, c.socks4(SocksClient.CONNECT, "localhost", echo.port(), ""));
            assertEchoes(c);
        }
        var response = TestSupport.get(TestSupport.client(proxy), TestSupport.url(origin, "/http"));
        assertEquals(200, response.statusCode());
        assertEquals(List.of("CONNECT socks5", "CONNECT socks4", "GET socks0"), seen);
    }

    @Test
    void withoutSocksTheListenerAnswersSocksBytesAsBadHttp() throws Exception {
        HttpProxyServer proxy = proxies.start(MicroProxy.bootstrap());
        try (SocksClient c = new SocksClient(proxy)) {
            c.write(new byte[] {5, 1, 0});
            c.socket.shutdownOutput();
            String answer = new String(c.input().readAllBytes(), StandardCharsets.ISO_8859_1);
            assertFalse(answer.startsWith("\u0005"), answer);
        }
    }

    // --- curl --------------------------------------------------------------------------------

    @Test
    void curlThroughTheSocksServer() throws Exception {
        Assumptions.assumeTrue(curlAvailable(), "curl is not installed");
        HttpProxyServer proxy = proxies.start(socks().withProxyAuthenticator(alice()));
        int port = proxy.getListenAddress().getPort();
        String url = TestSupport.localhostUrl(origin, "/curl");
        String out = curl("--proxy", "socks5h://alice:secret@127.0.0.1:" + port, url);
        assertTrue(out.contains("uri: /curl"), out);
        assertTrue(out.endsWith("200"), out);
        String refused = curl("--proxy", "socks5h://alice:wrong@127.0.0.1:" + port, url);
        assertFalse(refused.contains("uri: /curl"), refused);

        HttpProxyServer open = proxies.start(socks());
        String plain = curl("--socks5-hostname", "127.0.0.1:" + open.getListenAddress().getPort(), url);
        assertTrue(plain.contains("uri: /curl"), plain);
        String socks4a = curl("--socks4a", "127.0.0.1:" + open.getListenAddress().getPort(), url);
        assertTrue(socks4a.contains("uri: /curl"), socks4a);
    }

    @Test
    void curlHttpsThroughTheSocksServerIsIntercepted() throws Exception {
        Assumptions.assumeTrue(curlAvailable(), "curl is not installed");
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), TestSupport.echo());
        closing.add(() -> secure.stop(0));
        List<String> seen = new CopyOnWriteArrayList<>();
        HttpProxyServer proxy = proxies.start(socks()
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withFiltersSource((request, ctx) -> {
                    seen.add(request.method() + " " + request.uri());
                    return null;
                }));
        java.nio.file.Path ca = java.nio.file.Files.createTempFile("socks-proxy-ca", ".pem");
        try {
            proxyCa.writeCertificatePem(ca);
            String out = curl("--socks5-hostname", "127.0.0.1:" + proxy.getListenAddress().getPort(),
                    "--cacert", ca.toString(), "https://localhost:" + secure.getAddress().getPort() + "/tls");
            assertTrue(out.contains("uri: /tls"), out);
        } finally {
            java.nio.file.Files.deleteIfExists(ca);
        }
        assertEquals(List.of("CONNECT localhost:" + secure.getAddress().getPort(), "GET /tls"), seen);
    }

    /** Runs curl with {@code args} and no proxy settings from the environment; returns its output and status code. */
    private static String curl(String... args) throws Exception {
        List<String> command = new ArrayList<>(List.of("curl", "-sS", "--max-time", "20", "-w", "\n%{http_code}"));
        command.addAll(List.of(args));
        ProcessBuilder curl = new ProcessBuilder(command).redirectErrorStream(true);
        curl.environment().keySet().removeIf(k -> k.toLowerCase(java.util.Locale.ROOT).endsWith("_proxy"));
        Process p = curl.start();
        assertTrue(p.waitFor(30, TimeUnit.SECONDS));
        return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).strip();
    }

    static boolean curlAvailable() {
        try {
            Process p = new ProcessBuilder("curl", "--version").redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor(10, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
