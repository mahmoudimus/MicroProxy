package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.readUntil;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.tcp.TcpContext;
import org.microproxy.tcp.TcpInterceptor;
import org.microproxy.tcp.TcpMessage;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * A tunnel that the client asks its own proxy for, inside a session MicroProxy serves (an
 * intercepted HTTPS proxy's, or a plain HTTP proxy's), goes on as a {@code CONNECT} to MicroProxy
 * would once the proxy opened it: the client's first bytes decide. A server that waits for the
 * client is reached at once, plain HTTP is served as HTTP, the ClientHello's name, protocols and
 * the TCP hosts decide on interception, a server that speaks first is heard, and the TCP hooks
 * see what is relayed; every connection to the server goes through the client's proxy. Each test
 * runs for every way to that proxy: an HTTPS proxy over HTTP/2 and over HTTP/1.1, asked by an
 * HTTP/2 client and an HTTP/1.1 client, and a plain HTTP proxy.
 */
@Timeout(60)
class ForwardedTunnelTest {

    /** Signs the client's proxy's and the servers' certificates, which MicroProxy trusts. */
    static final CertificateAuthority serverCa = CertificateAuthority.generate("Forwarded Tunnel Server CA");
    /** MicroProxy's interception CA, which the clients trust. */
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("Forwarded Tunnel Proxy CA");

    /** How long a tunnel may take to answer: TLS with a server that waits took the 10 s handshake timeout. */
    static final long PROMPT_MILLIS = 2000;

    /** How the client reaches its proxy through MicroProxy, and asks it for a tunnel. */
    enum Way {
        /** An HTTP/2 client's {@code CONNECT} stream, forwarded on a stream to an HTTPS proxy. */
        H2_CLIENT_H2_PROXY,
        /** An HTTP/2 client's {@code CONNECT} stream, forwarded over HTTP/1.1 to an HTTPS proxy. */
        H2_CLIENT_H1_PROXY,
        /** An HTTP/1.1 client's {@code CONNECT}, forwarded on a stream to an HTTPS proxy. */
        H1_CLIENT_H2_PROXY,
        /** An HTTP/1.1 client's {@code CONNECT}, forwarded over HTTP/1.1 to an HTTPS proxy. */
        H1_CLIENT_H1_PROXY,
        /** An HTTP/1.1 client's {@code CONNECT} in its plain session, forwarded to an HTTP proxy. */
        PLAIN_PROXY;

        boolean https() {
            return this != PLAIN_PROXY;
        }

        boolean h2Client() {
            return this == H2_CLIENT_H2_PROXY || this == H2_CLIENT_H1_PROXY;
        }

        boolean h2Proxy() {
            return this == H2_CLIENT_H2_PROXY || this == H1_CLIENT_H2_PROXY;
        }
    }

    /** A client's session with its proxy, through MicroProxy. */
    @FunctionalInterface
    interface Session {
        /** Asks the proxy for a tunnel to {@code target}; returns the tunnel's bytes as a socket. */
        Socket tunnel(String target) throws IOException;
    }

    private HttpProxyServer proxy;
    private HttpProxyServer corp;
    private Way way;
    private final List<AutoCloseable> closeables = new CopyOnWriteArrayList<>();
    /** The requests the client's proxy received: {@code method uri version}. */
    private final List<String> corpSaw = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        if (corp != null) corp.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    private <T extends AutoCloseable> T closing(T c) {
        closeables.add(c);
        return c;
    }

    // -------------------------------------------------------------------------------------------
    // The proxies and the servers
    // -------------------------------------------------------------------------------------------

    /**
     * Starts the client's proxy for {@code way} (another MicroProxy: a TLS listener, with HTTP/2 or
     * not, or a plain forward proxy, which resolves {@code *.test} to the loopback address), then
     * MicroProxy from {@code microProxy}.
     */
    private void start(Way way, HttpProxyServerBootstrap microProxy) {
        this.way = way;
        HttpProxyServerBootstrap b = MicroProxy.bootstrap().withPort(0).withProxyAlias("corp")
                .withServerResolver((host, port) -> new InetSocketAddress(
                        host.endsWith(".test") ? TestSupport.LOOPBACK : InetAddress.getByName(host), port))
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void requestReceivedFromClient(FlowContext ctx, HttpRequest r) {
                        corpSaw.add(r.method() + " " + r.uri() + " " + r.protocolVersion());
                    }
                });
        if (way.https()) {
            b.withSslContextSource(() -> serverCa.serverContext("localhost", "127.0.0.1")).withHttp2(way.h2Proxy());
        }
        corp = b.start();
        proxy = microProxy.start();
    }

    /** MicroProxy: intercepts everything, offers HTTP/2 to clients and to servers. */
    private static HttpProxyServerBootstrap microProxy() {
        return MicroProxy.bootstrap().withPort(0).withProxyAlias("mp")
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, serverCa.clientContext()))
                .withHttp2(true)
                .withHttp2Upstream(true);
    }

    /** The client's proxy, as the client names it in its {@code CONNECT} to MicroProxy. */
    private String corpTarget() {
        return (way.https() ? "localhost:" : "127.0.0.1:") + corp.getListenAddress().getPort();
    }

    /** The {@code CONNECT} for {@code target} as the client's proxy received it. */
    private String forwarded(String target) {
        return "CONNECT " + target + (way.h2Proxy() ? " HTTP/2.0" : " HTTP/1.1");
    }

    private TestSupport.RawServer rawServer(TestSupport.RawHandler handler) {
        return closing(TestSupport.rawServer(handler));
    }

    /** A raw TCP server that echoes what it reads until the client half-closes, then closes. */
    private TestSupport.RawServer echoServer() {
        return rawServer(s -> s.getInputStream().transferTo(s.getOutputStream()));
    }

    private static String target(TestSupport.RawServer server) {
        return "127.0.0.1:" + server.port();
    }

    // -------------------------------------------------------------------------------------------
    // The clients
    // -------------------------------------------------------------------------------------------

    /**
     * A client's session with its proxy, through MicroProxy: an HTTP/2 client's (each tunnel a
     * {@code CONNECT} stream), or an HTTP/1.1 client's (whose one tunnel is the session's
     * connection from then on), over TLS that MicroProxy intercepts for an HTTPS proxy, else plain.
     */
    private Session session() throws IOException {
        InetSocketAddress address = proxy.getListenAddress();
        if (way.h2Client()) {
            H2StreamClient client = closing(H2StreamClient.intercepted(address, corpTarget(), proxyCa.clientContext()));
            return target -> {
                H2StreamClient.Stream stream = client.open(H2StreamClient.connect(target), false);
                assertEquals(200, stream.status());
                return stream.asSocket();
            };
        }
        Socket plain = closing(new Socket(address.getAddress(), address.getPort()));
        plain.setSoTimeout(20_000);
        String head = connect(plain, corpTarget());
        assertTrue(head.startsWith("HTTP/1.1 200"), head);
        Socket session = way.https() ? clientTls(plain, "localhost", corp.getListenAddress().getPort()) : plain;
        return target -> {
            String inner = connect(session, target);
            assertTrue(inner.startsWith("HTTP/1.1 200"), inner);
            return session;
        };
    }

    /** A TLS handshake over {@code s}, trusting MicroProxy's CA, without ALPN (the client speaks HTTP/1.1). */
    private SSLSocket clientTls(Socket s, String host, int port) throws IOException {
        SSLSocket tls = closing((SSLSocket) proxyCa.clientContext().getSocketFactory().createSocket(s, host, port, true));
        tls.setUseClientMode(true);
        tls.setSoTimeout(20_000);
        tls.startHandshake();
        return tls;
    }

    /** Starts TLS over {@code tunnel} with {@code sni} and {@code alpn}, trusting {@code trust}. */
    private SSLSocket startTls(Socket tunnel, String sni, SSLContext trust, String... alpn) throws IOException {
        SSLSocket tls = closing(TlsHellos.startTls(tunnel, sni, trust, alpn));
        tls.setSoTimeout(20_000);
        return tls;
    }

    /** Sends {@code CONNECT target} on {@code s} and returns the response head. */
    private static String connect(Socket s, String target) throws IOException {
        return request(s, "CONNECT " + target + " HTTP/1.1", target);
    }

    /** Sends a request head ({@code requestLine} and {@code Host}) and returns the response head. */
    private static String request(Socket s, String requestLine, String host) throws IOException {
        write(s.getOutputStream(), requestLine + "\r\nHost: " + host + "\r\n\r\n");
        return readUntil(s.getInputStream(), "\r\n\r\n");
    }

    /** Reads the body {@code head} declares with its Content-Length. */
    private static String body(Socket s, String head) throws IOException {
        int length = Integer.parseInt(WebSocketTestSupport.header(head, "Content-Length"));
        return new String(s.getInputStream().readNBytes(length), StandardCharsets.UTF_8);
    }

    private static String echoBack(Socket tunnel, String text) throws IOException {
        write(tunnel.getOutputStream(), text);
        return new String(tunnel.getInputStream().readNBytes(text.length()), StandardCharsets.ISO_8859_1);
    }

    private static long millisSince(long start) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
    }

    // -------------------------------------------------------------------------------------------
    // Filters and hooks
    // -------------------------------------------------------------------------------------------

    /**
     * Records what MicroProxy's filters see (requests, and the server connections made), and adds
     * {@code X-Filtered: mp} to the requests it sends.
     */
    private static HttpFiltersSource recording(List<String> seen) {
        return (original, ctx) -> new HttpFiltersAdapter(original, ctx) {
            @Override
            public HttpResponse clientToProxyRequest(HttpObject o) {
                if (o instanceof HttpRequest r) seen.add(r.method() + " " + r.uri() + " via=" + ctx.forwardedVia().orElse("-"));
                return null;
            }

            @Override
            public HttpResponse proxyToServerRequest(HttpObject o) {
                if (o instanceof HttpRequest r && r.method().name().equals("GET")) r.headers().set("X-Filtered", "mp");
                return null;
            }

            @Override
            public void proxyToServerConnectionSucceeded(FullFlowContext serverCtx) {
                ChainedProxy chained = serverCtx.getChainedProxy();
                seen.add("connected " + serverCtx.getServerHostAndPort() + " through "
                        + (chained == null ? "-" : chained.getChainedProxyAddress().getHostString() + ":"
                                + chained.getChainedProxyAddress().getPort()));
            }
        };
    }

    /** Upper-cases what the client sends through a raw tunnel, and records the hooks' calls. */
    private static TcpInterceptor shouting(List<String> seen, CountDownLatch ended) {
        return new TcpInterceptor() {
            @Override
            public byte[] tcpMessage(TcpMessage m, TcpContext ctx) {
                seen.add((m.fromClient() ? "> " : "< ") + m.text());
                return m.fromClient() ? m.text().toUpperCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8) : m.data();
            }

            @Override
            public void tcpEnd(TcpContext ctx) {
                seen.add("end " + ctx.host() + ":" + ctx.port() + " tls=" + ctx.tlsIntercepted()
                        + (ctx.tlsIntercepted() ? " sni=" + ctx.sni() + " alpn=" + ctx.alpn() : ""));
                ended.countDown();
            }
        };
    }

    // -------------------------------------------------------------------------------------------
    // The client's first bytes decide
    // -------------------------------------------------------------------------------------------

    @ParameterizedTest
    @EnumSource(Way.class)
    void aServerThatWaitsForTheClientIsReachedAtOnce(Way way) throws Exception {
        TestSupport.RawServer echo = echoServer();
        start(way, microProxy());
        Session session = session();
        long start = System.nanoTime();
        Socket tunnel = session.tunnel(target(echo));
        // The client's first bytes are not TLS: no handshake with the server is tried.
        assertEquals("the client speaks first", echoBack(tunnel, "the client speaks first"));
        long millis = millisSince(start);
        assertTrue(millis < PROMPT_MILLIS, millis + " ms");
        assertEquals(List.of(forwarded(target(echo))), corpSaw);
    }

    @ParameterizedTest
    @EnumSource(Way.class)
    void plainHttpInTheTunnelIsServedAsHttpThroughTheFilters(Way way) throws Exception {
        HttpServer origin = TestSupport.origin(TestSupport.echo());
        closeables.add(() -> origin.stop(0));
        String target = "127.0.0.1:" + origin.getAddress().getPort();
        List<String> seen = new CopyOnWriteArrayList<>();
        start(way, microProxy().withFiltersSource(recording(seen)));
        Socket tunnel = session().tunnel(target);
        for (String path : List.of("/plain?n=1", "/plain?n=2")) {
            String head = request(tunnel, "GET " + path + " HTTP/1.1", target);
            assertTrue(head.startsWith("HTTP/1.1 200"), head);
            String body = body(tunnel, head);
            assertEquals(path, echoedUri(body));
            assertEquals(List.of("mp"), echoedHeader(body, "x-filtered"));
            assertEquals(List.of("1.1 mp"), echoedHeader(body, "via"));
        }
        // Both requests went on the tunnel the CONNECT opened, whose proxy the filters see.
        assertEquals(List.of(forwarded(target)), corpSaw);
        assertTrue(seen.containsAll(List.of("connected " + target + " through " + corpTarget(),
                "GET /plain?n=1 via=" + corpTarget(), "GET /plain?n=2 via=" + corpTarget())), seen.toString());
    }

    @ParameterizedTest
    @EnumSource(Way.class)
    void anIgnoredServerNameIsTunnelledAsItIsThroughTheProxy(Way way) throws Exception {
        HttpsServer origin = TestSupport.httpsOrigin(serverCa.serverContext("origin.test"), TestSupport.echo());
        closeables.add(() -> origin.stop(0));
        // The target is an address: only the ClientHello's name tells that the rule applies.
        String target = "127.0.0.1:" + origin.getAddress().getPort();
        start(way, microProxy().withIgnoreHosts("^origin\\.test:"));
        SSLSocket tls = startTls(session().tunnel(target), "origin.test", serverCa.clientContext(), "http/1.1");
        // The client sees the server's own certificate.
        assertEquals(serverCa.getCertificate().getSubjectX500Principal().getName(), TlsHellos.issuer(tls));
        String head = request(tls, "GET /real HTTP/1.1", "origin.test");
        assertTrue(head.startsWith("HTTP/1.1 200"), head);
        String body = body(tls, head);
        assertEquals("/real", echoedUri(body));
        assertEquals(List.of(), echoedHeader(body, "via"));
        assertEquals(List.of(forwarded(target)), corpSaw);
    }

    @ParameterizedTest
    @EnumSource(Way.class)
    void theServerIsOfferedTheClientsProtocolsAndTheClientGetsTheServersChoice(Way way) throws Exception {
        List<List<String>> offered = new CopyOnWriteArrayList<>();
        SSLContext context = serverCa.serverContext("localhost", "127.0.0.1");
        // An HTTP/1.1 server that answers with the protocol it chose.
        TestSupport.RawServer origin = rawServer(plain -> {
            SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(plain, null, true);
            tls.setUseClientMode(false);
            tls.setHandshakeApplicationProtocolSelector((socket, protocols) -> {
                offered.add(List.copyOf(protocols));
                return protocols.contains("http/1.1") ? "http/1.1" : null;
            });
            tls.startHandshake();
            readUntil(tls.getInputStream(), "\r\n\r\n");
            String body = "alpn=" + tls.getApplicationProtocol();
            write(tls.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: " + body.length()
                    + "\r\nConnection: close\r\n\r\n" + body);
            tls.close();
        });
        String target = "localhost:" + origin.port();
        start(way, microProxy());
        SSLSocket http1 = startTls(session().tunnel(target), "localhost", proxyCa.clientContext(), "http/1.1");
        assertEquals("http/1.1", http1.getApplicationProtocol());
        assertTrue(TlsHellos.get(http1, target, "/").endsWith("alpn=http/1.1"));
        // Offered h2 as well, the server chose HTTP/1.1, and so does the client, though MicroProxy speaks h2.
        SSLSocket both = startTls(session().tunnel(target), "localhost", proxyCa.clientContext(), "h2", "http/1.1");
        assertEquals("http/1.1", both.getApplicationProtocol());
        assertTrue(TlsHellos.get(both, target, "/").endsWith("alpn=http/1.1"));
        // A server offered only what the client offered (the proxy speaks HTTP/2 upstream).
        assertEquals(List.of(List.of("http/1.1"), List.of("h2", "http/1.1")), offered);
        assertEquals(List.of(forwarded(target), forwarded(target)), corpSaw);
    }

    @ParameterizedTest
    @EnumSource(Way.class)
    void aServerThatSpeaksFirstIsHeardThroughTheProxy(Way way) throws Exception {
        TestSupport.RawServer smtp = rawServer(s -> {
            write(s.getOutputStream(), "220 ready\r\n");
            s.getInputStream().transferTo(s.getOutputStream());
        });
        start(way, microProxy());
        Session session = session();
        long start = System.nanoTime();
        Socket tunnel = session.tunnel(target(smtp));
        // The client waits for the server, which MicroProxy notices through the proxy's tunnel.
        assertEquals("220 ready\r\n", readUntil(tunnel.getInputStream(), "\r\n"));
        long millis = millisSince(start);
        assertTrue(millis < PROMPT_MILLIS, millis + " ms");
        assertEquals("HELO client\r\n", echoBack(tunnel, "HELO client\r\n"));
        // On the tunnel the CONNECT opened: no TLS with the server was tried.
        assertEquals(List.of(forwarded(target(smtp))), corpSaw);
    }

    @ParameterizedTest
    @EnumSource(Way.class)
    void plainHttpToATcpHostIsRelayedAsBytesThroughTheProxy(Way way) throws Exception {
        HttpServer origin = TestSupport.origin(TestSupport.echo());
        closeables.add(() -> origin.stop(0));
        // (The client's proxy resolves the name.)
        String target = "tcp.test:" + origin.getAddress().getPort();
        List<String> seen = new CopyOnWriteArrayList<>();
        start(way, microProxy().withTcpHosts("^tcp\\.test$").withFiltersSource(recording(seen)));
        Socket tunnel = session().tunnel(target);
        String head = request(tunnel, "GET /raw HTTP/1.1", target);
        assertTrue(head.startsWith("HTTP/1.1 200"), head);
        String body = body(tunnel, head);
        assertEquals("/raw", echoedUri(body));
        // Not through MicroProxy's filters.
        assertEquals(List.of(), echoedHeader(body, "via"));
        assertTrue(seen.stream().noneMatch(s -> s.startsWith("GET /raw")), seen.toString());
        assertEquals(List.of(forwarded(target)), corpSaw);
    }

    // -------------------------------------------------------------------------------------------
    // The TCP hooks
    // -------------------------------------------------------------------------------------------

    @ParameterizedTest
    @EnumSource(Way.class)
    void tcpHooksSeeATunnelThatCarriesNoTls(Way way) throws Exception {
        TestSupport.RawServer echo = echoServer();
        List<String> seen = new CopyOnWriteArrayList<>();
        CountDownLatch ended = new CountDownLatch(1);
        start(way, microProxy().withTcpInterceptor(shouting(seen, ended)));
        Socket tunnel = session().tunnel(target(echo));
        assertEquals("SHOUTED THROUGH THE PROXY", echoBack(tunnel, "shouted through the proxy"));
        tunnel.close();
        assertTrue(ended.await(10, TimeUnit.SECONDS), seen.toString());
        assertEquals("> shouted through the proxy", seen.getFirst());
        assertEquals("end " + target(echo) + " tls=false", seen.getLast());
        assertEquals(List.of(forwarded(target(echo))), corpSaw);
    }

    @ParameterizedTest
    @EnumSource(Way.class)
    void tlsThatDoesNotCarryHttpIsRelayedDecryptedThroughTheProxy(Way way) throws Exception {
        SSLContext context = serverCa.serverContext("localhost", "127.0.0.1");
        List<List<String>> offered = new CopyOnWriteArrayList<>();
        // An IMAP-like server over TLS that speaks first: ALPN imap, a greeting, then an answer per line.
        TestSupport.RawServer imaps = rawServer(accepted -> {
            SSLSocket s = (SSLSocket) context.getSocketFactory().createSocket(accepted, null, true);
            s.setUseClientMode(false);
            s.setHandshakeApplicationProtocolSelector((socket, protocols) -> {
                offered.add(List.copyOf(protocols));
                return protocols.contains("imap") ? "imap" : null;
            });
            s.setSoTimeout(20_000);
            s.startHandshake();
            write(s.getOutputStream(), "* OK ready\r\n");
            while (true) {
                String line = readUntil(s.getInputStream(), "\r\n");
                if (line.isEmpty()) return;
                write(s.getOutputStream(), "a OK " + line);
            }
        });
        String target = "localhost:" + imaps.port();
        List<String> seen = new CopyOnWriteArrayList<>();
        CountDownLatch ended = new CountDownLatch(1);
        start(way, microProxy().withTcpInterceptor(shouting(seen, ended)));
        // The client trusts only MicroProxy's CA: the TLS inside the proxy's tunnel is intercepted.
        SSLSocket tls = startTls(session().tunnel(target), "localhost", proxyCa.clientContext(), "imap");
        // The server was offered the client's protocol, and chose it for both.
        assertEquals("imap", tls.getApplicationProtocol());
        assertEquals("* OK ready\r\n", readUntil(tls.getInputStream(), "\r\n"));
        write(tls.getOutputStream(), "login\r\n");
        assertEquals("a OK LOGIN\r\n", readUntil(tls.getInputStream(), "\r\n"));
        tls.close();
        assertTrue(ended.await(10, TimeUnit.SECONDS), seen.toString());
        assertEquals(List.of(List.of("imap")), offered);
        assertEquals(List.of("< * OK ready\r\n", "> login\r\n", "< a OK LOGIN\r\n",
                "end " + target + " tls=true sni=localhost alpn=imap"), seen);
        assertEquals(List.of(forwarded(target)), corpSaw);
    }

    @ParameterizedTest
    @EnumSource(Way.class)
    void interceptedTlsInTheTunnelReachesTheServerThroughTheProxy(Way way) throws Exception {
        HttpsServer origin = TestSupport.httpsOrigin(serverCa.serverContext("localhost", "127.0.0.1"),
                TestSupport.echo());
        closeables.add(() -> origin.stop(0));
        String target = "localhost:" + origin.getAddress().getPort();
        List<String> seen = new CopyOnWriteArrayList<>();
        start(way, microProxy().withFiltersSource(recording(seen)));
        SSLSocket tls = startTls(session().tunnel(target), "localhost", proxyCa.clientContext(), "http/1.1");
        assertEquals(proxyCa.getCertificate().getSubjectX500Principal().getName(), TlsHellos.issuer(tls));
        String response = TlsHellos.get(tls, target, "/inner");
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        assertTrue(response.contains("h:x-filtered: mp"), response);
        assertEquals(List.of(forwarded(target)), corpSaw);
        assertTrue(seen.containsAll(List.of("connected " + target + " through " + corpTarget(),
                "GET /inner via=" + corpTarget())), seen.toString());
    }
}
