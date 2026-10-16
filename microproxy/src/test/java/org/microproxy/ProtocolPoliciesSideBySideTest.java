package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpServer;
import io.github.mahmoudimus.http2.HeaderField;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * One proxy, LittleProxy's policy for its HTTP/1.1 clients and MicroProxy's for its HTTP/2 (h2c)
 * clients: each field of {@link ProtocolPolicy#littleProxy()} applies to the first and not to the
 * second, set either way ({@code withLittleProxyCompatibility()}, or the preset as HTTP/1's own
 * policy).
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class ProtocolPoliciesSideBySideTest {

    static final CertificateAuthority originCa = CertificateAuthority.generate("Policies Origin CA");
    static final CertificateAuthority proxyCa = CertificateAuthority.generate("Policies Proxy CA");

    /** The two ways to give HTTP/1 clients LittleProxy's policy. */
    private static final List<UnaryOperator<HttpProxyServerBootstrap>> LITTLE_PROXY_FOR_HTTP1 = List.of(
            HttpProxyServerBootstrap::withLittleProxyCompatibility,
            b -> b.onHttp1(p -> p.preset(ProtocolPolicy.littleProxy())));

    private HttpProxyServer proxy;
    private final List<AutoCloseable> closeables = new CopyOnWriteArrayList<>();
    /** Each request's filter events, by "<client HTTP major version> <method> <uri>". */
    private final Map<String, List<String>> events = new ConcurrentHashMap<>();

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    private HttpProxyServerBootstrap h2c(UnaryOperator<HttpProxyServerBootstrap> littleProxyForHttp1) {
        if (proxy != null) proxy.abort();
        events.clear();
        return littleProxyForHttp1.apply(MicroProxy.bootstrap().withPort(0).withHttp2Cleartext(true)
                .withFiltersSource((request, ctx) -> new RecordingFilters(events.computeIfAbsent(
                        ctx.getHttpVersion().majorVersion() + " " + request.method() + " " + request.uri(),
                        k -> new CopyOnWriteArrayList<>()))));
    }

    private List<String> eventsOf(String key) {
        TestSupport.eventually("the events of " + key, () -> events.containsKey(key));
        return events.get(key);
    }

    private HttpServer origin() {
        HttpServer origin = TestSupport.origin(TestSupport.fixed(200, "ok"));
        closeables.add(() -> origin.stop(0));
        return origin;
    }

    private static String authority(HttpServer server) {
        return "127.0.0.1:" + server.getAddress().getPort();
    }

    /** Sends {@code head} over a new HTTP/1.1 connection to the proxy and reads until it closes. */
    private String http1(String head) throws IOException {
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            s.setSoTimeout(20_000);
            write(s.getOutputStream(), head);
            return new String(s.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
        }
    }

    private H2TestClient h2(String authority) throws IOException {
        H2TestClient c = H2TestClient.cleartext(proxy.getListenAddress(), authority).handshake();
        closeables.add(c);
        return c;
    }

    private static List<String> untilSending(List<String> events) {
        return events.subList(0, events.indexOf("proxyToServerRequestSending"));
    }

    @Test
    void resolveBeforeProxyToServerRequest() throws Exception {
        HttpServer origin = origin();
        for (UnaryOperator<HttpProxyServerBootstrap> how : LITTLE_PROXY_FOR_HTTP1) {
            proxy = h2c(how).start();
            String uri = "http://" + authority(origin) + "/";
            assertTrue(http1("GET " + uri + " HTTP/1.1\r\nHost: " + authority(origin) + "\r\nConnection: close\r\n\r\n")
                    .startsWith("HTTP/1.1 200"));
            H2TestClient c = h2(authority(origin));
            c.get(1, "/");
            assertEquals(200, c.response(1).status());
            assertEquals(List.of("clientToProxyRequest:head", "proxyToServerResolutionStarted",
                    "proxyToServerResolutionSucceeded", "proxyToServerRequest:head", "proxyToServerConnectionStarted",
                    "proxyToServerConnectionSucceeded"), untilSending(eventsOf("1 GET " + uri)));
            assertEquals(List.of("clientToProxyRequest:head", "proxyToServerRequest:head",
                    "proxyToServerResolutionStarted", "proxyToServerResolutionSucceeded",
                    "proxyToServerConnectionStarted", "proxyToServerConnectionSucceeded"),
                    untilSending(eventsOf("2 GET " + uri)));
        }
    }

    @Test
    void filterConnectAnswer() throws Exception {
        try (TestSupport.RawServer echo = TestSupport.rawServer(s -> s.getInputStream().transferTo(s.getOutputStream()))) {
            String target = "127.0.0.1:" + echo.port();
            for (UnaryOperator<HttpProxyServerBootstrap> how : LITTLE_PROXY_FOR_HTTP1) {
                proxy = h2c(how).start();
                try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
                    s.setSoTimeout(20_000);
                    write(s.getOutputStream(), "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
                    assertTrue(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 200"));
                }
                try (H2StreamClient c = H2StreamClient.cleartext(proxy.getListenAddress(), "unused:1")) {
                    H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target), false);
                    assertEquals(200, tunnel.status());
                    tunnel.end();
                }
                List<String> http1 = eventsOf("1 CONNECT " + target);
                List<String> http2 = eventsOf("2 CONNECT " + target);
                // (Both clients had their answers, written after the hooks ran.)
                assertFalse(http1.contains("proxyToClientResponse:full"), http1.toString());
                assertTrue(http2.contains("proxyToClientResponse:full"), http2.toString());
            }
        }
    }

    @Test
    void servePlainHttpAfterConnect() throws Exception {
        HttpServer origin = origin();
        String target = authority(origin);
        for (UnaryOperator<HttpProxyServerBootstrap> how : LITTLE_PROXY_FOR_HTTP1) {
            // (The preset's eager handshake would wait for a TLS answer the plain server never sends:
            // this field is about what the client's first bytes decide.)
            proxy = h2c(how).withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                    .onHttp1(p -> p.mitmServerHandshake(MitmServerHandshake.DEFERRED)).start();
            try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
                s.setSoTimeout(20_000);
                write(s.getOutputStream(), "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
                InputStream in = s.getInputStream();
                assertTrue(TestSupport.readUntil(in, "\r\n\r\n").startsWith("HTTP/1.1 200"));
                write(s.getOutputStream(), "GET /from-http1 HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n");
                assertTrue(new String(in.readAllBytes(), StandardCharsets.ISO_8859_1).startsWith("HTTP/1.1 200"));
            }
            try (H2StreamClient c = H2StreamClient.cleartext(proxy.getListenAddress(), "unused:1")) {
                H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target), false);
                assertEquals(200, tunnel.status());
                write(tunnel.out(), "GET /from-http2 HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n");
                assertTrue(tunnel.text().startsWith("HTTP/1.1 200"));
            }
            // The HTTP/2 client's CONNECT is HTTP/2's to decide: its plain HTTP is served as HTTP,
            // by a connection inside the stream; the HTTP/1 client's is relayed as bytes.
            assertTrue(events.keySet().stream().anyMatch(k -> k.endsWith("GET /from-http2")), events.keySet().toString());
            assertFalse(events.keySet().stream().anyMatch(k -> k.endsWith("GET /from-http1")), events.keySet().toString());
        }
    }

    /** A server that answers each request with the PROXY header its connection started with. */
    private TestSupport.RawServer proxyHeaderEcho() {
        TestSupport.RawServer raw = TestSupport.rawServer(socket -> {
            InputStream in = socket.getInputStream();
            String header = TestSupport.readUntil(in, "\r\n").strip();
            TestSupport.readUntil(in, "\r\n\r\n");
            write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                    + header.length() + "\r\n\r\n" + header);
        });
        closeables.add(raw);
        return raw;
    }

    @Test
    void proxyProtocolDestination() throws Exception {
        TestSupport.RawServer raw = proxyHeaderEcho();
        String target = "127.0.0.1:" + raw.port();
        for (UnaryOperator<HttpProxyServerBootstrap> how : LITTLE_PROXY_FOR_HTTP1) {
            proxy = h2c(how).withSendProxyProtocol(true).start();
            String fromHttp1 = http1("GET http://" + target + "/ HTTP/1.1\r\nHost: " + target
                    + "\r\nConnection: close\r\n\r\n");
            H2TestClient c = h2(target);
            c.get(1, "/");
            String fromHttp2 = c.response(1).text();
            // PROXY TCP4 <src> <dst> <srcport> <dstport>
            String http1Header = fromHttp1.substring(fromHttp1.indexOf("PROXY "));
            assertEquals(String.valueOf(raw.port()), http1Header.split(" ")[5].strip(), "HTTP/1: the server's address");
            assertEquals(String.valueOf(proxy.getListenAddress().getPort()), fromHttp2.split(" ")[5].strip(),
                    "HTTP/2: the address the client connected to");
        }
    }

    @Test
    void tlsRetryWithoutSni() throws Exception {
        try (TlsRetryWithoutSniTest.PickyOrigin picky = new TlsRetryWithoutSniTest.PickyOrigin(
                TlsRetryWithoutSniTest.originCa.serverContext("localhost", "127.0.0.1"))) {
            String target = "localhost:" + picky.port();
            for (UnaryOperator<HttpProxyServerBootstrap> how : LITTLE_PROXY_FOR_HTTP1) {
                proxy = h2c(how).withManInTheMiddle(new CertificateAuthorityMitmManager(TlsRetryWithoutSniTest.proxyCa,
                        TlsRetryWithoutSniTest.originCa.clientContext())).start();
                // https:// requests the proxy opens TLS for. HTTP/2's first: a session the
                // retry made could be resumed with SNI.
                H2TestClient c = h2(target);
                List<HeaderField> head = new ArrayList<>(List.of(new HeaderField(":method", "GET"),
                        new HeaderField(":scheme", "https"), new HeaderField(":authority", target),
                        new HeaderField(":path", "/")));
                c.headers(1, head, true);
                assertEquals(502, c.response(1).status(), "HTTP/2 keeps MicroProxy's default: no retry");
                String fromHttp1 = http1("GET https://" + target + "/ HTTP/1.1\r\nHost: " + target
                        + "\r\nConnection: close\r\n\r\n");
                assertTrue(fromHttp1.startsWith("HTTP/1.1 200"), fromHttp1);
                assertTrue(fromHttp1.contains("X-Sni: none"), fromHttp1);
            }
        }
    }

    @Test
    void mitmServerHandshake() throws Exception {
        // A server whose certificate the proxy does not trust: its handshake fails.
        CertificateAuthority stranger = CertificateAuthority.generate("Policies Stranger CA");
        com.sun.net.httpserver.HttpsServer untrusted = TestSupport.httpsOrigin(
                stranger.serverContext("localhost", "127.0.0.1"), TestSupport.fixed(200, "stranger"));
        closeables.add(() -> untrusted.stop(0));
        String target = "localhost:" + untrusted.getAddress().getPort();
        for (UnaryOperator<HttpProxyServerBootstrap> how : LITTLE_PROXY_FOR_HTTP1) {
            proxy = h2c(how).withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                    .start();
            // HTTP/1: LittleProxy's eager handshake fails the CONNECT itself.
            String fromHttp1 = http1("CONNECT " + target + " HTTP/1.1\r\nHost: " + target
                    + "\r\nConnection: close\r\n\r\n");
            assertTrue(fromHttp1.startsWith("HTTP/1.1 502"), fromHttp1);
            // HTTP/2: deferred, the CONNECT stream is answered 200 before the server's handshake.
            try (H2StreamClient c = H2StreamClient.cleartext(proxy.getListenAddress(), "unused:1")) {
                H2StreamClient.Stream tunnel = c.open(H2StreamClient.connect(target), false);
                assertEquals(200, tunnel.status());
                tunnel.end();
            }
        }
    }

    @Test
    void allowChunkedLengthIsHttp1sOwn() throws Exception {
        HttpServer origin = origin();
        String target = authority(origin);
        String both = "POST http://" + target + "/ HTTP/1.1\r\nHost: " + target
                + "\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        proxy = h2c(UnaryOperator.identity()).onHttp1(p -> p.allowChunkedLength(true)).start();
        assertTrue(http1(both).startsWith("HTTP/1.1 200"));
        proxy = h2c(UnaryOperator.identity()).withAllowChunkedLength(true).onHttp1(p -> p.allowChunkedLength(false))
                .start();
        assertTrue(http1(both).startsWith("HTTP/1.1 400"), "HTTP/1's own policy wins over the server's setting");
        proxy = h2c(HttpProxyServerBootstrap::withLittleProxyCompatibility).start();
        assertTrue(http1(both).startsWith("HTTP/1.1 400"), "LittleProxy refuses them too");
    }
}
