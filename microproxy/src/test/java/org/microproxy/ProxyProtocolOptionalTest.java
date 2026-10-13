package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.extras.AccessLogFormat;
import org.microproxy.stats.Counter;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * {@link ProxyProtocolMode#OPTIONAL}: a PROXY header (v1 or v2) is read when a connection starts
 * with one and the connection is served as it came otherwise, on every listener that reads PROXY
 * headers; trusted sources; and the bounded wait for a header that has begun.
 */
class ProxyProtocolOptionalTest {

    /** HTTP/1.1 {@code GET /} through the proxy to {@code origin}, closing the connection after. */
    private static String get(HttpServer origin) {
        return "GET http://127.0.0.1:" + origin.getAddress().getPort() + "/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    }

    private static final String V1_TCP4 = "PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\n";

    /** The v2 signature, version 2, and {@code command} (0 LOCAL, 1 PROXY), then the rest. */
    private static byte[] v2(int command, int family, byte[] addresses) {
        byte[] header = new byte[16 + addresses.length];
        System.arraycopy(new byte[] {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}, 0,
                header, 0, 12);
        header[12] = (byte) (0x20 | command);
        header[13] = (byte) family;
        header[14] = (byte) (addresses.length >> 8);
        header[15] = (byte) addresses.length;
        System.arraycopy(addresses, 0, header, 16, addresses.length);
        return header;
    }

    /** A v2 PROXY TCP4 header: 192.0.2.9:8080 to 10.0.0.1:443. */
    private static final byte[] V2_TCP4 = v2(1, 0x11, new byte[] {
        (byte) 192, 0, 2, 9, 10, 0, 0, 1, 0x1F, (byte) 0x90, 0x01, (byte) 0xBB});

    /** A v2 PROXY TCP6 header: [2001:db8::7]:4242 to [2001:db8::1]:443. */
    private static final byte[] V2_TCP6;

    static {
        byte[] addresses = new byte[36];
        addresses[0] = 0x20;
        addresses[1] = 0x01;
        addresses[2] = 0x0d;
        addresses[3] = (byte) 0xb8;
        addresses[15] = 7;
        addresses[16] = 0x20;
        addresses[17] = 0x01;
        addresses[18] = 0x0d;
        addresses[19] = (byte) 0xb8;
        addresses[31] = 1;
        addresses[32] = 0x10;
        addresses[33] = (byte) 0x92;
        addresses[34] = 0x01;
        addresses[35] = (byte) 0xBB;
        V2_TCP6 = v2(1, 0x21, addresses);
    }

    private HttpServer origin;
    private HttpProxyServer proxy;
    /** The client address each connection reported to {@code clientConnected}. */
    private final List<InetSocketAddress> connected = new CopyOnWriteArrayList<>();
    /** Each exchange's {@code %DOWNSTREAM_REMOTE_ADDRESS%} and {@code %DOWNSTREAM_DIRECT_REMOTE_ADDRESS_WITHOUT_PORT%}. */
    private final List<String> logged = new CopyOnWriteArrayList<>();
    private final AtomicInteger timedOut = new AtomicInteger();

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(TestSupport.fixed(200, "ok"));
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private HttpProxyServer start(HttpProxyServerBootstrap bootstrap) {
        AccessLogFormat format = AccessLogFormat.envoy(
                "%DOWNSTREAM_REMOTE_ADDRESS% %DOWNSTREAM_DIRECT_REMOTE_ADDRESS_WITHOUT_PORT%");
        proxy = bootstrap.withPort(0).withMetrics(true).plusActivityTracker(new ActivityTracker() {
            @Override
            public void clientConnected(FlowContext flowContext) {
                connected.add(flowContext.getClientAddress());
            }

            @Override
            public void flowEnded(FlowRecord record) {
                logged.add(format.format(record));
            }

            @Override
            public void connectionTimedOut(FlowContext flowContext) {
                timedOut.incrementAndGet();
            }
        }).start();
        return proxy;
    }

    private HttpProxyServer optional() {
        return start(MicroProxy.bootstrap().withAcceptProxyProtocol(ProxyProtocolMode.OPTIONAL));
    }

    private long count(String name) {
        return proxy.getStats().get(name) instanceof Counter c ? c.value() : 0;
    }

    private Socket connect() throws IOException {
        Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort());
        s.setSoTimeout(20_000);
        s.setTcpNoDelay(true);
        return s;
    }

    /** Sends {@code prefix} then {@code request}, and reads everything until the proxy closes. */
    private String exchange(byte[] prefix, String request) throws IOException {
        try (Socket s = connect()) {
            OutputStream out = s.getOutputStream();
            out.write(prefix);
            out.write(request.getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            return new String(s.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
        }
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private void assertClient(String address, int port) {
        eventually("a client connection", () -> !connected.isEmpty());
        InetSocketAddress client = connected.getLast();
        assertEquals(address, client.getAddress().getHostAddress());
        assertEquals(port, client.getPort());
        String expected = client.getAddress() instanceof java.net.Inet6Address
                ? "[" + address + "]:" + port : address + ":" + port;
        // The TCP peer (the load balancer) stays in the logs as the direct remote address. (An
        // earlier connection's record may come after this one's: it is written once that
        // connection has closed.)
        String line = expected + " " + proxy.getListenAddress().getAddress().getHostAddress();
        eventually("the access log record " + line + " in " + logged, () -> logged.contains(line));
    }

    private void assertTcpPeer() {
        eventually("a client connection", () -> !connected.isEmpty());
        assertTrue(connected.getLast().getAddress().isLoopbackAddress(), connected.toString());
    }

    @Test
    void v1HeaderIsReadAndNamesTheClient() throws Exception {
        optional();
        String response = exchange(ascii(V1_TCP4), get(origin));
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        assertClient("203.0.113.7", 51234);
        assertEquals(1, count("proxy_proto.v1.found"));
    }

    @Test
    void v1UnknownKeepsTheTcpPeer() throws Exception {
        optional();
        String response = exchange(ascii("PROXY UNKNOWN\r\n"), get(origin));
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        assertTcpPeer();
    }

    @Test
    void v2Tcp4HeaderIsRead() throws Exception {
        optional();
        String response = exchange(V2_TCP4, get(origin));
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        assertClient("192.0.2.9", 8080);
        assertEquals(1, count("proxy_proto.v2.found"));
    }

    @Test
    void v2Tcp6HeaderIsRead() throws Exception {
        optional();
        String response = exchange(V2_TCP6, get(origin));
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        assertClient("2001:db8:0:0:0:0:0:7", 4242);
    }

    @Test
    void v2LocalAndUnspecifiedKeepTheTcpPeer() throws Exception {
        optional();
        // LOCAL (a health check from the load balancer itself), then PROXY with an unspecified family.
        assertTrue(exchange(v2(0, 0x00, new byte[0]), get(origin)).startsWith("HTTP/1.1 200"));
        assertTcpPeer();
        connected.clear();
        assertTrue(exchange(v2(1, 0x00, new byte[0]), get(origin)).startsWith("HTTP/1.1 200"));
        assertTcpPeer();
        assertEquals(2, count("proxy_proto.v2.found"));
    }

    @Test
    void plainHttpWithoutHeaderIsServed() throws Exception {
        optional();
        String response = exchange(new byte[0], get(origin));
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        assertTcpPeer();
        assertEquals(1, count("proxy_proto.not_found_allowed"));
    }

    @Test
    void requestsThatStartLikeASignatureLoseNothing() throws Exception {
        optional();
        // "PRO" matches "PROXY " so far; "\r\n" matches the v2 signature so far. Neither is consumed.
        String port = String.valueOf(origin.getAddress().getPort());
        String response = exchange(new byte[0],
                "PROPFIND http://127.0.0.1:" + port + "/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        response = exchange(ascii("\r\n"), get(origin));
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        assertEquals(2, count("proxy_proto.not_found_allowed"));
    }

    @Test
    void byteAtATimeClientsAreReadWhole() throws Exception {
        optional();
        for (byte[] prefix : List.of(ascii(V1_TCP4), V2_TCP4, new byte[0])) {
            connected.clear();
            byte[] request = ascii(get(origin));
            try (Socket s = connect()) {
                OutputStream out = s.getOutputStream();
                for (byte b : prefix) {
                    out.write(b);
                    out.flush();
                    Thread.sleep(2);
                }
                for (byte b : request) {
                    out.write(b);
                    out.flush();
                }
                String response = new String(s.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
                assertTrue(response.startsWith("HTTP/1.1 200"), response);
            }
            if (prefix.length == 0) {
                assertTcpPeer();
            } else {
                eventually("a client connection", () -> !connected.isEmpty());
                assertEquals(prefix[0] == 'P' ? "203.0.113.7" : "192.0.2.9",
                        connected.getLast().getAddress().getHostAddress());
            }
        }
    }

    @Test
    void aSignatureThatStallsIsClosedWithinTheDeadline() throws Exception {
        // The deadline is the idle timeout here, which is shorter than the PROXY header timeout.
        start(MicroProxy.bootstrap().withAcceptProxyProtocol(ProxyProtocolMode.OPTIONAL)
                .withIdleConnectionTimeout(Duration.ofMillis(500)));
        for (byte[] partial : List.of(ascii("PROX"), new byte[] {0x0D, 0x0A, 0x0D, 0x0A, 0x00}, ascii("PROXY TCP4 1.2"))) {
            try (Socket s = connect()) {
                s.getOutputStream().write(partial);
                s.getOutputStream().flush();
                assertEquals(-1, s.getInputStream().read(), "closed without an answer");
            }
        }
        assertTrue(connected.isEmpty(), "no client connection was taken as started: " + connected);
        eventually("three timeouts", () -> timedOut.get() == 3);
        assertEquals(1, count("proxy_proto.v1.error"));
    }

    @Test
    void aHeaderDrippedSlowerThanTheDeadlineIsClosed() throws Exception {
        // Each byte comes well within the idle timeout, but the header as a whole does not.
        start(MicroProxy.bootstrap().withAcceptProxyProtocol(ProxyProtocolMode.OPTIONAL)
                .withIdleConnectionTimeout(Duration.ofSeconds(1)));
        try (Socket s = connect()) {
            OutputStream out = s.getOutputStream();
            try {
                for (byte b : ascii(V1_TCP4)) {
                    out.write(b);
                    out.flush();
                    Thread.sleep(100);
                }
            } catch (IOException closed) {
                // the proxy gave up on the header
            }
            assertEquals(-1, readOrEnd(s.getInputStream()));
        }
        assertTrue(connected.isEmpty(), connected.toString());
        eventually("a timeout", () -> timedOut.get() == 1);
    }

    /** The next byte, or -1 at the end of the stream or when the peer reset the connection. */
    private static int readOrEnd(InputStream in) {
        try {
            return in.read();
        } catch (IOException reset) {
            return -1;
        }
    }

    @Test
    void tlsListenerServesClientHelloWithOrWithoutHeader() throws Exception {
        SelfSignedSslContextSource tls = new SelfSignedSslContextSource();
        start(MicroProxy.bootstrap().withSslContextSource(tls).withAcceptProxyProtocol(ProxyProtocolMode.OPTIONAL));
        for (boolean header : new boolean[] {false, true}) {
            connected.clear();
            logged.clear();
            try (Socket plain = connect()) {
                if (header) TestSupport.write(plain.getOutputStream(), V1_TCP4);
                SSLSocket secure = (SSLSocket) tls.getSslContext().getSocketFactory()
                        .createSocket(plain, "127.0.0.1", plain.getPort(), true);
                secure.startHandshake();
                TestSupport.write(secure.getOutputStream(), get(origin));
                String response = new String(secure.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
                assertTrue(response.startsWith("HTTP/1.1 200"), response);
            }
            if (header) {
                assertClient("203.0.113.7", 51234);
            } else {
                assertTcpPeer();
            }
        }
    }

    @Test
    void socksListenerReadsTheHeaderFirst() throws Exception {
        start(MicroProxy.bootstrap().withSocksServer(true).withAcceptProxyProtocol(ProxyProtocolMode.OPTIONAL));
        for (byte[] prefix : List.of(V2_TCP4, new byte[0])) {
            connected.clear();
            try (SocksClient socks = new SocksClient(proxy)) {
                socks.out.write(prefix);
                assertEquals(0, socks.open("127.0.0.1", origin.getAddress().getPort()));
                TestSupport.write(socks.out, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
                String response = new String(socks.in.readAllBytes(), StandardCharsets.ISO_8859_1);
                assertTrue(response.startsWith("HTTP/1.1 200"), response);
            }
            if (prefix.length > 0) {
                eventually("a client connection", () -> !connected.isEmpty());
                assertEquals("192.0.2.9", connected.getLast().getAddress().getHostAddress());
            } else {
                assertTcpPeer();
            }
        }
    }

    @Test
    void h2cOnlyListenerReadsTheHeaderBeforeThePreface() throws Exception {
        start(MicroProxy.bootstrap().withHttp2CleartextOnly(true).withAcceptProxyProtocol(ProxyProtocolMode.OPTIONAL));
        // Not a preface either way: the listener answers SETTINGS then GOAWAY PROTOCOL_ERROR, which
        // shows the header was taken off first (it would otherwise be the bad preface).
        byte[] expected = {
            0, 0, 0, 0x4, 0, 0, 0, 0, 0,
            0, 0, 8, 0x7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1
        };
        for (byte[] prefix : List.of(ascii(V1_TCP4), new byte[0])) {
            String answer = exchange(prefix, "GET / HTTP/1.1\r\n\r\n");
            assertArrayEquals(expected, answer.getBytes(StandardCharsets.ISO_8859_1));
        }
        assertEquals(1, count("proxy_proto.v1.found"));
        assertEquals(1, count("proxy_proto.not_found_allowed"));
    }

    @Test
    void headersFromUntrustedPeersAreRejected() throws Exception {
        start(MicroProxy.bootstrap().withAcceptProxyProtocol(ProxyProtocolMode.OPTIONAL)
                .withProxyProtocolTrustedSources("192.0.2.0/24", "2001:db8::/32"));
        // The test client is on loopback, which is not trusted: its header is refused, and the
        // connection closed rather than served with either address.
        assertEquals("", exchange(ascii(V1_TCP4), get(origin)));
        assertEquals("", exchange(V2_TCP4, get(origin)));
        assertTrue(connected.isEmpty(), connected.toString());
        // Without a header it is served as it came.
        assertTrue(exchange(new byte[0], get(origin)).startsWith("HTTP/1.1 200"));
        assertTcpPeer();
        assertEquals(2, count("proxy_proto.untrusted_source"));
    }

    @Test
    void headersFromTrustedPeersAreHonored() throws Exception {
        start(MicroProxy.bootstrap().withAcceptProxyProtocol(ProxyProtocolMode.OPTIONAL)
                .withProxyProtocolTrustedSources("127.0.0.0/8", "::1"));
        assertTrue(exchange(ascii(V1_TCP4), get(origin)).startsWith("HTTP/1.1 200"));
        assertClient("203.0.113.7", 51234);
    }

    @Test
    void requiredModeClosesUntrustedPeersWithOrWithoutHeader() throws Exception {
        start(MicroProxy.bootstrap().withAcceptProxyProtocol(ProxyProtocolMode.REQUIRED)
                .withProxyProtocolTrustedSources("192.0.2.10"));
        assertEquals("", exchange(ascii(V1_TCP4), get(origin)));
        assertEquals("", exchange(new byte[0], get(origin)));
        assertTrue(connected.isEmpty(), connected.toString());
        assertEquals(2, count("proxy_proto.untrusted_source"));
    }

    @Test
    void requiredModeStillRejectsAConnectionWithoutHeader() throws Exception {
        start(MicroProxy.bootstrap().withAcceptProxyProtocol(ProxyProtocolMode.REQUIRED));
        assertEquals("", exchange(new byte[0], get(origin)));
        assertEquals("", exchange(ascii("\r\n"), get(origin)));
        assertTrue(connected.isEmpty(), connected.toString());
        assertEquals(2, count("proxy_proto.not_found_disallowed"));
        // A header is read as before, byte at a time too.
        logged.clear();
        try (Socket s = connect()) {
            OutputStream out = s.getOutputStream();
            for (byte b : V2_TCP6) {
                out.write(b);
                out.flush();
            }
            TestSupport.write(out, get(origin));
            ByteArrayOutputStream response = new ByteArrayOutputStream();
            s.getInputStream().transferTo(response);
            assertTrue(response.toString(StandardCharsets.ISO_8859_1).startsWith("HTTP/1.1 200"), response.toString());
        }
        assertClient("2001:db8:0:0:0:0:0:7", 4242);
    }

    @Test
    void adminShowsTheModeAndTrustedSources() throws Exception {
        start(MicroProxy.bootstrap().withAdmin(new InetSocketAddress(TestSupport.LOOPBACK, 0))
                .withAcceptProxyProtocol(ProxyProtocolMode.OPTIONAL).withProxyProtocolTrustedSources("10.0.0.0/8"));
        java.net.http.HttpClient http = java.net.http.HttpClient.newHttpClient();
        String admin = "http://127.0.0.1:" + proxy.getAdminAddress().getPort();
        String dump = http.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(admin + "/config_dump")).build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()).body();
        java.util.Map<?, ?> bootstrap = (java.util.Map<?, ?>) ((java.util.Map<?, ?>) ((List<?>) ((java.util.Map<?, ?>)
                AdminTest.Json.parse(dump)).get("configs")).get(0)).get("bootstrap");
        java.util.Map<?, ?> proxyProtocol = (java.util.Map<?, ?>) bootstrap.get("proxy_protocol");
        assertEquals(true, proxyProtocol.get("accept"));
        assertEquals("optional", proxyProtocol.get("mode"));
        assertEquals(List.of("10.0.0.0/8"), proxyProtocol.get("trusted_sources"));
        String listeners = http.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(admin + "/listeners")).build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()).body();
        assertTrue(listeners.contains("proxy_protocol_optional"), listeners);
    }

    @Test
    void launcherFlagsSetTheModeAndTrustedSources() throws Exception {
        java.io.PrintStream quiet = new java.io.PrintStream(OutputStream.nullOutputStream());
        HttpProxyServerBootstrap b = Launcher.parse(new String[] {"--port", "0", "--proxy-protocol-mode", "optional",
            "--proxy-protocol-trusted-sources", "10.0.0.0/8,192.0.2.1"}, quiet).bootstrap();
        assertEquals(ProxyProtocolMode.OPTIONAL, org.microproxy.impl.BootstrapView.proxyProtocolMode(b));
        assertEquals(List.of("10.0.0.0/8", "192.0.2.1"), org.microproxy.impl.BootstrapView.proxyProtocolTrustedSources(b));
        b = Launcher.parse(new String[] {"--port", "0", "--accept-proxy-protocol"}, quiet).bootstrap();
        assertEquals(ProxyProtocolMode.REQUIRED, org.microproxy.impl.BootstrapView.proxyProtocolMode(b));
        assertTrue(org.microproxy.impl.BootstrapView.proxyProtocolTrustedSources(b).isEmpty());
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> Launcher.parse(
                new String[] {"--proxy-protocol-mode", "sometimes"}, quiet));
    }

    @Test
    void sentHeaderCarriesTheReceivedSourceInEitherMode() throws Exception {
        CopyOnWriteArrayList<String> heads = new CopyOnWriteArrayList<>();
        try (TestSupport.RawServer raw = TestSupport.rawServer(s -> {
            heads.add(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n"));
            TestSupport.write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        })) {
            start(MicroProxy.bootstrap().withAcceptProxyProtocol(ProxyProtocolMode.OPTIONAL).withSendProxyProtocol(true));
            String request = "GET http://127.0.0.1:" + raw.port() + "/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
            assertTrue(exchange(ascii(V1_TCP4), request).startsWith("HTTP/1.1 200"));
            assertTrue(exchange(new byte[0], request).startsWith("HTTP/1.1 200"));
        }
        assertEquals(2, heads.size(), heads.toString());
        assertTrue(heads.get(0).startsWith(V1_TCP4 + "GET / HTTP/1.1\r\n"), heads.get(0));
        // Without a received header, the TCP peer is the source.
        assertTrue(heads.get(1).startsWith("PROXY TCP4 127.0.0.1 127.0.0.1 "), heads.get(1));
    }
}
