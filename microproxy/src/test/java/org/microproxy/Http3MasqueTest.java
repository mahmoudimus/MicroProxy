package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.eventually;

import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3ErrorCode;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.SelfSignedSslContextSource;
import org.microproxy.udp.UdpContext;
import org.microproxy.udp.UdpInterceptor;
import org.microproxy.udp.UdpMessage;

/**
 * CONNECT-UDP (MASQUE, RFC 9298) on a forward proxy's HTTP/3 listener: UDP payloads to a UDP echo
 * server and back in HTTP Datagrams (RFC 9297), over QUIC DATAGRAM frames and over DATAGRAM
 * capsules; filters, authentication and routing deciding on the target; the URI template; the
 * bounds on flows, queues and idle time; and the UDP hooks.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class Http3MasqueTest {

    private static final SelfSignedSslContextSource TLS = new SelfSignedSslContextSource();

    private HttpProxyServer proxy;
    private final List<AutoCloseable> closeables = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable c : closeables) c.close();
        if (proxy != null) proxy.abort();
    }

    /** A UDP server on loopback that sends every datagram back, prefixed as {@code prefix} says. */
    static final class UdpEcho implements AutoCloseable {
        final DatagramSocket socket;
        final List<String> received = new CopyOnWriteArrayList<>();
        final AtomicInteger count = new AtomicInteger();
        volatile boolean silent;

        UdpEcho() throws SocketException {
            socket = new DatagramSocket(new InetSocketAddress(TestSupport.LOOPBACK, 0));
            Thread.ofVirtual().start(() -> {
                byte[] buf = new byte[65535];
                while (!socket.isClosed()) {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    try {
                        socket.receive(p);
                    } catch (IOException e) {
                        return;
                    }
                    count.incrementAndGet();
                    received.add(new String(p.getData(), 0, p.getLength(), StandardCharsets.UTF_8));
                    if (silent) continue;
                    try {
                        socket.send(new DatagramPacket(p.getData(), p.getLength(), p.getSocketAddress()));
                    } catch (IOException e) {
                        return;
                    }
                }
            });
        }

        int port() {
            return socket.getLocalPort();
        }

        @Override
        public void close() {
            socket.close();
        }
    }

    private UdpEcho echo() throws SocketException {
        UdpEcho e = new UdpEcho();
        closeables.add(e);
        return e;
    }

    private static HttpProxyServerBootstrap forwardProxy() {
        return MicroProxy.bootstrap().withPort(0).withProxyAlias("mq").withSslContextSource(TLS).withHttp3(true);
    }

    private String proxyAuthority() {
        return "localhost:" + proxy.getListenAddress().getPort();
    }

    private H3TestClient client(boolean datagrams) throws IOException {
        H3TestClient.Options options = new H3TestClient.Options();
        options.datagrams = datagrams;
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        H3TestClient c = H3TestClient.connect(address, "localhost", TLS.getCertificate(), options);
        closeables.add(c);
        return c;
    }

    private List<HeaderField> connectUdp(String path, HeaderField... fields) {
        List<HeaderField> extra = new ArrayList<>(List.of(new HeaderField("capsule-protocol", "?1")));
        extra.addAll(List.of(fields));
        return H3TestClient.extendedConnect("connect-udp", "https", proxyAuthority(), path, extra.toArray(HeaderField[]::new));
    }

    private static String wellKnown(String host, int port) {
        return "/.well-known/masque/udp/" + host + "/" + port + "/";
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** The UDP payload of the next HTTP Datagram the tunnel receives, as text. */
    private static String nextDatagram(H3TestClient.Tunnel tunnel) throws IOException {
        byte[] content = tunnel.receiveDatagram(Duration.ofSeconds(10));
        assertNotNull(content, "no datagram");
        return new String(H3TestClient.udpPayload(content), StandardCharsets.UTF_8);
    }

    /** The UDP payload of the next DATAGRAM capsule on the stream, skipping others, as text. */
    private static String nextCapsule(H3TestClient.Tunnel tunnel) throws IOException {
        while (true) {
            H3TestClient.Capsule c = tunnel.readCapsule();
            assertNotNull(c, "the stream ended");
            if (c.type() == 0) return new String(H3TestClient.udpPayload(c.value()), StandardCharsets.UTF_8);
        }
    }

    // -------------------------------------------------------------------------------------------
    // Relaying
    // -------------------------------------------------------------------------------------------

    @Test
    void udpGoesBothWaysInQuicDatagrams() throws Exception {
        UdpEcho udp = echo();
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = forwardProxy().withFiltersSource((original, ctx) -> new HttpFiltersAdapter(original, ctx) {
            @Override
            public HttpResponse clientToProxyRequest(HttpObject o) {
                HttpRequest r = (HttpRequest) o;
                seen.add(r.method() + " " + r.uri() + " " + r.protocolVersion() + " upgrade=" + r.headers().get("Upgrade"));
                return null;
            }

            @Override
            public HttpObject proxyToClientResponse(HttpObject o) {
                if (o instanceof HttpResponse r) seen.add(r.status().code() + " " + r.headers().get("Upgrade"));
                return o;
            }
        }).start();
        H3TestClient client = client(true);
        assertTrue(client.serverSettings().h3Datagram(), "SETTINGS_H3_DATAGRAM");
        H3TestClient.Tunnel flow = client.open(connectUdp(wellKnown("127.0.0.1", udp.port())));
        assertEquals(200, flow.status);
        assertEquals("?1", flow.header("capsule-protocol"));
        assertEquals("1.1 mq", flow.header("via"));
        for (int i = 0; i < 5; i++) {
            flow.sendDatagram(utf8("ping " + i));
            assertEquals("ping " + i, nextDatagram(flow));
        }
        // A payload of another context is dropped (RFC 9298 section 4).
        flow.sendDatagram(new byte[] {0x02, 'x'}, true);
        flow.sendDatagram(utf8("after"));
        assertEquals("after", nextDatagram(flow));
        assertEquals(List.of("ping 0", "ping 1", "ping 2", "ping 3", "ping 4", "after"), udp.received);
        assertEquals(List.of("GET " + wellKnown("127.0.0.1", udp.port()) + " HTTP/3.0 upgrade=connect-udp",
                "101 connect-udp"), seen);
        // The client's FIN ends the flow, and the proxy's comes back.
        flow.end();
        assertEquals(-1, flow.in().read());
    }

    @Test
    void aUdpFlowIsOneRecordWhenItEnds() throws Exception {
        UdpEcho udp = echo();
        RecordedFlows flows = new RecordedFlows();
        proxy = forwardProxy().plusActivityTracker(flows).start();
        H3TestClient client = client(true);
        H3TestClient.Tunnel flow = client.open(connectUdp(wellKnown("127.0.0.1", udp.port())));
        assertEquals(200, flow.status);
        for (int i = 0; i < 3; i++) {
            flow.sendDatagram(utf8("ping " + i));
            assertEquals("ping " + i, nextDatagram(flow));
        }
        flow.end();
        assertEquals(-1, flow.in().read());
        FlowRecord r = flows.await(FlowRecord.Kind.UDP);
        assertEquals(18, r.bytesReceived());
        assertEquals(18, r.bytesSent());
        assertEquals(18, r.upstreamBytesSent());
        assertEquals(18, r.upstreamBytesReceived());
        assertEquals(101, r.responseCode(), "the acceptance, as filters see it");
        assertTrue(r.responseFlags().isEmpty(), r.toString());
        assertEquals("udp HTTP/3", org.microproxy.extras.AccessLogFormat.envoy("%MP_FLOW% %PROTOCOL%").format(r));
    }

    @Test
    void udpGoesBothWaysInCapsulesWithoutQuicDatagrams() throws Exception {
        UdpEcho udp = echo();
        proxy = forwardProxy().start();
        H3TestClient client = client(false);
        H3TestClient.Tunnel flow = client.open(connectUdp(wellKnown("127.0.0.1", udp.port())));
        assertEquals(200, flow.status);
        // Unknown capsules are skipped (RFC 9297 section 3.2), large ones too.
        flow.sendCapsule(0x2a, new byte[100_000]);
        for (int i = 0; i < 5; i++) {
            flow.sendDatagramCapsule(utf8("capsule " + i));
            assertEquals("capsule " + i, nextCapsule(flow));
        }
        assertEquals(5, udp.count.get());
        flow.end();
        assertNull(flow.readCapsule());
    }

    @Test
    void datagramCapsulesWorkAlongsideQuicDatagrams() throws Exception {
        UdpEcho udp = echo();
        proxy = forwardProxy().start();
        H3TestClient.Tunnel flow = client(true).open(connectUdp(wellKnown("127.0.0.1", udp.port())));
        flow.sendDatagramCapsule(utf8("by capsule"));
        // The client accepts QUIC datagrams: the answer comes in one.
        assertEquals("by capsule", nextDatagram(flow));
        // A payload too large for a QUIC datagram goes as a capsule.
        byte[] large = new byte[4000];
        Arrays.fill(large, (byte) 'L');
        flow.sendDatagramCapsule(large);
        assertEquals(new String(large, StandardCharsets.UTF_8), nextCapsule(flow));
    }

    @Test
    void aCustomTemplateNamesTheTargetInTheQuery() throws Exception {
        UdpEcho udp = echo();
        proxy = forwardProxy().withHttp3Options(Http3Options.builder()
                .connectUdpTemplate("https://proxy.example/masque?h={target_host}&p={target_port}").build()).start();
        H3TestClient client = client(true);
        H3TestClient.Tunnel flow = client.open(connectUdp("/masque?h=127.0.0.1&p=" + udp.port()));
        assertEquals(200, flow.status);
        flow.sendDatagram(utf8("query"));
        assertEquals("query", nextDatagram(flow));
        // The well-known path is not this proxy's template.
        assertEquals(400, client.open(connectUdp(wellKnown("127.0.0.1", udp.port()))).status);
    }

    @Test
    void theClientsResetEndsTheFlow() throws Exception {
        UdpEcho udp = echo();
        AtomicInteger ended = new AtomicInteger();
        proxy = forwardProxy().withUdpInterceptor(new UdpInterceptor() {
            @Override
            public byte[] udpMessage(UdpMessage message, UdpContext context) {
                return message.data();
            }

            @Override
            public void udpEnd(UdpContext context) {
                ended.incrementAndGet();
            }
        }).start();
        H3TestClient client = client(true);
        H3TestClient.Tunnel flow = client.open(connectUdp(wellKnown("127.0.0.1", udp.port())));
        flow.sendDatagram(utf8("one"));
        assertEquals("one", nextDatagram(flow));
        flow.reset(Http3ErrorCode.H3_REQUEST_CANCELLED.code());
        eventually("the flow to end", () -> ended.get() == 1);
        // The connection goes on: another flow opens.
        H3TestClient.Tunnel again = client.open(connectUdp(wellKnown("127.0.0.1", udp.port())));
        assertEquals(200, again.status);
    }

    // -------------------------------------------------------------------------------------------
    // Policy
    // -------------------------------------------------------------------------------------------

    @Test
    void filtersAndRoutingDecideOnTheTarget() throws Exception {
        UdpEcho udp = echo();
        proxy = forwardProxy()
                .withFiltersSource((original, ctx) -> new HttpFiltersAdapter(original, ctx) {
                    @Override
                    public HttpResponse clientToProxyRequest(HttpObject o) {
                        HttpRequest r = (HttpRequest) o;
                        if (r.uri().contains("/53/")) {
                            return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN);
                        }
                        return null;
                    }
                })
                .withServerResolver((host, port) -> {
                    if (host.equals("echo.test")) return new InetSocketAddress(TestSupport.LOOPBACK, port);
                    if (host.endsWith(".test")) throw new UnknownHostException(host);
                    return new InetSocketAddress(java.net.InetAddress.getByName(host), port);
                })
                .start();
        H3TestClient client = client(true);
        assertEquals(403, client.open(connectUdp(wellKnown("127.0.0.1", 53))).status, "a filter refused the target");
        assertEquals(502, client.open(connectUdp(wellKnown("nowhere.test", 9))).status, "an unresolvable target");
        assertEquals(400, client.open(connectUdp(wellKnown("127.0.0.1", 0))).status, "no port 0");
        assertEquals(400, client.open(connectUdp("/somewhere/else")).status, "not the template");
        // The proxy's resolver names the target.
        H3TestClient.Tunnel flow = client.open(connectUdp(wellKnown("echo.test", udp.port())));
        assertEquals(200, flow.status);
        flow.sendDatagram(utf8("resolved"));
        assertEquals("resolved", nextDatagram(flow));
    }

    @Test
    void aRouteThroughChainedProxiesOnlyIsRefused() throws Exception {
        UdpEcho udp = echo();
        proxy = forwardProxy().withChainProxyManager((request, chained, details) -> chained.add(new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return new InetSocketAddress(TestSupport.LOOPBACK, 9);
            }
        })).start();
        assertEquals(502, client(true).open(connectUdp(wellKnown("127.0.0.1", udp.port()))).status);
    }

    @Test
    void proxyAuthenticationIsAskedForOnTheStream() throws Exception {
        UdpEcho udp = echo();
        proxy = forwardProxy().withProxyAuthenticator((user, password) -> "user".equals(user) && "secret".equals(password))
                .start();
        H3TestClient client = client(true);
        H3TestClient.Tunnel refused = client.open(connectUdp(wellKnown("127.0.0.1", udp.port())));
        assertEquals(407, refused.status);
        assertNotNull(refused.header("proxy-authenticate"));
        HeaderField credentials = new HeaderField("proxy-authorization",
                "Basic " + Base64.getEncoder().encodeToString(utf8("user:secret")));
        H3TestClient.Tunnel flow = client.open(connectUdp(wellKnown("127.0.0.1", udp.port()), credentials));
        assertEquals(200, flow.status);
        flow.sendDatagram(utf8("authorized"));
        assertEquals("authorized", nextDatagram(flow));
    }

    // -------------------------------------------------------------------------------------------
    // Bounds
    // -------------------------------------------------------------------------------------------

    @Test
    void flowsPerConnectionAndInTotalAreBounded() throws Exception {
        UdpEcho udp = echo();
        proxy = forwardProxy().withHttp3Options(Http3Options.builder().connectUdpMaxFlows(3, 2).build()).start();
        H3TestClient first = client(true);
        assertEquals(200, first.open(connectUdp(wellKnown("127.0.0.1", udp.port()))).status);
        H3TestClient.Tunnel second = first.open(connectUdp(wellKnown("127.0.0.1", udp.port())));
        assertEquals(200, second.status);
        assertEquals(503, first.open(connectUdp(wellKnown("127.0.0.1", udp.port()))).status, "two per connection");
        H3TestClient other = client(true);
        assertEquals(200, other.open(connectUdp(wellKnown("127.0.0.1", udp.port()))).status);
        assertEquals(503, other.open(connectUdp(wellKnown("127.0.0.1", udp.port()))).status, "three in total");
        // A flow that ends makes room by the time its client reads the end.
        second.end();
        assertEquals(-1, second.in().read());
        assertEquals(200, first.open(connectUdp(wellKnown("127.0.0.1", udp.port()))).status);
    }

    /**
     * A flow the client resets or ends gives its places back by the time a request on a stream it
     * opens right after is handled, at the connection's bound and the proxy's, every time, with the
     * wait for ending flows off. The old stream's reader may not have read the reset yet, each
     * stream being read on a thread of its own, but QUIC received it first, and a request that finds
     * a bound full asks QUIC.
     */
    @Test
    void aFlowRightAfterTheClientsEndOfAnotherFindsRoom() throws Exception {
        UdpEcho udp = echo();
        proxy = forwardProxy().withHttp3Options(Http3Options.builder().maxConcurrentStreams(1000)
                .connectUdpMaxFlows(3, 2).connectUdpReleaseWait(Duration.ZERO).build()).start();
        H3TestClient client = client(true);
        H3TestClient other = client(true);
        H3TestClient.Tunnel elsewhere = other.open(connectUdp(wellKnown("127.0.0.1", udp.port())));
        assertEquals(200, elsewhere.status);
        H3TestClient.Tunnel kept = client.open(connectUdp(wellKnown("127.0.0.1", udp.port())));
        assertEquals(200, kept.status);
        H3TestClient.Tunnel ending = client.open(connectUdp(wellKnown("127.0.0.1", udp.port())));
        assertEquals(200, ending.status);
        for (int i = 0; i < 200; i++) {
            if (i % 4 == 3) {
                ending.end();
            } else {
                ending.reset(Http3ErrorCode.H3_REQUEST_CANCELLED.code());
            }
            ending = client.open(connectUdp(wellKnown("127.0.0.1", udp.port())));
            assertEquals(200, ending.status, "the flow opened after " + i + " ended");
        }
        for (H3TestClient.Tunnel flow : List.of(kept, ending, elsewhere)) {
            flow.sendDatagram(utf8("still"));
            assertEquals("still", nextDatagram(flow));
        }
    }

    /**
     * A client that closes its QUIC connection gives its flows' places back as the proxy sees the
     * close, before the flows' own threads notice (held here at {@code udpStart}, so they cannot):
     * a flow opened on a new connection once the proxy has seen the close is accepted at the
     * proxy's bound, with its wait for ending flows off.
     */
    @Test
    void aClosedConnectionsFlowsHoldNoPlaceOnceTheProxySeesTheClose() throws Exception {
        UdpEcho udp = echo();
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch disconnected = new CountDownLatch(1);
        CountDownLatch proceed = new CountDownLatch(1);
        AtomicBoolean holding = new AtomicBoolean();
        proxy = forwardProxy()
                .withHttp3Options(Http3Options.builder().connectUdpMaxFlows(1, 64).connectUdpReleaseWait(Duration.ZERO).build())
                .withUdpInterceptor(new UdpInterceptor() {
                    @Override
                    public void udpStart(UdpContext context) {
                        if (!holding.compareAndSet(false, true)) return;
                        started.countDown();
                        try {
                            proceed.await(60, TimeUnit.SECONDS);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }

                    @Override
                    public byte[] udpMessage(UdpMessage message, UdpContext context) {
                        return message.data();
                    }
                })
                .plusActivityTracker(new ActivityTracker() {
                    @Override
                    public void clientDisconnected(FlowContext flowContext, javax.net.ssl.SSLSession sslSession) {
                        disconnected.countDown();
                    }
                }).start();
        try {
            H3TestClient first = client(true);
            assertEquals(200, first.open(connectUdp(wellKnown("127.0.0.1", udp.port()))).status);
            assertTrue(started.await(30, TimeUnit.SECONDS), "the flow started");
            first.close();
            assertTrue(disconnected.await(30, TimeUnit.SECONDS), "the proxy saw the close");
            H3TestClient.Tunnel next = client(true).open(connectUdp(wellKnown("127.0.0.1", udp.port())));
            assertEquals(200, next.status);
            proceed.countDown();
            next.sendDatagram(utf8("next"));
            assertEquals("next", nextDatagram(next));
        } finally {
            proceed.countDown();
        }
    }

    @Test
    void anIdleFlowEnds() throws Exception {
        UdpEcho udp = echo();
        proxy = forwardProxy().withHttp3Options(Http3Options.builder().connectUdpIdleTimeout(Duration.ofMillis(400)).build())
                .start();
        H3TestClient.Tunnel flow = client(true).open(connectUdp(wellKnown("127.0.0.1", udp.port())));
        flow.sendDatagram(utf8("once"));
        assertEquals("once", nextDatagram(flow));
        long start = System.nanoTime();
        assertEquals(-1, flow.in().read(), "the proxy ends the idle flow's stream");
        assertTrue(System.nanoTime() - start >= TimeUnit.MILLISECONDS.toNanos(200));
    }

    @Test
    void aClientThatDoesNotReadItsStreamLosesDatagramsNotTheConnection() throws Exception {
        UdpEcho udp = echo();
        proxy = forwardProxy().withHttp3Options(Http3Options.builder().connectUdpQueue(64, 65_527).build()).start();
        H3TestClient client = client(false);
        H3TestClient.Tunnel flow = client.open(connectUdp(wellKnown("127.0.0.1", udp.port())));
        byte[] payload = new byte[1000];
        // More than the client's stream window (1.25 MB): the echoes the proxy cannot send as
        // capsules wait in the flow's queue, and those past it are dropped.
        int sent = 3000;
        for (int i = 0; i < sent; i++) {
            Arrays.fill(payload, (byte) ('a' + i % 26));
            flow.sendDatagramCapsule(payload);
        }
        int[] last = {-1};
        eventually("the target to stop receiving", () -> {
            int now = udp.count.get();
            boolean settled = now == last[0];
            last[0] = now;
            if (!settled) {
                try {
                    Thread.sleep(300);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            return settled;
        });
        int echoed = udp.count.get();
        // Now the client reads: what waited in its window and the flow's queue arrives.
        AtomicInteger received = new AtomicInteger();
        Thread reader = Thread.ofVirtual().start(() -> {
            try {
                while (flow.readCapsule() != null) received.incrementAndGet();
            } catch (IOException e) {
                // reset when the flow ends below
            }
        });
        int[] seen = {-1};
        eventually("the client to read what came", () -> {
            int now = received.get();
            boolean settled = now == seen[0] && now > 0;
            seen[0] = now;
            if (!settled) {
                try {
                    Thread.sleep(300);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            return settled;
        });
        assertTrue(received.get() < echoed, received.get() + " of " + echoed + " echoes came back");
        flow.end();
        reader.join(10_000);
        // The connection is fine.
        assertEquals(200, client.open(connectUdp(wellKnown("127.0.0.1", udp.port()))).status);
    }

    // -------------------------------------------------------------------------------------------
    // The UDP hooks
    // -------------------------------------------------------------------------------------------

    @Test
    void theUdpHooksRewriteDropAndInjectDatagrams() throws Exception {
        UdpEcho udp = echo();
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = forwardProxy().withUdpInterceptor(new UdpInterceptor() {
            @Override
            public void udpStart(UdpContext context) {
                seen.add("start " + context.host() + ":" + context.port() + " " + context.flowContext().getHttpVersion());
                context.send(false, utf8("hello from the proxy"));
            }

            @Override
            public byte[] udpMessage(UdpMessage message, UdpContext context) {
                seen.add((message.fromClient() ? "> " : "< ") + message.text());
                if (message.text().equals("drop me")) return null;
                if (message.fromClient() && message.text().equals("inject")) context.send(true, utf8("injected"));
                return message.fromClient() ? utf8(message.text().toUpperCase()) : message.data();
            }

            @Override
            public void udpEnd(UdpContext context) {
                seen.add("end");
            }
        }).start();
        H3TestClient.Tunnel flow = client(true).open(connectUdp(wellKnown("127.0.0.1", udp.port())));
        assertEquals("hello from the proxy", nextDatagram(flow));
        flow.sendDatagram(utf8("drop me"));
        flow.sendDatagram(utf8("shout"));
        assertEquals("SHOUT", nextDatagram(flow));
        flow.sendDatagram(utf8("inject"));
        List<String> back = List.of(nextDatagram(flow), nextDatagram(flow));
        assertTrue(back.contains("INJECT") && back.contains("injected"), back.toString());
        flow.end();
        assertEquals(-1, flow.in().read());
        eventually("the flow to end", () -> seen.contains("end"));
        assertEquals("start 127.0.0.1:" + udp.port() + " HTTP/3.0", seen.getFirst());
        assertFalse(udp.received.contains("drop me"));
        assertTrue(udp.received.containsAll(List.of("SHOUT", "INJECT", "injected")), udp.received.toString());
    }
}
