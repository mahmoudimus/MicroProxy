package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.MetricsAssertions.awaitValue;
import static org.microproxy.MetricsAssertions.value;
import static org.microproxy.TestSupport.eventually;

import io.github.mahmoudimus.http2.ErrorCode;
import io.github.mahmoudimus.http2.Http2Settings;
import io.github.mahmoudimus.http3.QuicVarInt;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
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
import org.microproxy.stats.StatsRegistry;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SelfSignedSslContextSource;
import org.microproxy.tls.SslContexts;
import org.microproxy.udp.UdpContext;
import org.microproxy.udp.UdpInterceptor;
import org.microproxy.udp.UdpMessage;

/**
 * CONNECT-UDP (MASQUE, RFC 9298) over TCP: an extended {@code CONNECT} with {@code :protocol
 * connect-udp} on HTTP/2 connections, h2c and the TLS listener's h2 (RFC 9298 section 3.4), and the
 * HTTP/1.1 {@code Upgrade: connect-udp} (section 3.2). UDP payloads go to a UDP echo server and back
 * in DATAGRAM capsules on the stream (RFC 9297 section 3.5); the capsule framing and its errors;
 * filters, authentication and routing deciding on the target; the bounds on flows, queues and idle
 * time; the UDP hooks; the stats and access records.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class Http2MasqueTest {

    private static final SelfSignedSslContextSource TLS = new SelfSignedSslContextSource();

    private HttpProxyServer proxy;
    private final List<AutoCloseable> closeables = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable c : closeables) c.close();
        if (proxy != null) proxy.abort();
    }

    private Http3MasqueTest.UdpEcho echo() throws IOException {
        Http3MasqueTest.UdpEcho e = new Http3MasqueTest.UdpEcho();
        closeables.add(e);
        return e;
    }

    /** A forward proxy serving h2c, with CONNECT-UDP on its TCP listener and no HTTP/3. */
    private static HttpProxyServerBootstrap h2c() {
        return MicroProxy.bootstrap().withPort(0).withProxyAlias("mq").withHttp2Cleartext(true).withConnectUdp(true);
    }

    private H2StreamClient client() throws IOException {
        H2StreamClient c = H2StreamClient.cleartext(proxy.getListenAddress(), "localhost:" + proxy.getListenAddress().getPort());
        closeables.add(c);
        return c;
    }

    private static String wellKnown(String host, int port) {
        return "/.well-known/masque/udp/" + host + "/" + port + "/";
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** Opens a CONNECT-UDP flow to {@code udp} on {@code client}, which the proxy accepts. */
    private static H2StreamClient.Stream flow(H2StreamClient client, Http3MasqueTest.UdpEcho udp) throws IOException {
        H2StreamClient.Stream flow = client.open(client.connectUdp(wellKnown("127.0.0.1", udp.port())), false);
        assertEquals(200, flow.status());
        return flow;
    }

    /** The UDP payload of the next DATAGRAM capsule on the stream, skipping others, as text. */
    private static String next(H2StreamClient.Stream flow) throws IOException {
        byte[] payload = flow.readDatagram();
        assertNotNull(payload, "the stream ended");
        return new String(payload, StandardCharsets.UTF_8);
    }

    // -------------------------------------------------------------------------------------------
    // Relaying
    // -------------------------------------------------------------------------------------------

    @Test
    void udpGoesBothWaysInCapsulesOverH2c() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = h2c().withFiltersSource((original, ctx) -> new HttpFiltersAdapter(original, ctx) {
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
        H2StreamClient client = client();
        assertEquals(1L, client.setting(Http2Settings.ENABLE_CONNECT_PROTOCOL), "SETTINGS_ENABLE_CONNECT_PROTOCOL");
        H2StreamClient.Stream flow = flow(client, udp);
        assertEquals("?1", flow.header("capsule-protocol"));
        assertEquals("1.1 mq", flow.header("via"));
        assertNull(flow.header("upgrade"), "no connection-specific fields in HTTP/2");
        for (int i = 0; i < 5; i++) {
            flow.sendDatagramCapsule(utf8("ping " + i));
            assertEquals("ping " + i, next(flow));
        }
        assertEquals(List.of("ping 0", "ping 1", "ping 2", "ping 3", "ping 4"), udp.received);
        assertEquals(List.of("GET " + wellKnown("127.0.0.1", udp.port()) + " HTTP/2.0 upgrade=connect-udp",
                "101 connect-udp"), seen);
        // The client's END_STREAM ends the flow, and the proxy's comes back.
        flow.end();
        assertNull(flow.readCapsule());
        assertNull(flow.awaitEnd(), "ended, not reset");
    }

    /** A forward proxy with HTTP/3 serves CONNECT-UDP to the h2 clients of its TLS listener too. */
    @Test
    void anHttp3ForwardProxyServesItOnItsTlsListenersH2() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        proxy = MicroProxy.bootstrap().withPort(0).withSslContextSource(TLS).withHttp3(true).withHttp2(true).start();
        H2StreamClient client = H2StreamClient.tls(proxy.getListenAddress(), SslContexts.trusting(TLS.getCertificate()),
                "localhost:" + proxy.getListenAddress().getPort());
        closeables.add(client);
        H2StreamClient.Stream flow = flow(client, udp);
        flow.sendDatagramCapsule(utf8("over tls"));
        assertEquals("over tls", next(flow));
        flow.end();
        assertNull(flow.readCapsule());
    }

    @Test
    void aUdpFlowIsOneRecordWhenItEnds() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        RecordedFlows flows = new RecordedFlows();
        proxy = h2c().plusActivityTracker(flows).start();
        H2StreamClient.Stream flow = flow(client(), udp);
        for (int i = 0; i < 3; i++) {
            flow.sendDatagramCapsule(utf8("ping " + i));
            assertEquals("ping " + i, next(flow));
        }
        flow.end();
        assertNull(flow.readCapsule());
        FlowRecord r = flows.await(FlowRecord.Kind.UDP);
        assertEquals(18, r.bytesReceived());
        assertEquals(18, r.bytesSent());
        assertEquals(18, r.upstreamBytesSent());
        assertEquals(18, r.upstreamBytesReceived());
        assertEquals(101, r.responseCode(), "the acceptance, as filters see it");
        assertTrue(r.responseFlags().isEmpty(), r.toString());
        assertEquals("udp HTTP/2", org.microproxy.extras.AccessLogFormat.envoy("%MP_FLOW% %PROTOCOL%").format(r));
    }

    @Test
    void theClientsResetEndsTheFlowNotTheConnection() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        AtomicInteger ended = new AtomicInteger();
        proxy = h2c().withUdpInterceptor(new UdpInterceptor() {
            @Override
            public byte[] udpMessage(UdpMessage message, UdpContext context) {
                return message.data();
            }

            @Override
            public void udpEnd(UdpContext context) {
                ended.incrementAndGet();
            }
        }).start();
        H2StreamClient client = client();
        H2StreamClient.Stream flow = flow(client, udp);
        flow.sendDatagramCapsule(utf8("one"));
        assertEquals("one", next(flow));
        flow.reset(ErrorCode.CANCEL);
        eventually("the flow to end", () -> ended.get() == 1);
        assertEquals(200, flow(client, udp).status(), "the connection goes on");
        assertNull(client.goAway());
    }

    // -------------------------------------------------------------------------------------------
    // Capsules
    // -------------------------------------------------------------------------------------------

    @Test
    void unknownCapsulesAreSkippedAndOtherContextsDropped() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        proxy = h2c().start();
        H2StreamClient.Stream flow = flow(client(), udp);
        // Unknown capsules are skipped (RFC 9297 section 3.2), large ones too, across DATA frames.
        flow.sendCapsule(0x2a, new byte[100_000]);
        flow.sendCapsule(0x3fff, utf8("reserved"));
        // A payload of another context is dropped (RFC 9298 section 4), and so is a DATAGRAM
        // capsule without even a context ID.
        flow.sendCapsule(0, new byte[] {0x02, 'x'});
        flow.sendCapsule(0, new byte[0]);
        // Context ID 0 in a longer encoding than it needs is still 0.
        flow.sendCapsule(0, new byte[] {0x40, 0x00, 'l', 'o', 'n', 'g'});
        flow.sendDatagramCapsule(utf8("after"));
        assertEquals("long", next(flow));
        assertEquals("after", next(flow));
        assertEquals(List.of("long", "after"), udp.received);
    }

    @Test
    void aStreamThatEndsInsideACapsuleIsReset() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        proxy = h2c().withMetrics(true).start();
        H2StreamClient client = client();
        // A capsule's length promises more than the stream carries.
        H2StreamClient.Stream truncated = flow(client, udp);
        truncated.sendDatagramCapsule(utf8("whole"));
        assertEquals("whole", next(truncated));
        byte[] header = concat(QuicVarInt.encode(0), QuicVarInt.encode(100));
        truncated.out().write(concat(header, new byte[] {0, 'p', 'a', 'r', 't'}));
        truncated.end();
        assertEquals(ErrorCode.CANCEL, truncated.awaitReset());
        // The stream ends inside a capsule's length.
        H2StreamClient.Stream inLength = flow(client, udp);
        inLength.out().write(new byte[] {0x00, 0x40});
        inLength.end();
        assertEquals(ErrorCode.CANCEL, inLength.awaitReset());
        // A DATAGRAM capsule larger than any UDP payload is not buffered.
        H2StreamClient.Stream huge = flow(client, udp);
        huge.out().write(concat(QuicVarInt.encode(0), QuicVarInt.encode(70_000)));
        assertEquals(ErrorCode.CANCEL, huge.awaitReset());
        assertEquals(List.of("whole"), udp.received);
        // Only the flows failed: the connection goes on.
        H2StreamClient.Stream fine = flow(client, udp);
        fine.sendDatagramCapsule(utf8("fine"));
        assertEquals("fine", next(fine));
        assertNull(client.goAway());
        assertEquals(4, value(proxy.getStats(), "masque.udp_flows_total"));
        awaitValue(proxy.getStats(), "masque.udp_flows_active", 1);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    // -------------------------------------------------------------------------------------------
    // Policy
    // -------------------------------------------------------------------------------------------

    @Test
    void filtersRoutingAndTheTemplateDecideOnTheTarget() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        proxy = h2c()
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
                .withMetrics(true)
                .start();
        H2StreamClient client = client();
        assertEquals(403, client.open(client.connectUdp(wellKnown("127.0.0.1", 53)), false).status(), "a filter refused it");
        assertEquals(502, client.open(client.connectUdp(wellKnown("nowhere.test", 9)), false).status(), "unresolvable");
        assertEquals(400, client.open(client.connectUdp(wellKnown("127.0.0.1", 0)), false).status(), "no port 0");
        assertEquals(400, client.open(client.connectUdp("/somewhere/else"), false).status(), "not the template");
        H2StreamClient.Stream flow = client.open(client.connectUdp(wellKnown("echo.test", udp.port())), false);
        assertEquals(200, flow.status());
        flow.sendDatagramCapsule(utf8("resolved"));
        assertEquals("resolved", next(flow));
        assertEquals(0, value(proxy.getStats(), "masque.flow_rejected.limit"));
    }

    @Test
    void aCustomTemplateNamesTheTargetInTheQuery() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        proxy = h2c().withHttp3Options(Http3Options.builder()
                .connectUdpTemplate("https://proxy.example/masque?h={target_host}&p={target_port}").build()).start();
        H2StreamClient client = client();
        H2StreamClient.Stream flow = client.open(client.connectUdp("/masque?h=127.0.0.1&p=" + udp.port()), false);
        assertEquals(200, flow.status());
        flow.sendDatagramCapsule(utf8("query"));
        assertEquals("query", next(flow));
        assertEquals(400, client.open(client.connectUdp(wellKnown("127.0.0.1", udp.port())), false).status());
    }

    @Test
    void aRouteThroughChainedProxiesOnlyIsRefused() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        proxy = h2c().withMetrics(true).withChainProxyManager((request, chained, details) -> chained.add(new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return new InetSocketAddress(TestSupport.LOOPBACK, 9);
            }
        })).start();
        H2StreamClient client = client();
        assertEquals(502, client.open(client.connectUdp(wellKnown("127.0.0.1", udp.port())), false).status());
        assertEquals(1, value(proxy.getStats(), "masque.flow_rejected.policy"));
    }

    @Test
    void proxyAuthenticationIsAskedForOnTheStream() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        proxy = h2c().withProxyAuthenticator((user, password) -> "user".equals(user) && "secret".equals(password)).start();
        H2StreamClient client = client();
        H2StreamClient.Stream refused = client.open(client.connectUdp(wellKnown("127.0.0.1", udp.port())), false);
        assertEquals(407, refused.status());
        assertNotNull(refused.header("proxy-authenticate"));
        H2StreamClient.Stream flow = client.open(client.connectUdp(wellKnown("127.0.0.1", udp.port()),
                "proxy-authorization", "Basic " + Base64.getEncoder().encodeToString(utf8("user:secret"))), false);
        assertEquals(200, flow.status());
        flow.sendDatagramCapsule(utf8("authorized"));
        assertEquals("authorized", next(flow));
    }

    /** Without CONNECT-UDP (no --masque, no --http3) the stream is answered 501. */
    @Test
    void aProxyThatDoesNotServeItAnswers501() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        proxy = MicroProxy.bootstrap().withPort(0).withHttp2Cleartext(true).start();
        H2StreamClient client = client();
        assertEquals(501, client.open(client.connectUdp(wellKnown("127.0.0.1", udp.port())), false).status());
        assertEquals(0, udp.count.get());
    }

    /** In an intercepted session the requests are the intercepted server's: no CONNECT-UDP there. */
    @Test
    void anInterceptedSessionAnswers501() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        CertificateAuthority originCa = CertificateAuthority.generate("MASQUE h2 Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("MASQUE h2 Proxy CA");
        H2TestOrigin origin = new H2TestOrigin(originCa.serverContext("localhost", "127.0.0.1"), s -> s.respond(200, true));
        closeables.add(origin);
        proxy = h2c().withHttp2(true).withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .start();
        try (H2StreamClient c = H2StreamClient.intercepted(proxy.getListenAddress(), "localhost:" + origin.port(),
                proxyCa.clientContext())) {
            assertEquals(501, c.open(c.connectUdp(wellKnown("127.0.0.1", udp.port())), false).status());
        }
        assertEquals(0, udp.count.get());
    }

    @Test
    void aReverseProxyCannotServeIt() {
        assertThrows(IllegalStateException.class, () -> MicroProxy.bootstrap().withPort(0)
                .withReverseProxy("http://127.0.0.1:9").withConnectUdp(true).start());
    }

    // -------------------------------------------------------------------------------------------
    // Bounds
    // -------------------------------------------------------------------------------------------

    @Test
    void flowsPerConnectionAndInTotalAreBounded() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        proxy = h2c().withMetrics(true).withHttp3Options(Http3Options.builder().connectUdpMaxFlows(3, 2).build()).start();
        StatsRegistry r = proxy.getStats();
        H2StreamClient first = client();
        flow(first, udp);
        H2StreamClient.Stream second = flow(first, udp);
        assertEquals(503, first.open(first.connectUdp(wellKnown("127.0.0.1", udp.port())), false).status(),
                "two per connection");
        H2StreamClient other = client();
        flow(other, udp);
        assertEquals(503, other.open(other.connectUdp(wellKnown("127.0.0.1", udp.port())), false).status(),
                "three in total");
        assertEquals(2, value(r, "masque.flow_rejected.limit"));
        assertEquals(3, value(r, "masque.udp_flows_active"));
        // A flow that ends makes room on its connection.
        second.end();
        assertNull(second.readCapsule());
        awaitValue(r, "masque.udp_flows_active", 2);
        eventually("room for a flow", () -> {
            try {
                return first.open(first.connectUdp(wellKnown("127.0.0.1", udp.port())), false).status() == 200;
            } catch (IOException e) {
                return false;
            }
        });
    }

    @Test
    void anIdleFlowEnds() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        proxy = h2c().withHttp3Options(Http3Options.builder().connectUdpIdleTimeout(Duration.ofMillis(400)).build()).start();
        H2StreamClient.Stream flow = flow(client(), udp);
        flow.sendDatagramCapsule(utf8("once"));
        assertEquals("once", next(flow));
        long start = System.nanoTime();
        assertNull(flow.readCapsule(), "the proxy ends the idle flow's stream");
        assertTrue(System.nanoTime() - start >= TimeUnit.MILLISECONDS.toNanos(200));
    }

    /**
     * Capsules to a client that does not read its stream wait for HTTP/2 send window; meanwhile
     * the flow's queue fills and the datagrams past it are dropped and counted, while the
     * connection and the target side go on.
     */
    @Test
    void aClientThatDoesNotReadItsStreamLosesDatagramsNotTheConnection() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        proxy = h2c().withMetrics(true).withHttp3Options(Http3Options.builder().connectUdpQueue(64, 65_527).build()).start();
        StatsRegistry r = proxy.getStats();
        H2StreamClient client = client();
        H2StreamClient.Stream flow = flow(client, udp);
        byte[] payload = new byte[1000];
        // Far more than the stream's window (64 KiB) and the flow's queue together.
        int sent = 1000;
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
                while (flow.readDatagram() != null) received.incrementAndGet();
            } catch (IOException e) {
                // the flow ended
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
        awaitValue(r, "masque.udp_flows_active", 0);
        assertTrue(value(r, "masque.datagrams_dropped") > 0, "the datagrams dropped are counted");
        assertEquals(received.get(), value(r, "masque.capsules_tx"));
        // The connection is fine.
        assertEquals(200, flow(client, udp).status());
    }

    // -------------------------------------------------------------------------------------------
    // The UDP hooks and the stats
    // -------------------------------------------------------------------------------------------

    @Test
    void theUdpHooksRewriteDropAndInjectDatagrams() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = h2c().withUdpInterceptor(new UdpInterceptor() {
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
        H2StreamClient.Stream flow = flow(client(), udp);
        assertEquals("hello from the proxy", next(flow));
        flow.sendDatagramCapsule(utf8("drop me"));
        flow.sendDatagramCapsule(utf8("shout"));
        assertEquals("SHOUT", next(flow));
        flow.sendDatagramCapsule(utf8("inject"));
        List<String> back = List.of(next(flow), next(flow));
        assertTrue(back.contains("INJECT") && back.contains("injected"), back.toString());
        flow.end();
        assertNull(flow.readCapsule());
        eventually("the flow to end", () -> seen.contains("end"));
        assertEquals("start 127.0.0.1:" + udp.port() + " HTTP/2.0", seen.getFirst());
        assertFalse(udp.received.contains("drop me"));
        assertTrue(udp.received.containsAll(List.of("SHOUT", "INJECT", "injected")), udp.received.toString());
    }

    @Test
    void datagramsAndCapsulesAreCountedWhenTheFlowEnds() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        proxy = h2c().withMetrics(true).start();
        StatsRegistry r = proxy.getStats();
        H2StreamClient.Stream flow = flow(client(), udp);
        for (int i = 0; i < 3; i++) {
            flow.sendDatagramCapsule(utf8("ping " + i));
            assertEquals("ping " + i, next(flow));
        }
        flow.sendCapsule(0x2a, utf8("unknown"));
        assertEquals(1, value(r, "masque.udp_flows_active"));
        flow.end();
        assertNull(flow.readCapsule());
        awaitValue(r, "masque.udp_flows_active", 0);
        assertEquals(1, value(r, "masque.udp_flows_total"));
        // Every datagram is a capsule over HTTP/2, both ways; unknown capsules count as nothing.
        assertEquals(3, value(r, "masque.datagrams_rx"));
        assertEquals(3, value(r, "masque.capsules_rx"));
        assertEquals(3, value(r, "masque.datagrams_tx"));
        assertEquals(3, value(r, "masque.capsules_tx"));
        assertEquals(18, value(r, "masque.rx_bytes_total"));
        assertEquals(18, value(r, "masque.tx_bytes_total"));
        assertEquals(0, value(r, "masque.datagrams_dropped"));
    }

    // -------------------------------------------------------------------------------------------
    // HTTP/1.1 (RFC 9298 section 3.2)
    // -------------------------------------------------------------------------------------------

    @Test
    void http11UpgradeCarriesCapsulesOnTheConnection() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        List<String> seen = new CopyOnWriteArrayList<>();
        proxy = MicroProxy.bootstrap().withPort(0).withProxyAlias("mq").withConnectUdp(true)
                .withFiltersSource((original, ctx) -> new HttpFiltersAdapter(original, ctx) {
                    @Override
                    public HttpResponse clientToProxyRequest(HttpObject o) {
                        HttpRequest r = (HttpRequest) o;
                        seen.add(r.method() + " " + r.uri() + " " + r.protocolVersion());
                        return null;
                    }
                }).start();
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            s.setSoTimeout(10_000);
            OutputStream out = s.getOutputStream();
            InputStream in = s.getInputStream();
            TestSupport.write(out, "GET " + wellKnown("127.0.0.1", udp.port()) + " HTTP/1.1\r\nHost: localhost\r\n"
                    + "Connection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n");
            String head = TestSupport.readUntil(in, "\r\n\r\n");
            assertTrue(head.startsWith("HTTP/1.1 101 "), head);
            assertTrue(head.toLowerCase().contains("upgrade: connect-udp"), head);
            assertTrue(head.toLowerCase().contains("capsule-protocol: ?1"), head);
            for (int i = 0; i < 3; i++) {
                out.write(H3TestClient.capsule(0, H3TestClient.contextZero(utf8("h1 " + i))));
                out.flush();
                assertEquals("h1 " + i, new String(readDatagram(in), StandardCharsets.UTF_8));
            }
            // Half-closing ends the flow: the proxy's end comes back.
            s.shutdownOutput();
            assertEquals(-1, in.read());
        }
        assertEquals(List.of("GET " + wellKnown("127.0.0.1", udp.port()) + " HTTP/1.1"), seen);
        assertEquals(List.of("h1 0", "h1 1", "h1 2"), udp.received);
    }

    @Test
    void anIdleHttp11FlowEndsItsConnection() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        proxy = MicroProxy.bootstrap().withPort(0).withConnectUdp(true)
                .withHttp3Options(Http3Options.builder().connectUdpIdleTimeout(Duration.ofMillis(400)).build()).start();
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            s.setSoTimeout(10_000);
            TestSupport.write(s.getOutputStream(), "GET " + wellKnown("127.0.0.1", udp.port()) + " HTTP/1.1\r\n"
                    + "Host: localhost\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n");
            assertTrue(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 101 "));
            long start = System.nanoTime();
            assertEquals(-1, s.getInputStream().read(), "the proxy ends the idle flow's connection");
            assertTrue(System.nanoTime() - start >= TimeUnit.MILLISECONDS.toNanos(200));
        }
    }

    @Test
    void http11UpgradeIsRefusedLikeTheOthers() throws Exception {
        Http3MasqueTest.UdpEcho udp = echo();
        proxy = MicroProxy.bootstrap().withPort(0).withConnectUdp(true).start();
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            s.setSoTimeout(10_000);
            TestSupport.write(s.getOutputStream(), "GET /somewhere/else HTTP/1.1\r\nHost: localhost\r\n"
                    + "Connection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n");
            String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
            assertTrue(head.startsWith("HTTP/1.1 400 "), head);
        }
        assertEquals(0, udp.count.get());
    }

    /** The UDP payload of the next DATAGRAM capsule on a connection, skipping others. */
    private static byte[] readDatagram(InputStream in) throws IOException {
        while (true) {
            long type = QuicVarInt.read(in);
            if (type < 0) throw new SocketException("the connection ended");
            long length = QuicVarInt.read(in);
            byte[] value = in.readNBytes((int) length);
            if (type == 0) return H3TestClient.udpPayload(value);
        }
    }
}
