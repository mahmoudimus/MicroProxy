package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * The forward proxy's HTTP/3 listener against aioquic's HTTP/3 client, an independent
 * implementation: a CONNECT tunnel to a TCP echo server, a WebSocket over extended CONNECT (RFC
 * 9220) to a WebSocket echo server, and CONNECT-UDP (RFC 9298) to a UDP echo server, its payloads
 * in QUIC DATAGRAM frames and in DATAGRAM capsules (RFC 9297), with filters seeing each request.
 *
 * <p>Skipped unless Python 3 with aioquic is available ({@link AioquicPeers}).
 */
@Timeout(value = 180, unit = TimeUnit.SECONDS)
class AioquicMasqueTest {

    private static final SelfSignedSslContextSource TLS = new SelfSignedSslContextSource();

    @TempDir
    Path dir;

    private HttpProxyServer proxy;
    private final List<AutoCloseable> closeables = new CopyOnWriteArrayList<>();
    private final List<String> filtered = new CopyOnWriteArrayList<>();
    private Path ca;

    @BeforeEach
    void setUp() throws Exception {
        AioquicPeers.assumeAvailable();
        ca = AioquicPeers.certificates(dir.resolve("ca.pem"), TLS.getCertificate());
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withSslContextSource(TLS)
                .withHttp3(true)
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                        filtered.add(originalRequest.method() + " " + originalRequest.uri() + " " + ctx.getHttpVersion());
                        return new HttpFiltersAdapter(originalRequest, ctx) {
                            @Override
                            public HttpObject proxyToClientResponse(HttpObject o) {
                                if (o instanceof HttpResponse r) filtered.add(r.status().code() + " " + r.headers().get("Upgrade"));
                                return o;
                            }
                        };
                    }
                })
                .start();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        for (AutoCloseable c : closeables) c.close();
    }

    @Test
    void connectWebSocketAndConnectUdpFromAioquic() throws Exception {
        TestSupport.RawServer tcp = TestSupport.rawServer(s -> s.getInputStream().transferTo(s.getOutputStream()));
        closeables.add(tcp);
        WebSocketTestSupport.EchoServer ws = new WebSocketTestSupport.EchoServer();
        closeables.add(ws);
        Http3MasqueTest.UdpEcho udp = new Http3MasqueTest.UdpEcho();
        closeables.add(udp);

        Map<String, Object> r = AioquicPeers.masque(dir, proxy.getListenAddress().getPort(), ca,
                "127.0.0.1:" + tcp.port(), "127.0.0.1:" + ws.raw().port(), "127.0.0.1:" + udp.port());

        assertEquals(200L, r.get("connect_status"));
        assertEquals("hello over aioquic", r.get("connect_echo"));

        assertEquals(200L, r.get("ws_status"));
        assertEquals("echo:ping over aioquic", r.get("ws_echo"));
        assertTrue(ws.received.getFirst().isMasked());
        assertEquals("ping over aioquic", ws.received.getFirst().payloadAsText());

        assertEquals(200L, r.get("udp_status"));
        assertEquals(List.of("datagram 0", "datagram 1", "datagram 2"), r.get("udp_datagram_echoes"));
        assertEquals("by capsule", r.get("udp_capsule_echo"));
        assertEquals(Boolean.TRUE, r.get("udp_ended"));
        assertEquals(200L, r.get("udp_capsules_status"));
        assertEquals(List.of("capsule 0", "capsule 1", "capsule 2"), r.get("udp_capsule_echoes"),
                "a client that takes no HTTP/3 datagrams gets capsules");
        assertEquals(List.of("datagram 0", "datagram 1", "datagram 2", "by capsule", "capsule 0", "capsule 1",
                "capsule 2"), udp.received);

        String udpPath = "/.well-known/masque/udp/127.0.0.1/" + udp.port() + "/";
        assertEquals(List.of(
                "CONNECT 127.0.0.1:" + tcp.port() + " HTTP/3.0", "200 null",
                "GET http://127.0.0.1:" + ws.raw().port() + "/chat HTTP/3.0", "101 websocket",
                "GET " + udpPath + " HTTP/3.0", "101 connect-udp",
                "GET " + udpPath + " HTTP/3.0", "101 connect-udp"), filtered);
    }
}
